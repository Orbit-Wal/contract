# Issue #28 — Contexto persistente (SSOT)

> **Título:** `set_recovery_config` can be called mid-recovery with no guard or documented interaction
> **Repo:** Orbit-Wal/contract · **Contrato:** `contracts/globe-wallet`
> **Rama de trabajo:** `fix/issue-28`
> **Estado:** � ADR definitivo aceptado (ADR-028-1, opción A) — pendiente de implementación y tests
> **Última actualización:** 2026-08-26

Este archivo es la fuente única de verdad (SSOT) para el trabajo sobre la
Issue #28. Debe actualizarse en cada sesión/commit relevante en lugar de
dispersar contexto en el historial de chat.

---

## 1. Problema

`set_recovery_config(env, admin, threshold, delay_in_ledgers)`
([contracts/globe-wallet/src/lib.rs](../../contracts/globe-wallet/src/lib.rs#L573))
permite al admin reconfigurar el umbral M-of-N y el delay de timelock de
recovery en cualquier momento, **incluso mientras existe un
`RecoveryProposal` pendiente** (`DataKey::RecoveryProposal`).

No hay guardas, ni tests, ni documentación que definan cómo debe
interactuar una reconfiguración con una recovery en curso. El único guard
existente (`require_admin`) protege *quién* puede llamar, no *cuándo*
puede llamarse respecto al ciclo de vida de una propuesta activa.

Referencia de funciones involucradas:
- `set_recovery_config` — L573-598
- `initiate_recovery` — L613-640
- `approve_recovery` — L642-670
- `revoke_recovery_approval` — L672-703
- `execute_recovery` — L718-750 (re-lee `RecoveryConfig` en vivo)
- `cancel_recovery` (admin) — ~L750+

## 2. Análisis: acoplamiento *live* vs *frozen*

El diseño actual de GlobeWallet mezcla dos modelos de acoplamiento entre
`RecoveryConfig` y `RecoveryProposal` sin decidir explícitamente cuál aplica:

| Aspecto | Comportamiento actual | Tipo de acoplamiento |
|---|---|---|
| `threshold` usado en `approve_recovery` para armar `ready_at` | Lee `RecoveryConfig` **en el momento del approve** | Live (config vigente al momento de la llamada) |
| `threshold` usado en `execute_recovery` para re-validar quorum | Vuelve a leer `RecoveryConfig` **en el momento de ejecutar** (defensa en profundidad documentada en el propio código) | Live |
| `delay_in_ledgers` usado para calcular `ready_at` | Se calcula **una sola vez**, cuando se alcanza quorum en `approve_recovery`; queda congelado en `proposal.ready_at` | Frozen (snapshot) |
| `RecoveryProposal.approvals` (lista de guardianes que ya aprobaron) | No se reevalúa contra el nuevo `threshold` hasta el próximo `approve_recovery`/`execute_recovery` | Frozen hasta la próxima lectura live |

### Escenarios problemáticos identificados

1. **Bajar el `threshold` a mitad de recovery para forzar quorum antes de tiempo.**
   Si ya hay `k` aprobaciones (`k < threshold_original`) y el admin (o un
   admin comprometido/bajo coacción) llama `set_recovery_config` con
   `threshold <= k`, la siguiente llamada a `approve_recovery` (o incluso
   una ya en curso en el mismo host invocation) puede marcar quorum y
   armar `ready_at` con una propuesta que nunca alcanzó el umbral
   originalmente exigido.

2. **Subir el `threshold` para invalidar retroactivamente una recovery legítima ya en quorum.**
   Si la propuesta ya tiene `ready_at` armado bajo el `threshold` viejo, y
   el admin sube el `threshold`, `execute_recovery` volverá a fallar con
   `RecoveryNotQuorate` pese a que los guardianes cumplieron el proceso
   correctamente en su momento — comportamiento no documentado, potencial
   *silent boundary failure* desde la perspectiva de los guardianes.

3. **Cambiar `delay_in_ledgers` no afecta timelocks ya armados** (correcto
   por ser snapshot), pero tampoco hay ningún evento ni chequeo que le
   informe a los guardianes que la config cambió bajo una propuesta activa.
   No hay evento `recovery_config_changed_mid_recovery` ni similar.

4. **No hay reentrancy/orden de invocación documentado**: nada impide que,
   dentro del mismo host invocation, un guardián dispare `approve_recovery`
   y el admin dispare `set_recovery_config` en la misma transacción
   compuesta, dejando el resultado dependiente del orden de sub-invocaciones
   (ver precedente ya auditado en
   [docs/record-spend-reentrancy.md](../record-spend-reentrancy.md) para
   otro caso de acoplamiento vivo dentro de un mismo host invocation).

### Decisión de diseño

Ver **ADR-028-1** (sección 3) para el análisis formal de las tres opciones
(A/B/C) y la decisión definitiva. **Se adopta la opción A: bloquear
`set_recovery_config` mientras exista un `RecoveryProposal` pendiente.**

## 3. ADR — Architecture Decision Record

### ADR-028-1: Bloquear `set_recovery_config` mientras haya una `RecoveryProposal` pendiente

- **Estado:** ✅ **Aceptado** (definitivo — cierra la Issue #28 a nivel de diseño)
- **Fecha:** 2026-08-26

#### Contexto

`RecoveryConfig` (`threshold`, `delay_in_ledgers`) y `RecoveryProposal`
(`new_admin`, `approvals`, `ready_at`) son dos entradas de storage
independientes con dos modelos de lectura distintos y hoy sin reconciliar:

- **Read-time live check:** tanto `approve_recovery` (para decidir si se
  alcanza quorum y armar `ready_at`) como `execute_recovery` (para
  re-validar quorum como defensa en profundidad) leen `RecoveryConfig`
  **en el instante de la llamada**, no un valor fijado al iniciar la
  recovery.
- **Write-time frozen timelock:** `ready_at`, una vez armado, es un
  entero (`ledger_sequence + delay_in_ledgers`) calculado **una sola vez**
  y persistido dentro de `RecoveryProposal`. No se recalcula si
  `delay_in_ledgers` cambia después.

Esta mezcla implica que **no existe hoy ningún invariante que ligue el
ciclo de vida de una `RecoveryProposal` a un `RecoveryConfig` estable**: el
admin puede llamar `set_recovery_config` en cualquier punto intermedio
(sin aprobaciones, con quorum parcial, con quorum ya alcanzado e incluso
durante la ventana de timelock) sin que ninguna guarda lo impida, y sin que
el contrato emita ningún evento que dé visibilidad a los guardianes de que
la config bajo la que están operando cambió a mitad de proceso.

Esto es directamente análogo al problema ya resuelto en la **Issue #26**
(`remove_guardian` durante una recovery pendiente): un cambio de estado de
gobernanza (ahí, membresía de guardianes; aquí, threshold/delay) ejecutado
por el admin mientras una `RecoveryProposal` está en vuelo, sin reglas
explícitas de interacción. La Issue #26 se resolvió **reconciliando
activamente** el estado del proposal en el mismo call (`remove_guardian`
recorta `approvals` y limpia `ready_at` si corresponde) en lugar de
bloquear la mutación. Para la Issue #28 se evalúa el mismo patrón de
"reconciliar" (opción B) frente a "bloquear" (opción A) y "documentar el
modelo live" (opción C).

#### Opciones evaluadas

- **(A) Bloquear.** `set_recovery_config` retorna un error nuevo
  (`RecoveryConfigLocked`) si existe un `RecoveryProposal` pendiente. El
  admin debe `cancel_recovery` (o esperar a `execute_recovery`) antes de
  reconfigurar. Precedente directo en el propio contrato:
  `RecoveryAlreadyPending` (una sola recovery en vuelo) y
  `UpgradeAlreadyPending` (una sola upgrade en vuelo) ya usan exactamente
  este patrón de "un guard de exclusión mutua sobre una operación
  sensible en curso".
- **(B) Congelar `threshold` en `initiate_recovery`.** Igual que
  `delay_in_ledgers`/`ready_at`, guardar un snapshot de `threshold` dentro
  de `RecoveryProposal` en el momento de iniciar, y usar ese snapshot (no
  `RecoveryConfig.threshold` vigente) en `approve_recovery`/
  `execute_recovery`. Permite reconfigurar libremente sin bloquear, al
  costo de una migración de esquema (`RecoveryProposal` gana un campo) y
  de tener que decidir qué ocurre con `guardians.len()` también
  cambiando bajo la propuesta congelada (fuera del alcance original de la
  Issue #28, pero acoplado).
- **(C) Permitir y documentar el modelo live.** No añade ningún guard;
  solo formaliza en doc comments y tests que `threshold`/`delay_in_ledgers`
  son siempre "lo que diga `RecoveryConfig` en el momento de cada
  llamada". Descartada: mantiene abierta la superficie de ataque de los
  escenarios 1 y 2 de la sección 2 (bajar quorum a mitad de proceso para
  forzarlo; subir quorum para invalidar retroactivamente una recovery ya
  legítima), y traslada la responsabilidad de detectarlo a los guardianes
  vigilando eventos fuera de cadena.

#### Decisión

Se adopta la **opción A**. Justificación:

1. **Consistencia arquitectónica con invariantes ya existentes.** El
   contrato ya trata "hay una operación de gobernanza sensible en vuelo"
   como estado mutuamente excluyente para upgrades (`UpgradeAlreadyPending`)
   y para la propia recovery (`RecoveryAlreadyPending`). Bloquear
   `set_recovery_config` mientras `RecoveryProposal` exista extiende ese
   mismo invariante en lugar de introducir un segundo modelo (snapshot)
   para un tercer subsistema.
2. **Menor superficie de estados a auditar/testear.** La opción B es
   correcta pero obliga a razonar sobre combinaciones adicionales
   (snapshot de `threshold` vs. `guardians.len()` cambiando en paralelo vía
   `add_guardian`/`remove_guardian`, que la Issue #26 ya trata con
   reconciliación activa sobre `approvals`, no sobre `threshold`). Mezclar
   ambos modelos de congelamiento en la misma estructura aumenta el riesgo
   de una interacción no cubierta.
3. **Alineado con la filosofía de "fail loud, not silent" del proyecto**
   (ver namespace contiguo de errores y comentarios de `record_spend`
   sobre TTL): un intento de reconfigurar durante una recovery activa debe
   ser un error explícito y accionable (`RecoveryConfigLocked`), no un
   comportamiento silencioso que dependa del orden de llamadas.
4. **Costo de implementación mínimo y sin migración de esquema**: no
   requiere añadir campos a `RecoveryProposal` ni tocar
   `approve_recovery`/`execute_recovery` más allá de un comentario
   aclaratorio (sección 4).

Opción B queda documentada como alternativa rechazada, no como trabajo
futuro: si en el futuro se requiere permitir reconfiguración concurrente,
debe abrirse una nueva issue que reevalúe también su interacción con
`add_guardian`/`remove_guardian` (Issue #26), no reabrir esta.

#### Consecuencias

**Invariante de seguridad garantizado tras el fix:**
> Mientras exista un `RecoveryProposal` (`env.storage().instance().has(&DataKey::RecoveryProposal) == true`),
> `RecoveryConfig` es inmutable. Toda la evaluación de quorum y timelock
> para esa propuesta se hace bajo una única configuración estable, fijada
> en el momento de `initiate_recovery` y válida hasta `cancel_recovery` o
> `execute_recovery`.

**Casos de borde resueltos explícitamente:**
- **Threshold raise/lower mid-recovery:** ya no es posible; `set_recovery_config`
  falla con `RecoveryConfigLocked` en ambos sentidos (subir o bajar).
  Los escenarios 1 y 2 de la sección 2 quedan cerrados por construcción.
- **Delay changes mid-recovery:** mismo resultado — `set_recovery_config`
  falla, por lo que `delay_in_ledgers` tampoco puede cambiar mientras haya
  una propuesta activa. El comportamiento frozen de `ready_at` (ya
  correcto) deja de tener incluso la posibilidad teórica de una config
  parcialmente distinta en el resto de la vida del proposal.
- **`add_guardian`/`remove_guardian` durante recovery:** **sin cambios** —
  siguen permitidos (`remove_guardian` ya reconcilia `approvals`/`ready_at`
  desde la Issue #26). Este ADR **no** extiende el bloqueo a la membresía
  de guardianes; solo a `RecoveryConfig`. Justificación: `guardians.len()`
  cambiando no vuelve inconsistente una config ya congelada de la misma
  forma que si `threshold` cambiara, y extender el bloqueo ahí es un
  cambio de comportamiento fuera del alcance de esta issue.
- **Orden de sub-invocación dentro de un mismo host invocation:** deja de
  ser ambiguo — cualquier intento de `set_recovery_config` dentro de la
  misma transacción compuesta en la que ya existe (o se acaba de crear)
  un `RecoveryProposal` falla determinísticamente, sin importar el orden
  relativo frente a `approve_recovery`.
- **Nuevo error:** `WalletError::RecoveryConfigLocked = 1031` (próximo
  discriminante libre en el namespace `1001+` contiguo — los últimos en
  uso son `InvalidAssetInfo = 1029` y `UpgradeWasmNotUploaded = 1030`; no
  reutilizar `1029` como se sugirió en un borrador previo de este documento).

### ADR-028-2: No tocar el modelo frozen de `delay_in_ledgers`/`ready_at`

- **Estado:** ✅ Aceptado
- **Contexto:** Ese snapshot ya es correcto: `ready_at` se calcula una
  única vez en `approve_recovery` al alcanzar quorum y no se recalcula.
  Con ADR-028-1 aceptado, esto queda además protegido transitivamente
  (no puede haber un `delay_in_ledgers` distinto "flotando" durante la
  vida del proposal).
- **Decisión:** El fix de la Issue #28 no debe alterar cómo se congela
  `ready_at`; solo cierra la ventana de reconfiguración de `RecoveryConfig`
  completo (`threshold` y `delay_in_ledgers`) mientras haya un proposal.

## 4. Especificación de contratos — Doc comments requeridos

> Redacción exacta a aplicar en la implementación (no aplicada aún — este
> documento es la especificación, no el código).

### `set_recovery_config`

```rust
/// Configure (or reconfigure) the M-of-N recovery threshold and the
/// post-quorum timelock delay. Admin-authorized.
///
/// Locked while a `RecoveryProposal` is pending (issue #28 / ADR-028-1):
/// the config governing an in-flight recovery must stay fixed for that
/// proposal's entire lifecycle. Without this guard, an admin (or an
/// attacker who has coerced/compromised the admin key) could lower
/// `threshold` mid-recovery to manufacture quorum out of approvals that
/// never met the original bar, or raise it to silently invalidate a
/// proposal guardians had already legitimately brought to quorum. Callers
/// must `cancel_recovery` or wait for `execute_recovery` to consume the
/// proposal before calling this again. This does **not** affect
/// `add_guardian`/`remove_guardian`, which remain callable mid-recovery
/// per the existing issue #26 reconciliation logic.
///
/// # Errors
/// * [`WalletError::RecoveryConfigLocked`] — a `RecoveryProposal` is
///   currently pending; cancel or execute it first.
/// * [`WalletError::InvalidRecoveryThreshold`] — `threshold <= 1` (a
///   single guardian must never be able to unilaterally recover admin).
/// * [`WalletError::NotEnoughGuardians`] — fewer than
///   [`Self::MIN_GUARDIANS_FOR_RECOVERY`] guardians registered, or
///   `threshold > guardians.len()`.
```

### `approve_recovery`

```rust
/// A guardian approves the pending recovery proposal.
///
/// Once approvals reach the configured threshold, the timelock is
/// armed: `ready_at = current_ledger_sequence + delay_in_ledgers`.
///
/// Since `set_recovery_config` refuses to run while a proposal is pending
/// (issue #28 / ADR-028-1), the `RecoveryConfig` read here is guaranteed
/// to be identical to the one active when `initiate_recovery` created this
/// proposal — reading it "live" is equivalent to reading a frozen snapshot
/// for the lifetime of the proposal. Do not weaken that guard without
/// re-deriving `threshold` from a value stored on the proposal itself.
```

### `execute_recovery`

```rust
/// Execute a recovery once quorum has been reached and the timelock has
/// elapsed. Callable by anyone (typically a guardian or the new admin
/// candidate) — authorization comes entirely from the guardian
/// signatures already recorded on the proposal, not from the caller.
///
/// Deliberately does **not** call `require_admin`/`current.require_auth()`:
/// that is precisely the capability that is unavailable when a device is
/// lost. Re-checks quorum at execution time (not just at
/// `approve_recovery` time) in case a guardian revoked between quorum
/// and timelock expiry in a way this contract didn't observe (defense in
/// depth; `revoke_recovery_approval` already clears `ready_at`, but this
/// guards against any future code path that forgets to). This re-check is
/// belt-and-suspenders, not a live-config-tracking mechanism: per issue
/// #28 / ADR-028-1, `RecoveryConfig` cannot change at all while this
/// proposal exists, so `config.threshold` here is provably identical to
/// the value used by every prior `approve_recovery` call on this proposal.
///
/// Any in-flight *normal* `propose_admin`/`accept_admin` transfer is
/// cancelled as part of executing a recovery, so the two flows can't race.
```

## 5. Matriz de transición de estados — `RecoveryProposal` × mutaciones de `RecoveryConfig`

| Estado de `RecoveryProposal` | `approvals.len()` vs `threshold` | `ready_at` | `set_recovery_config` (post-fix) | Resultado |
|---|---|---|---|---|
| No existe (`None`) | n/a | n/a | Permitido | Config actualizada; siguiente `initiate_recovery` usa la nueva config. |
| Existe, sub-quorum | `< threshold` | `None` | **Bloqueado** | `Err(RecoveryConfigLocked)`. Estado del proposal sin cambios. |
| Existe, quorum recién alcanzado | `>= threshold` | `Some(seq)` recién armado | **Bloqueado** | `Err(RecoveryConfigLocked)`. |
| Existe, en ventana de timelock | `>= threshold` | `Some(seq)`, `ledger.seq < seq` | **Bloqueado** | `Err(RecoveryConfigLocked)`. |
| Existe, timelock vencido (ejecutable) | `>= threshold` | `Some(seq)`, `ledger.seq >= seq` | **Bloqueado** | `Err(RecoveryConfigLocked)` — el admin debe dejar que se ejecute o cancelarla explícitamente. |
| Recién cancelada (`cancel_recovery` en la misma tx, ya removida de storage) | n/a | n/a | Permitido | Storage ya no tiene `RecoveryProposal`; se comporta como el primer estado. |
| Recién ejecutada (`execute_recovery` en la misma tx, ya removida de storage) | n/a | n/a | Permitido | Idem — `execute_recovery` hace `remove(&DataKey::RecoveryProposal)` antes de retornar. |

Transiciones de `approve_recovery`/`revoke_recovery_approval` **no** se ven
afectadas por este ADR: siguen leyendo `RecoveryConfig` en vivo, pero ese
valor es ahora invariablemente el mismo desde `initiate_recovery` hasta que
el proposal se cierra (ver ADR-028-1, sección "Decisión", punto 3).

## 6. Matriz de casos de prueba (para QA)

| # | Test | Precondición | Acción | Resultado esperado |
|---|---|---|---|---|
| 1 | `test_set_recovery_config_succeeds_without_pending_recovery` | Sin `RecoveryProposal` | `set_recovery_config(admin, 2, 10)` | `Ok(())`; config persistida. |
| 2 | `test_set_recovery_config_fails_while_recovery_pending_sub_quorum` | `initiate_recovery` llamado, sin alcanzar quorum | `set_recovery_config(admin, 3, 20)` | `Err(RecoveryConfigLocked)`; config original sin cambios. |
| 3 | `test_set_recovery_config_fails_while_recovery_pending_at_quorum` | Quorum alcanzado, `ready_at` armado, antes de vencer | `set_recovery_config(admin, 2, 5)` (lower) | `Err(RecoveryConfigLocked)`; `ready_at` sin cambios. |
| 4 | `test_set_recovery_config_fails_while_recovery_ready_to_execute` | Quorum alcanzado y `ledger.seq >= ready_at` | `set_recovery_config(admin, 4, 10)` (raise) | `Err(RecoveryConfigLocked)`; `execute_recovery` posterior sigue funcionando con la config original. |
| 5 | `test_set_recovery_config_succeeds_immediately_after_cancel_recovery` | Proposal pendiente → `cancel_recovery` | `set_recovery_config(admin, 3, 15)` | `Ok(())` en la misma prueba, sin necesidad de un nuevo bloque/ledger. |
| 6 | `test_set_recovery_config_succeeds_immediately_after_execute_recovery` | Proposal ejecutado con éxito | `set_recovery_config(new_admin, 3, 15)` | `Ok(())`; confirma que `RecoveryProposal` fue removido de storage por `execute_recovery`. |
| 7 | `test_set_recovery_config_locked_error_does_not_mutate_state` | Cualquier estado "pendiente" de la matriz de la sección 5 | `try_set_recovery_config` con distintos `threshold`/`delay` | `RecoveryConfig` y `RecoveryProposal` idénticos antes/después (byte a byte, vía `recovery_config()`/`recovery_proposal()`). |
| 8 | `test_approve_recovery_uses_config_stable_across_proposal_lifetime` | `initiate_recovery` con config X | Dos `approve_recovery` de guardianes distintos, sin `set_recovery_config` intermedio (bloqueado por diseño) | `threshold`/`delay_in_ledgers` efectivos idénticos a X en cada aprobación — test de regresión que documenta el invariante, no solo el guard. |
| 9 | `test_non_admin_cannot_bypass_recovery_config_lock` | Proposal pendiente | `set_recovery_config` invocado por una address no-admin | `Err(Unauthorized)` (se evalúa **antes** o **después** de `RecoveryConfigLocked` según el orden de checks elegido en la implementación — fijar el orden exacto en el PR y testear ese orden explícitamente). |
| 10 | `test_add_remove_guardian_still_allowed_mid_recovery` | Proposal pendiente | `add_guardian`/`remove_guardian` | `Ok(())` — confirma que ADR-028-1 **no** amplía el bloqueo a membresía de guardianes (issue #26 sigue vigente sin cambios). |
| 11 | Regresión de snapshot | Cualquiera de los anteriores que emita/deje de emitir eventos | Ejecutar bajo `cargo test` | Nuevos snapshots en `test_snapshots/tests/` generados y commiteados junto al fix, no en este documento. |

> Nota para QA: los tests 1–9 deben añadirse a
> `contracts/globe-wallet/src/lib.rs` (`mod tests`), siguiendo el patrón
> `try_*` + `assert_eq!(..., Err(Ok(WalletError::...)))` ya usado en el
> archivo (ver ejemplos en las líneas ~1920-2070). El test 10 es de
> regresión de la Issue #26 y debe verificar explícitamente que este ADR
> no la reabre.

## 7. Estado del entorno local (auditoría)

Ejecutado con [scripts/audit-env-issue-28.sh](../../scripts/audit-env-issue-28.sh)
el 2026-08-26:

| Herramienta | Versión detectada | Estado |
|---|---|---|
| `rustc` | 1.97.1 | ✅ |
| `cargo` | 1.97.1 | ✅ |
| `stellar` (CLI, sucesor de `soroban-cli`) | 27.1.0 | ✅ |
| target `wasm32-unknown-unknown` | instalado | ✅ |
| `soroban-sdk` (pin en `Cargo.toml` raíz) | 21.7.7 | ✅ coincide con lo pineado |

**Nota:** `rustc`/`cargo`/`rustup` viven en `~/.cargo/bin`, que no está en
el `PATH` por defecto de shells no interactivos en este entorno. Usar:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
```
antes de invocar `cargo`/`rustc` directamente en scripts o CI locales.

## 8. Próximos pasos

1. ~~Validar con el equipo cuál de las opciones (A)/(B)/(C) se adopta~~ →
   **cerrado**: ADR-028-1 aceptado, opción A.
2. Escribir los tests de la matriz de la sección 6 en modo *red* (deben
   fallar contra el código actual, demostrando el bug).
3. Implementar el guard `RecoveryConfigLocked` en `set_recovery_config`
   con el discriminante `1031`, exactamente como se especifica en las
   secciones 3 y 4 de este documento.
4. Aplicar textualmente los doc comments de la sección 4 a
   `set_recovery_config`, `approve_recovery` y `execute_recovery`.
5. Verificar que los tests de la sección 6 pasan en verde y regenerar
   solo los snapshots nuevos/afectados en `test_snapshots/tests/`.
