# Issue #28 — Contexto persistente (SSOT)

> **Título:** `set_recovery_config` can be called mid-recovery with no guard or documented interaction
> **Repo:** Orbit-Wal/contract · **Contrato:** `contracts/globe-wallet`
> **Rama de trabajo:** `fix/issue-28`
> **Estado:** 🟡 Análisis inicial — sin fix aplicado aún
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

### Pregunta de diseño pendiente (a resolver antes de implementar el fix)

¿Cuál debe ser el comportamiento deseado?
- **(a) Bloquear** `set_recovery_config` mientras `RecoveryProposal` esté
  pendiente (`RecoveryAlreadyPending`-style guard), forzando a
  cancelar/ejecutar primero. Más simple y predecible; ya existe precedente
  de "una sola operación en vuelo a la vez" en el propio contrato
  (`RecoveryAlreadyPending`, `UpgradeAlreadyPending`).
- **(b) Permitir el cambio pero congelar (`snapshot`) el `threshold` en el
  momento de `initiate_recovery`**, igual que ya se hace con
  `delay_in_ledgers`/`ready_at`, para que toda la propuesta sea evaluada de
  forma consistente con la config vigente al momento de iniciarla.
- **(c) Permitir el cambio y documentar explícitamente el modelo live**,
  añadiendo el evento faltante y tests que fijen el comportamiento como
  contrato público (no recomendado: mantiene la superficie de ataque de los
  escenarios 1 y 2).

> **Recomendación preliminar (sujeta a revisión del equipo de contratos):**
> opción (a), por consistencia con los guards ya existentes
> (`RecoveryAlreadyPending`, `UpgradeAlreadyPending`) y porque minimiza la
> superficie de estados intermedios a testear.

## 3. Objetivos de testing

Ninguno de estos casos tiene cobertura actual (verificado por búsqueda en
`contracts/globe-wallet/src/lib.rs` y `contracts/globe-wallet/tests/`):

- [ ] `test_set_recovery_config_fails_while_recovery_pending` — llamar
      `set_recovery_config` con una `RecoveryProposal` activa debe fallar
      (si se adopta la opción (a)) con un nuevo `WalletError` dedicado.
- [ ] `test_set_recovery_config_lowering_threshold_mid_recovery_does_not_retroactively_quorate`
      — regresión explícita para el escenario 1 si se adopta (b) o (c).
- [ ] `test_set_recovery_config_raising_threshold_mid_recovery_documented_effect_on_ready_at`
      — fija el comportamiento del escenario 2.
- [ ] `test_set_recovery_config_after_recovery_cancelled_or_executed_succeeds`
      — camino feliz: reconfigurar es válido en ausencia de propuesta.
- [ ] Test de orden de sub-invocación dentro de un mismo host invocation
      (patrón ya usado en
      [contracts/globe-wallet/tests/record_spend_reentrancy.rs](../../contracts/globe-wallet/tests/record_spend_reentrancy.rs))
      adaptado a `set_recovery_config` + `approve_recovery`/`execute_recovery`.
- [ ] Evento nuevo (si aplica) cubierto por snapshot test en
      `test_snapshots/tests/`.

## 4. ADRs preliminares (borrador, no decididos)

### ADR-028-1: Bloquear reconfiguración durante recovery activa
- **Estado:** Propuesto
- **Contexto:** Ver sección 2, escenarios 1 y 2.
- **Decisión propuesta:** Añadir guard en `set_recovery_config` que
  retorne un nuevo `WalletError::RecoveryPendingConfigLocked` (o reutilizar
  `RecoveryAlreadyPending` con semántica ampliada — a decidir) si
  `env.storage().instance().has(&DataKey::RecoveryProposal)`.
- **Consecuencias:** El admin debe `cancel_recovery` o esperar a
  `execute_recovery` antes de poder ajustar `threshold`/`delay_in_ledgers`.
  Requiere actualizar docs (`RECOVERY.md` si existe) y el doc-comment de
  `set_recovery_config`.

### ADR-028-2: Numeración de errores
- **Estado:** Propuesto
- **Contexto:** Namespace de errores del contrato es contiguo desde 1001
  (ver comentario en `WalletError`, línea ~140). Último discriminante
  visto: `RecoveryNotQuorate = 1028`.
- **Decisión propuesta:** Nuevo error, si se requiere, debe usar
  `1029` y mantenerse en el mismo namespace `1001+`.

### ADR-028-3: No tocar el modelo frozen de `delay_in_ledgers`/`ready_at`
- **Estado:** Propuesto
- **Contexto:** Ese snapshot ya es correcto y está cubierto por tests
  existentes (`test_raise_spend_then_lower_limit` es de spend limits, no
  de recovery — verificar cobertura real de `ready_at` freeze antes de
  asumir cobertura).
- **Decisión propuesta:** El fix de la Issue #28 no debe alterar cómo se
  congela `ready_at`; solo debe cerrar la ventana de reconfiguración de
  `threshold` a mitad de proceso.

## 5. Estado del entorno local (auditoría)

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

## 6. Próximos pasos

1. Validar con el equipo cuál de las opciones (a)/(b)/(c) de la sección 2
   se adopta como decisión de diseño definitiva → cerrar ADR-028-1.
2. Escribir los tests de la sección 3 en modo *red* (deben fallar contra el
   código actual, demostrando el bug).
3. Implementar el guard/snapshot elegido en `set_recovery_config`.
4. Actualizar doc-comments de `set_recovery_config` y, si existe,
   `RECOVERY.md`/`docs/design/architecture.md`.
5. Verificar snapshots de test (`test_snapshots/tests/`) regenerados solo
   para los tests nuevos/afectados.
