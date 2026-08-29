# GlobeWallet Protocol Architecture

## Overview

The GlobeWallet protocol consists of two Soroban smart contracts:

| Contract | Role |
|---|---|
| `globe-wallet` | Core wallet registry — per-user asset whitelist, per-asset daily spend limits, admin governance |
| `token-wrapper` | Allowance-gated token transfers — approve/spend-from pattern on top of the Soroban token interface |

## Intended relationship

The `token-wrapper` contract exists to **enable the globe-wallet contract to move
tokens on behalf of users** who have granted a per-session allowance (per its
module doc comment). In the intended architecture:

1. The user grants an allowance to the globe-wallet contract via
   `token-wrapper::approve(owner=user, spender=globe_wallet_id, token_id, amount, expiry)`.
2. The globe-wallet contract calls `token-wrapper::transfer_from(spender=globe_wallet_id, ...)`
   internally as part of its payment path.
3. Globe-wallet enforces daily spend limits via `record_spend` **before** (or as
   part of) the `transfer_from` call.

This two-contract composition means **spend limits are enforced at the
globe-wallet layer, and the token-wrapper layer handles the actual token
movement on Soroban**.

```
┌──────────────────────────────────────────┐
│                 Integrator               │
│  (backend / wallet UI / mobile app)      │
└─────────────┬────────────────────────────┘
              │ calls
              ▼
┌─────────────────────────────────────────┐
│           globe-wallet                   │
│  ┌───────────────────────────────────┐  │
│  │ record_spend  ← enforces daily   │  │
│  │ (user, asset,   spend limit      │  │
│  │  amount)        before transfer  │  │
│  └───────────┬───────────────────────┘  │
│              │ pass-through              │
│              ▼                           │
│  ┌───────────────────────────────────┐  │
│  │ token-wrapper::transfer_from      │  │
│  │   ← allowance check              │  │
│  │   ← SAC token transfer           │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

## Current state: contracts are not wired together

**As of the current codebase, globe-wallet and token-wrapper are fully independent
and do not call each other.**

Verifying by inspection:

```bash
# token-wrapper has zero awareness of globe-wallet's spend-limit logic
$ grep -rn "globe_wallet\|GlobeWallet\|record_spend" contracts/token-wrapper/src/
# → only the module doc comment string "GlobeWallet" — no code-level reference

# globe-wallet has zero awareness of token-wrapper's allowance logic
$ grep -rn "token_wrapper\|TokenWrapper\|transfer_from" contracts/globe-wallet/src/
# → no matches at all
```

Neither contract stores the other's address, neither invokes the other via
`env.invoke_contract`, and neither imports the other's client type.

## Security implication

A payment routed through **`token-wrapper::transfer_from` directly** (bypassing
`globe-wallet` entirely) is **not subject to any daily spend limit**. This is a
materially weaker security posture than what the project's stated pitch
("spend limits… to limit loss on key compromise") implies to anyone who hasn't
read both contracts' full source.

> ⚠️ **Known gap:** Until globe-wallet and token-wrapper are wired together
> (or a single entry-point contract is introduced that chains `record_spend`
> before `transfer_from`), the spend-limit guarantee only applies when
> integrators route through globe-wallet's API. There is no on-chain
> enforcement preventing a caller from using token-wrapper directly and
> bypassing the daily cap.

## Integration guidance

For integrators (the backend repo, wallet UI, or mobile app), the correct
payment path until the contracts are wired together is:

1. **Call `globe-wallet::record_spend(user, asset_code, amount)`** — this enforces
   the daily spend limit. If the limit is exceeded, the call fails and the
   entire transaction reverts.
2. **Call `token-wrapper::transfer_from(spender, token_id, from, to, amount)`** —
   this checks the allowance and executes the SAC token transfer.

These must be called **together in a single transaction** (or at minimum
`record_spend` must succeed before `transfer_from`) for the spend limit to
take effect.

The backend `src/services/contracts/globeWallet.ts` and
`src/services/soroban.ts` integration layers should ensure both calls are made
in the correct order for any user-initiated send operation.

## Future: wiring the contracts together

A follow-up issue should track actually wiring the contracts so that the
spend-limit guarantee is enforced on-chain rather than relying on integrator
discipline:

- globe-wallet could be given the token-wrapper contract ID and call
  `transfer_from` internally after `record_spend` succeeds.
- Or a new entry-point function on globe-wallet (e.g., `send`) could be added
  that atomically calls `record_spend` → `transfer_from`.
- Either approach closes the bypass gap and makes the "spend limits to limit
  loss on key compromise" claim hold for every on-chain payment path.

## Related documents

- [record_spend day-boundary analysis](./record_spend_boundary.md) — how the
  fixed-bucket daily spend window works, including boundary guarantees and
  the ±1 s drift edge case.