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
   `token-wrapper::approve(owner=user, spender=globe_wallet_id, amount, expiry)`.
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

## Current state: reentrancy-safe wired payment architecture

GlobeWallet and token-wrapper are wired together on-chain via the `GlobeWallet::send` entry point:

1. **Allowance Delegation**: The user grants an allowance to `globe-wallet` via `token-wrapper::approve(owner=user, spender=globe_wallet_id, amount, expiry)`.
2. **Wired Send**: The user invokes `globe-wallet::send(user, token_wrapper, token_id, to, asset_code, amount)`.
3. **Enforcement & Settlement**:
   - `globe-wallet` performs CHECKS (validates amount > 0, verifies `token_id` is on the admin-curated allowlist, checks daily spend limit).
   - `globe-wallet` applies EFFECTS (records and commits updated `DailySpent` in persistent storage).
   - `globe-wallet` executes INTERACTIONS (calls `token-wrapper::transfer_from(spender=globe_wallet_id, token_id, from=user, to, amount)` which debits the allowance and executes the token transfer).

```
┌───────────────────────────────────────────────────────────┐
│                        Integrator                         │
│           (backend / wallet UI / mobile app)              │
└─────────────┬─────────────────────────────────────────────┘
              │ calls
              ▼
┌──────────────────────────────────────────────────────────┐
│                      globe-wallet                        │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 1. Checks: token allowlist & spend limit           │  │
│  │ 2. Effects: commit DailySpent to storage           │  │
│  └──────────┬─────────────────────────────────────────┘  │
│             │ 3. Interactions (pass-through)             │
│             ▼                                            │
│  ┌────────────────────────────────────────────────────┐  │
│  │ token-wrapper::transfer_from                       │  │
│  │   ← allowance check & debit                        │  │
│  │   ← external token contract transfer               │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

## Threat Model: Arbitrary Token Contract Execution

### Attack Vectors
When a payment workflow invokes a caller-supplied `token_id`, the external contract code is untrusted. Unlike the standard Stellar Asset Contract (SAC), a custom or malicious token contract could:
1. **Re-enter `globe-wallet` mid-flight**: The token contract's `transfer` implementation could call back into `globe-wallet::record_spend` or `globe-wallet::send` before the initial call unwinds, attempting to exploit inconsistent, half-committed spend limit state to bypass daily caps.
2. **Manipulate wallet configuration**: A re-entrant call could attempt to modify guardians, trigger unauthorized recovery operations, or alter spend limits while an outer execution frame is open.
3. **State desynchronization**: If spend recording and token transfer occurred non-atomically or without strict ordering, reentrancy could lead to double-counting or under-counting of daily expenditures.

### Dual Mitigation Strategy

To eliminate these threats completely, GlobeWallet implements both:

1. **Admin-Curated Token Allowlist (`set_token_allowed` / `is_token_allowed`)**:
   - Only token contract addresses explicitly allowlisted by the contract administrator (`TokenNotAllowed = 1034`) can be passed to `send`.
   - Untrusted or arbitrary token contracts are rejected during pre-flight checks before any downstream interaction or contract invocation occurs.

2. **Checks-Effects-Interactions (CEI) Ordering Across the Wired Call Chain**:
   - `globe-wallet::send` executes in strict CEI order:
     - **Checks**: Validate `amount > 0`, verify `token_id` allowlist status, calculate candidate spend against configured daily limit.
     - **Effects**: Write and commit the updated `DailySpent` record to persistent storage, extend TTL, and emit `spend_recorded`.
     - **Interactions**: Only after all internal state is committed does `globe-wallet` invoke `token-wrapper::transfer_from`.
   - Any re-entrant call mid-flight observes fully-committed, consistent state and cannot circumvent daily spend limits.
   - If the downstream transfer fails, Soroban's transaction rollback guarantees that all storage mutations within the invocation revert atomically.

3. **Soroban Platform Invariants**:
   - Soroban host runtime strictly enforces `ContractReentryMode::Prohibited` for normal contract calls, causing any attempted re-entry into active call frames to immediately trap with `Error(Context, InvalidAction)`.

## Integration Guidance

Integrators (backend API, mobile client, and web apps) should route payments through `globe-wallet::send`:

1. User approves the GlobeWallet contract address on `token-wrapper` once per session or spend allowance:
   `token-wrapper.approve(user, globe_wallet_id, allowance_amount, expiry_ledger)`
2. User executes payment:
   `globe-wallet.send(user, token_wrapper_id, token_id, recipient, asset_code, amount)`

## Related Documents

- [record_spend reentrancy & wiring proof](../record-spend-reentrancy.md) — comprehensive proof and security invariants for `record_spend` and wired `send`.
- [record_spend day-boundary analysis](./record_spend_boundary.md) — fixed-bucket daily spend window guarantees.