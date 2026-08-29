# Threat model: wiring `globe-wallet::record_spend` to `token-wrapper::transfer_from`

Written against [issue #92](https://github.com/Orbit-Wal/contract/issues/92),
implementing the wiring `docs/design/architecture.md`'s "Future: wiring the
contracts together" section left as a follow-up. This document is the
design-decision write-up CONTRIBUTING.md requires before/alongside the code —
read it before reading the diff.

## 1. What already exists, and what's new

`docs/record-spend-reentrancy.md` proves `record_spend` is reentrancy-safe
**in isolation**: its own read-check-write sequence never calls out to another
contract, so nothing can interleave with it. That proof is still true and
this change does not touch `record_spend`'s body at all.

What's new is `GlobeWallet::send` — the actual wiring — which, by
construction, **does** make an external call (to `token-wrapper`, which
itself calls an arbitrary, caller-supplied `token_id`). That external call is
a new reentrancy surface the existing proof says nothing about, because it
didn't exist yet when that proof was written. This document extends the
analysis to that new surface.

## 2. The call chain

```
GlobeWallet::send(user, token_id, asset_code, to, amount)
  │
  ├─ 1. require_auth(user)
  ├─ 2. token_id allowlist check                       ── no external call
  ├─ 3. Self::record_spend(...)                         ── no external call (see below)
  │
  └─ 4. TokenWrapperClient::transfer_from(spender=self, token_id, from=user, to, amount)
           │
           ├─ allowance check + decrement               ── token-wrapper's own storage
           │
           └─ token::Client::new(&env, &token_id).transfer(from, to, amount)
                    │
                    └─ arbitrary code at `token_id` runs here
```

Step 3 calls `record_spend` as a **direct Rust associated-function call**
(`Self::record_spend(...)`), not `env.invoke_contract`. It executes in the
same host frame as `send` itself — there is no cross-contract boundary
between step 3 and the rest of `send`, so `record_spend`'s existing
reentrancy proof continues to hold unmodified: by the time step 4 begins,
`DailySpent` has already been read, checked, written, and its TTL extended,
with zero opportunity for anything to observe or interleave with that
sequence.

Step 4 is the one place in this entire call chain where control transfers to
code this contract does not control: first `token-wrapper` (a contract we
wrote, but which itself calls out further), then whatever contract
`token_id` actually points to.

## 3. What the platform guarantees, and what it doesn't

### 3.1 Reentry into `GlobeWallet` itself is blocked by the host, not by us

Soroban's default contract-invocation policy is `ContractReentryMode::Prohibited`:
once a contract's frame is active on the call stack, the host refuses to let
any subsequent call — from anywhere in the chain — re-enter that same
contract while the frame is still open. `docs/record-spend-reentrancy.md`
already establishes this for the direct case and cites the platform source
(`rs-soroban-env`'s `frame.rs`) and CAP-0046-11.

This is not scoped to a particular function or a particular caller's
intentions — it's keyed on **contract identity on the call stack**,
unconditionally. So for the chain in §2: while `GlobeWallet::send`'s frame is
open (which it is for the entire duration of steps 1-4, since step 4 is the
last thing `send` does before returning), **no code anywhere further down
the chain — including a fully adversarial contract at `token_id` — can
successfully call back into any `GlobeWallet` function.** Not `record_spend`,
not `send` again, not anything else. The host rejects the attempt before
`GlobeWallet` code ever runs.

The same protection applies one level in: while `token-wrapper`'s frame is
open (during its call into `token_id`), nothing can re-enter `token-wrapper`
either — so a malicious `token_id` can't loop back through
`token-wrapper::transfer_from` again to double-spend a different allowance
in the same chain.

**This is proven, not assumed, for the specific 3-hop chain in this PR** by
`test_send_rejects_reentrant_malicious_token` in
`contracts/globe-wallet/src/lib.rs`, which deploys a real mock contract whose
`transfer` implementation calls `GlobeWalletClient::record_spend` before
returning, and asserts the outer `send` call fails rather than silently
succeeding with a corrupted double-count. This does not merely restate the
existing single-contract proof — it exercises the actual multi-contract path
this PR adds, because a platform guarantee that holds for one call depth is
worth re-verifying, not re-assuming, at a new depth with a genuinely
adversarial callee in the loop.

### 3.2 What reentrancy protection does *not* cover

An arbitrary `token_id` is still a fully adversarial piece of code running
with the CPU/memory budget of the caller's transaction, and reentry
prohibition only closes the *callback* vector. It does not close:

- **Fake settlement.** A `token_id` need not be a real asset at all — its
  `transfer` function can simply return successfully having moved nothing.
  `record_spend` will have already decremented the user's daily allowance,
  and `token-wrapper` will have already decremented the on-chain allowance,
  against a transfer that had no real economic effect. This is not a
  reentrancy bug; it's a trust bug — `send` has no way to know a `token_id`
  is "real" unless something tells it so.
- **Resource griefing.** A malicious `token_id`'s `transfer` can burn CPU
  budget or storage I/O attempting expensive work before failing. Because
  Soroban transactions are atomic, a failure here reverts `record_spend`'s
  write along with everything else in the same transaction — so this is a
  self-inflicted, single-transaction failure for whoever chose to pass that
  `token_id`, not a way to corrupt another user's state. It is still bad UX
  (a spent budget with no result) and worth closing off entirely rather than
  leaving as "at least it's not exploitable."
- **Anything that doesn't require calling back into a contract already on
  the stack** — e.g. `token_id`'s `transfer` calling into some *third*,
  unrelated contract to do something bad. That's a general "don't call
  arbitrary code" problem, not specific to this wiring, and is exactly why
  §4 restricts `token_id` rather than relying on reentry prohibition alone.

## 4. Chosen mitigations

Both of the suggested-fix's options are implemented, because they close
different halves of the problem:

1. **Token allowlist** (`DataKey::AllowedTokens`, admin-gated
   `add_allowed_token`/`remove_allowed_token`, checked in `send` before any
   state changes). This is the mitigation that actually matters here: it's
   what stops §3.2's fake-settlement and resource-griefing paths, since
   neither of those is a reentrancy problem reentry prohibition can address.
   `send` rejects any `token_id` not on the allowlist with
   `WalletError::TokenNotAllowed`, before touching any storage.

2. **Checks-effects-interactions across the whole wired call, not just
   within `record_spend`.** `send` performs the allowlist check, then
   `record_spend` (all of globe-wallet's own state changes), and only then
   the external `transfer_from` call — so even in a hypothetical future
   Soroban version where reentry rules changed, every one of globe-wallet's
   *own* writes for this operation is already committed before any external
   code runs. This is "defense in depth" given §3.1 already proves the
   direct callback is blocked at the platform level today — but platform
   guarantees are exactly the kind of thing `docs/record-spend-reentrancy.md`
   itself says to "revisit ... when upgrading the Soroban SDK/host,
   especially if contract re-entry rules change." Ordering the wiring this
   way means a future change to those rules would need a *second*,
   independent gap (a way to actually corrupt already-committed state) to
   cause harm, not just a change in reentry policy.

Why not *only* the allowlist, skipping CEI ordering? Because the ordering
costs nothing (it's the natural way to write the function) and is exactly
the property that would matter if the platform guarantee in §3.1 ever
weakened — relying solely on a platform invariant this contract doesn't
control, when a free structural mitigation is available, is not the
conservative choice for code that moves real money.

Why not *only* CEI ordering, skipping the allowlist? Because CEI ordering
protects against reentrancy corrupting state; it does nothing about a
`token_id` that simply lies about having moved value. The allowlist is
non-negotiable for that.

## 5. What `send` does NOT do (explicitly out of scope)

- It does not attempt to validate that an allowlisted `token_id` is
  "correctly" implemented beyond the standard token interface — allowlisting
  is a governance/curation decision (admin adds only contracts it has
  verified), not something this contract can check on-chain.
- It does not change `record_spend`'s signature, storage layout, or
  behavior. `test_record_spend_*` and the existing
  `two_spends_in_one_host_invocation_accumulate` continue to pass unmodified
  (see the PR's pasted `cargo test` output).
- It does not attempt to make `token-wrapper::transfer_from` itself
  allowlist-aware — `token-wrapper` remains a general-purpose,
  globe-wallet-agnostic allowance primitive, matching its existing module
  doc. Gating happens at the `send` call site in `globe-wallet`, which is
  where the trust decision actually belongs.
