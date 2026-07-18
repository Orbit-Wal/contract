# `record_spend` reentrancy invariant

## Decision

`GlobeWallet::record_spend` is reentrancy-safe in its current form. The
read/check/write sequence for `DailySpent` cannot be interleaved with another
invocation of `GlobeWallet`: there is no contract call between the read and the
write, and ordinary Soroban contract calls prohibit contract re-entry.

This conclusion is deliberately limited to reentrancy. It does not establish
that every possible `amount`, limit configuration, or payment integration is
otherwise valid.

## Invariant

For a positive limit, one `(user, asset_code, day)` key, and successful
positive-amount calls, each `record_spend` observes the amount written by every
earlier call in the same host invocation. It writes exactly

```text
previous amount for the current day + requested amount
```

and only when that value is at most the configured limit. A failed call does
not commit a partial update.

## Proof for the current implementation

The relevant operations execute in this order:

1. `user.require_auth()` completes.
2. The limit is read.
3. `DailySpent(user, asset_code)` is read.
4. `checked_add` computes the candidate amount.
5. The candidate is compared with the limit.
6. `DailySpent` is written.
7. The `spend_recorded` event is published.

For a contract address, step 1 may cause the host to invoke that account
contract's reserved `__check_auth` function. This happens before the
`DailySpent` snapshot in step 3, so it cannot observe the function between its
check and write.

After step 3, the implementation uses only arithmetic and Soroban ledger,
storage, and event host APIs. It does not use `Env::invoke_contract`, a
generated client for another contract, token transfer APIs, or any other
operation that can transfer control to caller-supplied contract code.
Consequently, no callback can occur inside the read/check/write interval.

There is a second, independent platform guarantee: normal Soroban contract
invocations use prohibited re-entry mode. An external contract called by
GlobeWallet could not call GlobeWallet again while the original GlobeWallet
frame remained active; the host rejects that attempt with a context
`InvalidAction`. The special self-reentry allowance for custom-account
`__check_auth` applies to the account contract being authenticated, not to an
unrelated GlobeWallet frame.

The regression test `two_spends_in_one_host_invocation_accumulate` exercises
the remaining same-invocation case. A batching contract calls `record_spend`
twice under one root host invocation. The two amounts exactly consume the
limit, and a subsequent one-unit spend is rejected. If the second call read a
stale value and overwrote the first write, that final spend would incorrectly
succeed.

## Guidance for future changes

Keep the interval from reading `DailySpent` through writing the replacement
`SpendRecord` free of interactions. In particular:

- Do not insert a generated contract-client call, `Env::invoke_contract`,
  token transfer, callback, hook, or user-controlled authorization operation
  inside that interval.
- Keep `require_auth` before the `DailySpent` read. Contract-account
  authentication can execute `__check_auth`.
- Do not split the operation into separately callable "check" and "commit"
  entrypoints.
- Read and write the same `(user, asset_code, day)` identity; do not derive
  either side from mutable state that an interaction can change.
- If an interaction becomes necessary, apply checks-effects-interactions:
  commit the spend before calling out and rely on Soroban's transaction
  rollback if the later interaction fails. Add a regression test for the
  exact callback path. If execution semantics ever permit GlobeWallet
  re-entry, add an explicit per-key reentrancy guard as well.
- Revisit this proof and its regression test when upgrading the Soroban
  SDK/host, especially if contract re-entry rules change.

## Platform references

- [Stellar authorization documentation](https://developers.stellar.org/docs/learn/fundamentals/contract-development/authorization)
  describes contract-account `__check_auth` invocation by `require_auth`.
- [CAP-0046-11, self-reentrancy for custom accounts](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0046-11.md#self-reentrancy-for-custom-accounts)
  defines the narrow custom-account exception and states that re-entering
  another contract remains prohibited.
- [Soroban host frame enforcement](https://github.com/stellar/rs-soroban-env/blob/v26.1.3/soroban-env-host/src/host/frame.rs)
  rejects re-entry in `ContractReentryMode::Prohibited`.
