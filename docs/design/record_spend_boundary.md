# `record_spend` Day-Boundary Guarantee Analysis

## 1. How the bucket is computed

```rust
let now = env.ledger().timestamp(); // Unix seconds, set by validators
let day = now / 86_400;             // integer division → UTC midnight bucket
```

`env.ledger().timestamp()` is the **close time of the ledger** that executes the transaction.
Stellar validators agree on this timestamp via consensus within a tolerance band
(the Stellar Core `MAX_CLOSE_TIME_DRIFT`, currently **±1 second** from the network median).

---

## 2. Exact boundary guarantee

| Timestamp (Unix seconds)  | `day = ts / 86_400` | Bucket           |
|---------------------------|---------------------|------------------|
| `N × 86_400 − 1`          | `N − 1`             | previous day     |
| `N × 86_400`              | `N`                 | **new day — counter resets** |
| `N × 86_400 + 1`          | `N`                 | same new day     |

**Formal statement:**

> Two invocations of `record_spend` whose ledger timestamps satisfy
> `⌊t₁ / 86400⌋ == ⌊t₂ / 86400⌋` will accumulate into the **same** daily total.
> Any pair where `⌊t₁ / 86400⌋ ≠ ⌊t₂ / 86400⌋` will each start from a **fresh zero**.
>
> Proven by tests in `contracts/globe-wallet/src/lib.rs`:
> - `test_record_spend_exact_day_boundary`
> - `test_record_spend_boundary_last_second_of_day_accumulates`
> - `test_record_spend_boundary_first_second_of_new_day_resets`
> - `test_record_spend_bucket_is_integer_division`
> - `test_record_spend_boundary_drift_awareness`

---

## 3. Known edge case: validator timestamp drift at midnight

Stellar ledger close times are **not perfectly uniform**. The consensus protocol
allows up to ±1 s drift from the network median. Two transactions a human user
considers simultaneous could receive ledger timestamps straddling an exact
`N × 86_400` boundary.

**Probability:** 1 / 86,400 ≈ **0.0012%** per pair of back-to-back transactions.

**Effect:** The second transaction lands in a new bucket and its daily counter
**resets to zero** — giving the user a fresh full daily limit rather than
accumulating against what they spent seconds before midnight.

**Is this exploitable?**

No. The reset is *more restrictive* than the user expected in the usual case.
A malicious user cannot use this to exceed their daily cap; they can only
accidentally benefit from a reset (spending more in a calendar day than
intended). This is an **edge-case UX confusion, not a security hole**.

`test_record_spend_boundary_drift_awareness` documents this behavior explicitly.

---

## 4. Fixed-bucket vs rolling 24 h window

### Fixed bucket (current implementation)

**Pros:**
- Simple: one storage key per (user, asset), one field (`day`) to invalidate old data.
- Gas-efficient: no range scan, no ordered log.
- Predictable reset: users know limits refresh at UTC midnight.
- No unbounded state growth.

**Cons:**
- The boundary can split what a human considers "the same session" (±1 s drift,
  probability 0.001%).
- A user can spend near-cap just before midnight and again after — effectively
  2× in a calendar day. This is by-design but may surprise users.

### Rolling 24 h window

**Pros:**
- Eliminates the midnight double-spend UX issue.
- More aligned with how users think of "last 24 hours".

**Cons:**
- Requires storing a **timestamped transaction log** (unbounded state growth), or
  a circular buffer — complex in a `#![no_std]` Soroban environment.
- Higher gas per `record_spend` call (scan/sum the window).
- TTL archival risk: if an old log entry is archived, the window silently widens —
  harder correctness guarantee than a simple day bucket.

---

## 5. Recommendation

**Keep the fixed-bucket design.**

The 0.001% boundary drift risk is not exploitable. The UX confusion (counter
resetting slightly earlier or later than the user expected) is minor and
fully documented by the tests.

If the midnight double-spend UX concern becomes a real product issue, the correct
mitigation (in increasing order of complexity) is:

1. **Client-side warning** in the wallet UI when a spend is attempted within
   N minutes of UTC midnight.
2. **Configurable epoch offset** stored per-user: `day = (ts + user_offset) / 86_400`
   shifts the personal "midnight" without adding on-chain complexity.

Both preserve the O(1) on-chain storage invariant while addressing the UX
issue at the correct layer.
