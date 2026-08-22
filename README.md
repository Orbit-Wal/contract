# GlobeWallet — Contract

Soroban smart contracts for the GlobeWallet protocol on the Stellar network.

## Contracts

| Contract | Description |
|---|---|
| `globe-wallet` | Core wallet registry — asset whitelist, spend limits, admin governance |
| `token-wrapper` | Allowance-gated token transfers for protocol integrations |

## Stack

| Layer | Technology |
|---|---|
| Platform | Stellar / Soroban |
| Language | Rust (`#![no_std]`) |
| SDK | soroban-sdk 21.x |
| Build | cargo + soroban-cli |

## Getting Started

Install the Soroban CLI:

```bash
cargo install --locked soroban-cli
```

Build all contracts:

```bash
cargo build --target wasm32-unknown-unknown --release
```

Run tests:

```bash
cargo test
```

Deploy to testnet (requires funded keypair):

```bash
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/globe_wallet.wasm \
  --source <SECRET_KEY> \
  --network testnet
```

## Contract: `globe-wallet`

### API

```rust
// Admin
initialize(env, admin)
admin(env) -> Address
transfer_admin(env, current, new_admin)

// Asset registry (self-sovereign, user.require_auth())
add_asset(env, user, asset: AssetInfo) -> Result<()>
remove_asset(env, user, asset_code: String) -> Result<()>
get_assets(env, user) -> Vec<AssetInfo>

// Spend limits
set_spend_limit(env, user, asset_code, limit: i128) -> Result<()>
get_spend_limit(env, user, asset_code) -> i128
record_spend(env, user, asset_code, amount) -> Result<()>
```

### Spend Limit Logic

- Limit is per-user, per-asset, daily (86 400-second window from ledger timestamp).
- `limit = 0` means unlimited.
- `record_spend` is called from any payment path; rejects with `SpendLimitExceeded` if
  cumulative daily spend would exceed the limit.
- Day window resets automatically — no manual reset required.

## Contract: `token-wrapper`

Provides `approve` / `allowance` / `transfer_from` semantics on top of the
Soroban token interface, enabling the globe-wallet contract to move tokens
on behalf of users within a session allowance.

> **Important:** `approve` uses **overwrite** semantics — calling it again
> for the same `(owner, spender)` pair **replaces** the previous allowance
> rather than adding to it. See the function's doc comment for details.

## Events

| Contract | Topic | Data |
|---|---|---|
| globe-wallet | `initialized` | admin |
| globe-wallet | `admin_transferred` | (old, new) |
| globe-wallet | `asset_added` | (user, asset_code) |
| globe-wallet | `asset_removed` | (user, asset_code) |
| globe-wallet | `spend_limit_set` | (user, asset_code, limit) |
| globe-wallet | `spend_recorded` | (user, asset_code, amount, total, limit) |
| token-wrapper | `approved` | (owner, spender, amount, expiry) |
| token-wrapper | `transfer_from` | (spender, from, to, amount) |

## Related Repos

- [`Orbit-Wal/Globe-Wallet`](https://github.com/Orbit-Wal/Globe-Wallet) — Web frontend
- [`Orbit-Wal/mobile`](https://github.com/Orbit-Wal/mobile) — React Native app
- [`Orbit-Wal/backend`](https://github.com/Orbit-Wal/backend) — REST API
