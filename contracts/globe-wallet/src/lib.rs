#![no_std]

//! # globe-wallet
//!
//! Core GlobeWallet smart contract on Stellar / Soroban.
//!
//! ## Features
//! - Multi-asset wallet registry: track whitelisted assets per user
//! - Admin-gated asset management
//! - Spend limits: per-asset daily caps to limit loss on key compromise
//! - Event emission for all state-changing operations
//!
//! ## Spend Limits
//! Each user can set a `spend_limit` (in stroops/smallest unit) per asset.
//! Payments that would exceed the daily limit are rejected with `SpendLimitExceeded`.
//! Limits reset automatically on ledger-time day boundary.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, BytesN, Env, String, Symbol, Vec,
};

/// Maximum assets per wallet — prevents unbounded O(n) scans.
const MAX_ASSETS: u32 = 50;

// ── Storage Keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    /// Pending admin candidate awaiting acceptance.
    PendingAdmin(Address),
    PendingUpgrade,
    /// Whitelisted assets for a user wallet
    UserAssets(Address),
    /// Spend limit: (user, asset_code) → limit in stroops
    SpendLimit(Address, String),
    /// Daily spent: (user, asset_code) → (amount, day_timestamp)
    DailySpent(Address, String),
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct AssetInfo {
    /// e.g. "XLM", "USDC"
    pub code: String,
    /// Issuer address; None for XLM (native)
    pub issuer: Option<Address>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SpendRecord {
    pub amount: i128,
    /// Ledger-time timestamp of the current day window
    pub day: u64,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct UpgradeProposal {
    pub wasm_hash: BytesN<32>,
    pub proposed_by: Address,
    pub ready_at: u32,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum WalletError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    AssetAlreadyAdded = 4,
    AssetNotFound = 5,
    InvalidSpendLimit = 6,
    /// Payment would exceed the daily spend limit for this asset
    SpendLimitExceeded = 7,
    NoAssetsProvided = 8,
    NoPendingAdmin = 9,
    SpendOverflow = 10,
    /// Wallet already holds the maximum number of assets
    MaxAssetsReached = 11,
    UpgradeAlreadyPending = 12,
    UpgradeNotPending = 13,
    UpgradeNotReady = 14,
    UpgradeHashMismatch = 15,

    UpgradeAlreadyPending = 11,
    UpgradeNotPending = 12,
    UpgradeHashMismatch = 13,
    UpgradeNotReady = 14,
    SpendOverflow = 9,
    NoPendingAdmin = 10,
    UpgradeAlreadyPending = 11,
    UpgradeNotPending = 12,
    UpgradeNotReady = 13,
    UpgradeHashMismatch = 14,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct GlobeWallet;

#[contractimpl]
impl GlobeWallet {
    /// Initialize the contract with an admin address.
    ///
    /// # Errors
    /// * [`WalletError::AlreadyInitialized`]
    pub fn initialize(env: Env, admin: Address) -> Result<(), WalletError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(WalletError::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.events()
            .publish((Symbol::new(&env, "initialized"),), admin);
        Ok(())
    }

    /// Return current admin.
    pub fn admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    /// Legacy single-step admin transfer.
    ///
    /// Deprecated in favor of `propose_admin` + `accept_admin`.
    ///
    /// # Errors
    /// * [`WalletError::NotInitialized`] / [`WalletError::Unauthorized`]
    #[deprecated(note = "Use propose_admin and accept_admin instead")]
    pub fn transfer_admin(env: Env, current: Address, new_admin: Address) -> Result<(), WalletError> {
        Self::propose_admin(env, current, new_admin)
    }

    /// Propose a new admin candidate.
    ///
    /// The current admin remains in control until the candidate accepts.
    pub fn propose_admin(env: Env, current: Address, candidate: Address) -> Result<(), WalletError> {
        current.require_auth();
        Self::require_admin(&env, &current)?;
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin(current.clone()), &candidate);
        env.events().publish(
            (Symbol::new(&env, "admin_proposed"),),
            (current, candidate),
        );
        Ok(())
    }

    /// Accept a pending admin proposal.
    pub fn accept_admin(env: Env, candidate: Address) -> Result<(), WalletError> {
        candidate.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(WalletError::NotInitialized)?;
        let pending: Option<Address> = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin(admin.clone()));
        let pending = pending.ok_or(WalletError::NoPendingAdmin)?;
        if pending != candidate {
            return Err(WalletError::Unauthorized);
        }
        env.storage().instance().set(&DataKey::Admin, &candidate);
        env.storage().instance().remove(&DataKey::PendingAdmin(admin.clone()));
        env.events().publish(
            (Symbol::new(&env, "admin_transferred"),),
            (admin, candidate),
        );
        Ok(())
    }

    /// Cancel the current pending admin proposal.
    pub fn cancel_admin_transfer(env: Env, current: Address) -> Result<(), WalletError> {
        current.require_auth();
        Self::require_admin(&env, &current)?;
        env.storage()
            .instance()
            .remove(&DataKey::PendingAdmin(current.clone()));
        env.events().publish((Symbol::new(&env, "admin_transfer_cancelled"),), current);
        Ok(())
    }

    /// Queue an upgrade for later execution.
    ///
    /// The proposal is stored in contract instance storage and emitted as an
    /// event so the upgrade is visible on-chain before any code swap occurs.
    pub fn propose_upgrade(
        env: Env,
        proposer: Address,
        wasm_hash: BytesN<32>,
        delay_in_ledgers: u32,
    ) -> Result<(), WalletError> {
        proposer.require_auth();
        Self::require_admin(&env, &proposer)?;
        if env.storage().instance().has(&DataKey::PendingUpgrade) {
            return Err(WalletError::UpgradeAlreadyPending);
        }
        let ready_at = env.ledger().sequence().saturating_add(delay_in_ledgers);
        let proposal = UpgradeProposal {
            wasm_hash: wasm_hash.clone(),
            proposed_by: proposer.clone(),
            ready_at,
        };
        env.storage()
            .instance()
            .set(&DataKey::PendingUpgrade, &proposal);
        env.events().publish(
            (Symbol::new(&env, "upgrade_proposed"),),
            (proposer, wasm_hash.clone(), ready_at),
        );

        // Ensure the proposed wasm hash exists in test environment snapshots.
        // soroban-env-host will panic during execute_upgrade() if the wasm blob
        // is missing, so we record the hash during propose_upgrade.
        // No-op in test env: execute_upgrade() will still validate stored hash.
        // soroban-env-host snapshots for this minimal contract may not require
        // pre-registering the wasm blob.
        let _ = wasm_hash.clone();
        Ok(())
    }

    /// Execute a previously proposed upgrade after the timelock elapses.
    pub fn execute_upgrade(
        env: Env,
        executor: Address,
        wasm_hash: BytesN<32>,
    ) -> Result<(), WalletError> {
        executor.require_auth();
        Self::require_admin(&env, &executor)?;
        let proposal: UpgradeProposal = env
            .storage()
            .instance()
            .get(&DataKey::PendingUpgrade)
            .ok_or(WalletError::UpgradeNotPending)?;
        if proposal.wasm_hash != wasm_hash {
            return Err(WalletError::UpgradeHashMismatch);
        }
        if env.ledger().sequence() < proposal.ready_at {
            return Err(WalletError::UpgradeNotReady);
        }
        env.deployer().update_current_contract_wasm(wasm_hash.clone());
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        env.events().publish(
            (Symbol::new(&env, "upgrade_executed"),),
            (executor, wasm_hash),
        );
        Ok(())
    }

    // ── Asset Registry ────────────────────────────────────────────────────────

    /// Add an asset to a user's wallet registry.
    ///
    /// Only the user themselves (via `require_auth`) can add assets.
    ///
    /// # Errors
    /// * [`WalletError::AssetAlreadyAdded`] — asset code already registered.
    pub fn add_asset(env: Env, user: Address, asset: AssetInfo) -> Result<(), WalletError> {
        user.require_auth();
        let mut assets: Vec<AssetInfo> = env
            .storage()
            .persistent()
            .get(&DataKey::UserAssets(user.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        if assets.len() >= MAX_ASSETS {
            return Err(WalletError::MaxAssetsReached);
        }
        for i in 0..assets.len() {
            if assets.get(i).unwrap().code == asset.code {
                return Err(WalletError::AssetAlreadyAdded);
            }
        }
        assets.push_back(asset.clone());
        env.storage()
            .persistent()
            .set(&DataKey::UserAssets(user.clone()), &assets);
        env.events()
            .publish((Symbol::new(&env, "asset_added"),), (user, asset.code));
        Ok(())
    }

    /// Remove an asset from a user's wallet registry.
    ///
    /// # Errors
    /// * [`WalletError::AssetNotFound`] — asset code not registered.
    pub fn remove_asset(env: Env, user: Address, asset_code: String) -> Result<(), WalletError> {
        user.require_auth();
        let assets: Vec<AssetInfo> = env
            .storage()
            .persistent()
            .get(&DataKey::UserAssets(user.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        let mut new_assets: Vec<AssetInfo> = Vec::new(&env);
        let mut found = false;
        for i in 0..assets.len() {
            let a = assets.get(i).unwrap();
            if a.code == asset_code {
                found = true;
            } else {
                new_assets.push_back(a);
            }
        }
        if !found {
            return Err(WalletError::AssetNotFound);
        }
        env.storage()
            .persistent()
            .set(&DataKey::UserAssets(user.clone()), &new_assets);
        env.events()
            .publish((Symbol::new(&env, "asset_removed"),), (user, asset_code));
        Ok(())
    }

    /// Return all assets registered by a user.
    pub fn get_assets(env: Env, user: Address) -> Vec<AssetInfo> {
        env.storage()
            .persistent()
            .get(&DataKey::UserAssets(user))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Admin-only: trim a user's asset list if it exceeds MAX_ASSETS.
    /// Returns the number of assets removed, or 0 if already within bounds.
    pub fn migrate_user_assets(env: Env, admin: Address, user: Address) -> Result<u32, WalletError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        let mut assets: Vec<AssetInfo> = env
            .storage()
            .persistent()
            .get(&DataKey::UserAssets(user.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        if assets.len() <= MAX_ASSETS {
            return Ok(0);
        }
        let excess = assets.len() - MAX_ASSETS;
        while assets.len() > MAX_ASSETS {
            assets.pop_back();
        }
        env.storage()
            .persistent()
            .set(&DataKey::UserAssets(user), &assets);
        Ok(excess)
    }

    // ── Spend Limits ──────────────────────────────────────────────────────────

    /// Set a daily spend limit (in stroops) for a specific asset.
    ///
    /// `limit = 0` removes the limit (unlimited).
    ///
    /// **Retroactive enforcement:** if the user has already spent more than
    /// the proposed new limit in the current day window, the call is rejected
    /// with `SpendLimitExceeded`. This prevents a limit-lowering from
    /// silently granting headroom that was only valid under the old, higher
    /// limit.
    ///
    /// # Errors
    /// * [`WalletError::InvalidSpendLimit`] — negative limit.
    /// * [`WalletError::SpendLimitExceeded`] — current day's spend already
    ///   exceeds the proposed limit.
    pub fn set_spend_limit(
        env: Env,
        user: Address,
        asset_code: String,
        limit: i128,
    ) -> Result<(), WalletError> {
        user.require_auth();
        if limit < 0 {
            return Err(WalletError::InvalidSpendLimit);
        }
        // Retroactive check: reject if today's spend already exceeds the
        // new limit (unless the new limit is 0 = unlimited).
        if limit != 0 {
            let now = env.ledger().timestamp();
            let day = now / 86400;
            let key = DataKey::DailySpent(user.clone(), asset_code.clone());
            let record: SpendRecord = env
                .storage()
                .temporary()
                .get(&key)
                .unwrap_or(SpendRecord { amount: 0, day });
            let spent_today = if record.day == day { record.amount } else { 0 };
            if spent_today > limit {
                return Err(WalletError::SpendLimitExceeded);
            }
        }
        env.storage().persistent().set(
            &DataKey::SpendLimit(user.clone(), asset_code.clone()),
            &limit,
        );
        env.events().publish(
            (Symbol::new(&env, "spend_limit_set"),),
            (user, asset_code, limit),
        );
        Ok(())
    }

    /// Get the daily spend limit for a user/asset pair (0 = unlimited).
    pub fn get_spend_limit(env: Env, user: Address, asset_code: String) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::SpendLimit(user, asset_code))
            .unwrap_or(0)
    }

    /// Record a spend and reject if it would exceed the daily limit.
    ///
    /// Call this from any payment-execution path to enforce limits.
    /// Day window is a 86 400-second bucket derived from ledger timestamp.
    ///
    /// Reentrancy invariant: keep the interval from reading `DailySpent`
    /// through writing its replacement free of external contract calls. See
    /// `docs/record-spend-reentrancy.md` for the proof and change guidance.
    ///
    /// # Errors
    /// * [`WalletError::SpendLimitExceeded`]
    pub fn record_spend(
        env: Env,
        user: Address,
        asset_code: String,
        amount: i128,
    ) -> Result<(), WalletError> {
        user.require_auth();
        let limit = Self::get_spend_limit(env.clone(), user.clone(), asset_code.clone());
        if limit == 0 {
            // No limit configured → always allow
            return Ok(());
        }
        let now = env.ledger().timestamp();
        let day = now / 86400;
        let key = DataKey::DailySpent(user.clone(), asset_code.clone());
        let record: SpendRecord = env
            .storage()
            .temporary()
            .get(&key)
            .unwrap_or(SpendRecord { amount: 0, day });
        let spent_today = if record.day == day { record.amount } else { 0 };
        let new_spent = spent_today
            .checked_add(amount)
            .ok_or(WalletError::SpendOverflow)?;
        if new_spent > limit {
            return Err(WalletError::SpendLimitExceeded);
        }
        env.storage().temporary().set(
            &key,
            &SpendRecord {
                amount: new_spent,
                day,
            },
        );
        env.events().publish(
            (Symbol::new(&env, "spend_recorded"),),
            (user, asset_code, amount, new_spent, limit),
        );
        Ok(())
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn require_admin(env: &Env, caller: &Address) -> Result<(), WalletError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(WalletError::NotInitialized)?;
        if &admin != caller {
            return Err(WalletError::Unauthorized);
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, Env, String};

    fn make_code(env: &Env, n: u32) -> String {
        String::from_str(env, &std::format!("A{:02}", n))
    }

    fn fill_to_max(env: &Env, client: &GlobeWalletClient, user: &Address) {
        for i in 0..MAX_ASSETS {
            let code = make_code(env, i);
            let asset = AssetInfo { code, issuer: None };
            client.add_asset(user, &asset);
        }
    }
    use soroban_sdk::{testutils::Address as _, testutils::Ledger, Env, String};

    fn setup() -> (Env, Address, Address, GlobeWalletClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, GlobeWallet);
        let client = GlobeWalletClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, id, admin, client)
    }

    fn xlm(env: &Env) -> AssetInfo {
        AssetInfo {
            code: String::from_str(env, "XLM"),
            issuer: None,
        }
    }

    fn usdc(env: &Env) -> AssetInfo {
        AssetInfo {
            code: String::from_str(env, "USDC"),
            issuer: Some(Address::generate(env)),
        }
    }

    #[test]
    fn test_initialize() {
        let (_env, _cid, admin, client) = setup();
        assert_eq!(client.admin(), admin);
    }

    #[test]
    fn test_initialize_twice_fails() {
        let (_env, _cid, admin, client) = setup();
        assert_eq!(
            client.try_initialize(&admin),
            Err(Ok(WalletError::AlreadyInitialized))
        );
    }

    #[test]
    fn test_add_and_get_assets() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        client.add_asset(&user, &xlm(&env));
        client.add_asset(&user, &usdc(&env));
        let assets = client.get_assets(&user);
        assert_eq!(assets.len(), 2);
        assert_eq!(assets.get(0).unwrap().code, String::from_str(&env, "XLM"));
    }

    #[test]
    fn test_add_duplicate_asset_fails() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        client.add_asset(&user, &xlm(&env));
        assert_eq!(
            client.try_add_asset(&user, &xlm(&env)),
            Err(Ok(WalletError::AssetAlreadyAdded))
        );
    }

    #[test]
    fn test_remove_asset() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        client.add_asset(&user, &xlm(&env));
        client.add_asset(&user, &usdc(&env));
        client.remove_asset(&user, &String::from_str(&env, "XLM"));
        let assets = client.get_assets(&user);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets.get(0).unwrap().code, String::from_str(&env, "USDC"));
    }

    #[test]
    fn test_remove_nonexistent_asset_fails() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        assert_eq!(
            client.try_remove_asset(&user, &String::from_str(&env, "XLM")),
            Err(Ok(WalletError::AssetNotFound))
        );
    }

    #[test]
    fn test_spend_limit_set_and_get() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");
        client.set_spend_limit(&user, &code, &1_000_000_i128);
        assert_eq!(client.get_spend_limit(&user, &code), 1_000_000);
    }

    #[test]
    fn test_record_spend_within_limit() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");
        client.set_spend_limit(&user, &code, &1_000_000_i128);
        client.record_spend(&user, &code, &500_000_i128);
        client.record_spend(&user, &code, &499_999_i128);
    }

    #[test]
    fn test_record_spend_exceeds_limit_fails() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");
        client.set_spend_limit(&user, &code, &1_000_000_i128);
        client.record_spend(&user, &code, &999_999_i128);
        assert_eq!(
            client.try_record_spend(&user, &code, &2_i128),
            Err(Ok(WalletError::SpendLimitExceeded))
        );
    }

    #[test]
    fn test_record_spend_overflow_does_not_poison_later_calls() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");
        client.set_spend_limit(&user, &code, &i128::MAX);

        client.record_spend(&user, &code, &1_i128);

        assert_eq!(
            client.try_record_spend(&user, &code, &i128::MAX),
            Err(Ok(WalletError::SpendOverflow))
        );

        client.record_spend(&user, &code, &1_i128);
    }

    #[test]
    fn test_no_limit_allows_any_spend() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");
        // No set_spend_limit call → unlimited
        client.record_spend(&user, &code, &i128::MAX);
    }

    /// Retroactive enforcement: raise limit → spend near it → lower limit
    /// below already-spent amount → must be rejected.
    #[test]
    fn test_raise_spend_then_lower_limit() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");

        // 1. Set a high limit
        client.set_spend_limit(&user, &code, &1_000_000_i128);

        // 2. Spend close to the high limit
        client.record_spend(&user, &code, &900_000_i128);

        // 3. Try to lower the limit below what was already spent → must fail
        assert_eq!(
            client.try_set_spend_limit(&user, &code, &500_000_i128),
            Err(Ok(WalletError::SpendLimitExceeded))
        );

        // 4. The old limit should still be in effect
        assert_eq!(client.get_spend_limit(&user, &code), 1_000_000);

        // 5. Lowering to exactly the spent amount should succeed
        client.set_spend_limit(&user, &code, &900_000_i128);
        assert_eq!(client.get_spend_limit(&user, &code), 900_000);

        // 6. Further spending is now blocked (at the exact limit)
        assert_eq!(
            client.try_record_spend(&user, &code, &1_i128),
            Err(Ok(WalletError::SpendLimitExceeded))
        );

        // 7. Removing the limit (setting to 0 = unlimited) should always work
        client.set_spend_limit(&user, &code, &0_i128);
        assert_eq!(client.get_spend_limit(&user, &code), 0);
    }

    #[test]
    fn test_transfer_admin() {
        let (env, _cid, admin, client) = setup();
        let new_admin = Address::generate(&env);
        client.transfer_admin(&admin, &new_admin);
        assert_eq!(client.admin(), admin);
        client.propose_admin(&admin, &new_admin);
        client.accept_admin(&new_admin);
        assert_eq!(client.admin(), new_admin);
    }

    #[test]
    fn test_require_admin_not_initialized() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, GlobeWallet);
        let client = GlobeWalletClient::new(&env, &id);
        let caller = Address::generate(&env);
        assert_eq!(
            client.try_transfer_admin(&caller, &caller),
            Err(Ok(WalletError::NotInitialized))
        );
    }

    #[test]
    fn test_propose_without_accept_keeps_admin_unchanged() {
        let (env, _cid, admin, client) = setup();
        let new_admin = Address::generate(&env);
        client.propose_admin(&admin, &new_admin);
        assert_eq!(client.admin(), admin);
    }

    #[test]
    fn test_accept_by_wrong_address_fails() {
        let (env, _cid, admin, client) = setup();
        let candidate = Address::generate(&env);
        let wrong = Address::generate(&env);
        client.propose_admin(&admin, &candidate);
        assert_eq!(
            client.try_accept_admin(&wrong),
            Err(Ok(WalletError::Unauthorized))
        );
        assert_eq!(client.admin(), admin);
    }

    #[test]
    fn test_cancel_admin_transfer() {
        let (env, _cid, admin, client) = setup();
        let candidate = Address::generate(&env);
        client.propose_admin(&admin, &candidate);
        client.cancel_admin_transfer(&admin);
        assert_eq!(client.admin(), admin);
        assert_eq!(
            client.try_accept_admin(&candidate),
            Err(Ok(WalletError::NoPendingAdmin))
        );
    }

    #[test]
    fn test_propose_and_execute_upgrade() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, GlobeWallet);
        let client = GlobeWalletClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        let user = Address::generate(&env);
        client.add_asset(&user, &xlm(&env));

        let wasm_bytes = soroban_sdk::Bytes::from_slice(&env, include_bytes!("globe_wallet.wasm"));
        let wasm_hash = env.deployer().upload_contract_wasm(wasm_bytes);
        client.propose_upgrade(&admin, &wasm_hash, &1u32);

        env.ledger().set_sequence_number(2);
        client.execute_upgrade(&admin, &wasm_hash);

        let assets = client.get_assets(&user);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets.get(0).unwrap().code, String::from_str(&env, "XLM"));
    }

    #[test]
    fn test_upgrade_requires_admin_and_ready_time() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, GlobeWallet);
        let client = GlobeWalletClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        let wasm_hash = BytesN::from_array(&env, &[0u8; 32]);
        let wasm_bytes = soroban_sdk::Bytes::from_slice(&env, include_bytes!("globe_wallet.wasm"));
        let wasm_hash = env.deployer().upload_contract_wasm(wasm_bytes);
        let non_admin = Address::generate(&env);
        assert_eq!(
            client.try_propose_upgrade(&non_admin, &wasm_hash, &0u32),
            Err(Ok(WalletError::Unauthorized))
        );

        client.propose_upgrade(&admin, &wasm_hash, &5u32);
        assert_eq!(
            client.try_execute_upgrade(&admin, &wasm_hash),
            Err(Ok(WalletError::UpgradeNotReady))
        );
    }

    #[test]
    fn test_upgrade_rejects_hash_mismatch() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, GlobeWallet);
        let client = GlobeWalletClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        let wasm_hash = BytesN::from_array(&env, &[9u8; 32]);
        let other_hash = BytesN::from_array(&env, &[10u8; 32]);
        client.propose_upgrade(&admin, &wasm_hash, &0u32);
        env.ledger().set_sequence_number(1);
        assert_eq!(
            client.try_execute_upgrade(&admin, &other_hash),
            Err(Ok(WalletError::UpgradeHashMismatch))
        );
    }

    #[test]
    fn test_upgrade_propose_double_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, GlobeWallet);
        let client = GlobeWalletClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        let wasm_hash = BytesN::from_array(&env, &[11u8; 32]);
        client.propose_upgrade(&admin, &wasm_hash, &0u32);
        assert_eq!(
            client.try_propose_upgrade(&admin, &wasm_hash, &0u32),
            Err(Ok(WalletError::UpgradeAlreadyPending))
        );
    }

    #[test]
    fn test_add_asset_beyond_max_fails() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        fill_to_max(&env, &client, &user);
        let overflow = AssetInfo {
            code: String::from_str(&env, "OVERFLOW"),
            issuer: None,
        };
        assert_eq!(
            client.try_add_asset(&user, &overflow),
            Err(Ok(WalletError::MaxAssetsReached))
        );
    }

    #[test]
    fn test_remove_asset_frees_slot() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        fill_to_max(&env, &client, &user);
        let overflow = AssetInfo {
            code: String::from_str(&env, "OVERFLOW"),
            issuer: None,
        };
        assert_eq!(
            client.try_add_asset(&user, &overflow),
            Err(Ok(WalletError::MaxAssetsReached))
        );
        client.remove_asset(&user, &make_code(&env, 0));
        client.add_asset(&user, &overflow);
        assert_eq!(client.get_assets(&user).len(), MAX_ASSETS);
    }

    #[test]
    fn test_migrate_user_assets_trims_excess() {
        let (env, cid, admin, client) = setup();
        let user = Address::generate(&env);

        let mut assets: Vec<AssetInfo> = Vec::new(&env);
        for i in 0..MAX_ASSETS + 10 {
            assets.push_back(AssetInfo {
                code: make_code(&env, i),
                issuer: None,
            });
        }
        env.as_contract(&cid, || {
            env.storage()
                .persistent()
                .set(&DataKey::UserAssets(user.clone()), &assets);
        });

        let excess = client.migrate_user_assets(&admin, &user);
        assert_eq!(excess, 10);
        assert_eq!(client.get_assets(&user).len() as u32, MAX_ASSETS);
    }

    #[test]
    fn test_migrate_user_assets_noop_when_within_bounds() {
        let (env, _cid, admin, client) = setup();
        let user = Address::generate(&env);
        client.add_asset(&user, &xlm(&env));
        assert_eq!(client.migrate_user_assets(&admin, &user), 0);
        assert_eq!(client.get_assets(&user).len(), 1);
    }

    #[test]
    fn test_migrate_user_assets_requires_admin() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        let non_admin = Address::generate(&env);
        assert_eq!(
            client.try_migrate_user_assets(&non_admin, &user),
            Err(Ok(WalletError::Unauthorized))
        );
    }
}
