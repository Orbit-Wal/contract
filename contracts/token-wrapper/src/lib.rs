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
//!
//! ## Asset Disambiguation
//! Assets are uniquely identified by (code, issuer) to prevent two different assets
//! with the same code (e.g., scam USDC vs legitimate USDC) from sharing spend limits.
//! The storage key format is: `code|issuer` (or `code|native` for XLM).

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Env, String, Symbol, Vec,
    TryFromVal,
};

// ── Storage Keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    /// Whitelisted assets for a user wallet
    UserAssets(Address),
    /// Spend limit: (user, asset_code, issuer_key) → limit in stroops
    /// issuer_key = "native" for XLM, or the issuer address as a string
    SpendLimit(Address, String, String),
    /// Daily spent: (user, asset_code, issuer_key) → SpendRecord
    DailySpent(Address, String, String),
}

#[contracttype]
pub enum LegacyDataKey {
    SpendLimit(Address, String),
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
    /// Migration error: legacy key not found or already migrated
    MigrationError = 9,
    AssetLimitExceeded = 10,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct GlobeWallet;

#[contractimpl]
impl GlobeWallet {
    // ── Asset Key Helpers ─────────────────────────────────────────────────────

    /// Generate a unique key string for an asset: "code|issuer" or "code|native"
    fn asset_key(env: &Env, asset: &AssetInfo) -> String {
        let issuer_part = match &asset.issuer {
            Some(addr) => addr.to_string(),
            None => String::from_str(env, "native"),
        };
        let mut buf = [0u8; 128];
        let code_len = asset.code.len() as usize;
        asset.code.copy_into_slice(&mut buf[0..code_len]);
        buf[code_len] = b'|';
        let issuer_len = issuer_part.len() as usize;
        issuer_part.copy_into_slice(&mut buf[code_len + 1 .. code_len + 1 + issuer_len]);
        let total_len = code_len + 1 + issuer_len;
        let slice = core::str::from_utf8(&buf[0..total_len]).unwrap();
        String::from_str(env, slice)
    }

    /// Generate a unique key string from code + issuer string (for migration)
    fn asset_key_from_parts(env: &Env, code: &String, issuer_str: &String) -> String {
        let mut buf = [0u8; 128];
        let code_len = code.len() as usize;
        code.copy_into_slice(&mut buf[0..code_len]);
        buf[code_len] = b'|';
        let issuer_len = issuer_str.len() as usize;
        issuer_str.copy_into_slice(&mut buf[code_len + 1 .. code_len + 1 + issuer_len]);
        let total_len = code_len + 1 + issuer_len;
        let slice = core::str::from_utf8(&buf[0..total_len]).unwrap();
        String::from_str(env, slice)
    }

    // ── Initialization ────────────────────────────────────────────────────────

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

    /// Transfer admin to a new address.
    ///
    /// # Errors
    /// * [`WalletError::NotInitialized`] / [`WalletError::Unauthorized`]
    pub fn transfer_admin(env: Env, current: Address, new_admin: Address) -> Result<(), WalletError> {
        current.require_auth();
        Self::require_admin(&env, &current)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.events().publish(
            (Symbol::new(&env, "admin_transferred"),),
            (current, new_admin),
        );
        Ok(())
    }

    // ── Asset Registry ────────────────────────────────────────────────────────

    /// Maximum assets a single user can whitelist.
    pub const MAX_ASSETS: u32 = 50;

    /// Add an asset to a user's wallet registry.
    ///
    /// Only the user themselves (via `require_auth`) can add assets.
    ///
    /// # Errors
    /// * [`WalletError::AssetAlreadyAdded`] — asset already registered.
    /// * [`WalletError::AssetLimitExceeded`] — user would exceed [`MAX_ASSETS`].
    pub fn add_asset(env: Env, user: Address, asset: AssetInfo) -> Result<(), WalletError> {
        user.require_auth();
        let mut assets: Vec<AssetInfo> = env
            .storage()
            .persistent()
            .get(&DataKey::UserAssets(user.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        if assets.len() >= Self::MAX_ASSETS as u32 {
            return Err(WalletError::AssetLimitExceeded);
        }
        for i in 0..assets.len() {
            let existing = assets.get(i).unwrap();
            if existing.code == asset.code && existing.issuer == asset.issuer {
                return Err(WalletError::AssetAlreadyAdded);
            }
        }
        assets.push_back(asset.clone());
        env.storage()
            .persistent()
            .set(&DataKey::UserAssets(user.clone()), &assets);
        env.events().publish(
            (Symbol::new(&env, "asset_added"),),
            (user, asset.code, asset.issuer),
        );
        Ok(())
    }

    /// Remove an asset from a user's wallet registry.
    ///
    /// # Errors
    /// * [`WalletError::AssetNotFound`] — asset not registered.
    pub fn remove_asset(env: Env, user: Address, asset: AssetInfo) -> Result<(), WalletError> {  
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
        if a.code == asset.code && a.issuer == asset.issuer {  
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
    env.events().publish(  
        (Symbol::new(&env, "asset_removed"),),  
        (user, asset.code, asset.issuer),  
    );  
    Ok(())  
}
    /// Return all assets registered by a user.
    pub fn get_assets(env: Env, user: Address) -> Vec<AssetInfo> {
        env.storage()
            .persistent()
            .get(&DataKey::UserAssets(user))
            .unwrap_or_else(|| Vec::new(&env))
    }

    // ── Spend Limits (Disambiguated by Issuer) ──────────────────────────────

    /// Set a daily spend limit (in stroops) for a specific asset.
    ///
    /// `limit = 0` removes the limit (unlimited).
    /// Assets are uniquely identified by (code, issuer) to prevent collisions.
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
        asset: AssetInfo,
        limit: i128,
    ) -> Result<(), WalletError> {
        user.require_auth();
        if limit < 0 {
            return Err(WalletError::InvalidSpendLimit);
        }
        let asset_key = Self::asset_key(&env, &asset);
        // Retroactive check: reject if today's spend already exceeds the
        // new limit (unless the new limit is 0 = unlimited).
        if limit != 0 {
            let now = env.ledger().timestamp();
            let day = now / 86400;
            let key = DataKey::DailySpent(user.clone(), asset.code.clone(), asset_key.clone());
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
        env.storage()
            .persistent()
            .set(&DataKey::SpendLimit(user.clone(), asset.code.clone(), asset_key.clone()), &limit);
        env.events().publish(
            (Symbol::new(&env, "spend_limit_set"),),
            (user, asset.code, asset_key, limit),
        );
        Ok(())
    }

    /// Get the daily spend limit for a user/asset pair (0 = unlimited).
    pub fn get_spend_limit(env: Env, user: Address, asset: AssetInfo) -> i128 {
        let asset_key = Self::asset_key(&env, &asset);
        env.storage()
            .persistent()
            .get(&DataKey::SpendLimit(user, asset.code, asset_key))
            .unwrap_or(0)
    }

    /// Record a spend and reject if it would exceed the daily limit.
    ///
    /// Call this from any payment-execution path to enforce limits.
    /// Day window is a 86 400-second bucket derived from ledger timestamp.
    ///
    /// # Errors
    /// * [`WalletError::SpendLimitExceeded`]
    pub fn record_spend(
        env: Env,
        user: Address,
        asset: AssetInfo,
        amount: i128,
    ) -> Result<(), WalletError> {
        user.require_auth();
        let asset_key = Self::asset_key(&env, &asset);
        let limit = Self::get_spend_limit(env.clone(), user.clone(), asset.clone());
        if limit == 0 {
            // No limit configured → always allow
            return Ok(());
        }
        let now = env.ledger().timestamp();
        let day = now / 86400;
        let key = DataKey::DailySpent(user.clone(), asset.code.clone(), asset_key.clone());
        let record: SpendRecord = env
            .storage()
            .temporary()
            .get(&key)
            .unwrap_or(SpendRecord { amount: 0, day });
        let spent_today = if record.day == day { record.amount } else { 0 };
        let new_spent = spent_today.checked_add(amount).unwrap_or(i128::MAX);
        if new_spent > limit {
            return Err(WalletError::SpendLimitExceeded);
        }
        env.storage()
            .temporary()
            .set(&key, &SpendRecord { amount: new_spent, day });
        env.events().publish(
            (Symbol::new(&env, "spend_recorded"),),
            (user, asset.code, asset_key, amount, new_spent, limit),
        );
        Ok(())
    }

    // ── Asset List Migration ───────────────────────────────────────────────────

    /// Admin-only: trim a user's asset list to `MAX_ASSETS` if it exceeds the bound.
    pub fn migrate_user_assets(env: Env, admin: Address, user: Address) -> Result<u32, WalletError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        let assets: Vec<AssetInfo> = env
            .storage()
            .persistent()
            .get(&DataKey::UserAssets(user.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        let len = assets.len();
        if len <= Self::MAX_ASSETS {
            return Ok(0);
        }
        let mut trimmed: Vec<AssetInfo> = Vec::new(&env);
        for i in 0..Self::MAX_ASSETS {
            trimmed.push_back(assets.get(i).unwrap());
        }
        env.storage()
            .persistent()
            .set(&DataKey::UserAssets(user.clone()), &trimmed);
        let removed = len - Self::MAX_ASSETS;
        env.events().publish(
            (Symbol::new(&env, "user_assets_migrated"),),
            (user, removed),
        );
        Ok(removed)
    }

    // ── Spend Limit Migration Path ─────────────────────────────────────────────

    /// Migrate a single user's legacy spend limits from old (code-only) to new (code|issuer) format.
    ///
    /// This must be called by the admin for each user that had limits set under the old format.
    /// The correct issuer must be provided to resolve the ambiguity.
    ///
    /// # Parameters
    /// - `admin`: Must be the contract admin (authorizes the call)
    /// - `user`: The user whose limits are being migrated
    /// - `legacy_asset_code`: The asset code that was used under the old format
    /// - `correct_issuer`: The issuer address that resolves the ambiguity (None for XLM)
    /// - `allow_overwrite`: If true, replaces any existing new-format entry
    ///
    /// # Returns
    /// - `bool`: true if a limit was migrated, false if no limit existed
    ///
    /// # Errors
    /// * [`WalletError::MigrationError`] — if migration fails due to conflicting entries
    pub fn migrate_user_spend_limits(
        env: Env,
        admin: Address,
        user: Address,
        legacy_asset_code: String,
        correct_issuer: Option<Address>,
        allow_overwrite: bool,
    ) -> Result<bool, WalletError> {
        Self::require_admin(&env, &admin)?;

        let asset = AssetInfo {
            code: legacy_asset_code.clone(),
            issuer: correct_issuer,
        };
        let new_asset_key = Self::asset_key(&env, &asset);
        
        // Read old limit (code-only key)
        let old_key = LegacyDataKey::SpendLimit(user.clone(), legacy_asset_code.clone());
        let old_limit: i128 = env
            .storage()
            .persistent()
            .get(&old_key)
            .unwrap_or(0);

        if old_limit == 0 {
            return Ok(false); // No limit to migrate
        }

        // Check if new key already exists
        let new_key = DataKey::SpendLimit(
            user.clone(), 
            asset.code.clone(), 
            new_asset_key.clone()
        );
        let existing: i128 = env
            .storage()
            .persistent()
            .get(&new_key)
            .unwrap_or(0);

        if existing != 0 && !allow_overwrite {
            return Err(WalletError::MigrationError);
        }

        // Write new limit
        env.storage()
            .persistent()
            .set(&new_key, &old_limit);

        // Optionally remove old key
        env.storage().persistent().remove(&old_key);

        // Also migrate daily spent records
        let old_daily_key = LegacyDataKey::DailySpent(user.clone(), legacy_asset_code.clone());
        let daily_record: Option<SpendRecord> = env.storage().temporary().get(&old_daily_key);
        if let Some(record) = daily_record {
            let new_daily_key = DataKey::DailySpent(
                user.clone(),
                asset.code.clone(),
                new_asset_key.clone(),
            );
            env.storage()
                .temporary()
                .set(&new_daily_key, &record);
            env.storage().temporary().remove(&old_daily_key);
        }

        env.events().publish(
            (Symbol::new(&env, "spend_limit_migrated"),),
            (user, legacy_asset_code, new_asset_key, old_limit),
        );

        Ok(true)
    }

    /// Batch migrate multiple users' legacy spend limits.
    ///
    /// More gas-efficient than calling `migrate_user_spend_limits` for each user individually.
    /// The admin provides a list of users and the same asset code/issuer for all.
    ///
    /// # Returns
    /// - `u64`: Number of users successfully migrated
    pub fn batch_migrate_spend_limits(
        env: Env,
        admin: Address,
        users: Vec<Address>,
        legacy_asset_code: String,
        correct_issuer: Option<Address>,
        allow_overwrite: bool,
    ) -> Result<u64, WalletError> {
        Self::require_admin(&env, &admin)?;
        let mut migrated_count = 0u64;

        for i in 0..users.len() {
            let user = users.get(i).unwrap();
            match Self::migrate_user_spend_limits(
                env.clone(),
                admin.clone(),
                user,
                legacy_asset_code.clone(),
                correct_issuer.clone(),
                allow_overwrite,
            ) {
                Ok(true) => migrated_count += 1,
                Ok(false) => {} // No limit to migrate, skip
                Err(e) => return Err(e),
            }
        }

        Ok(migrated_count)
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
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env, String};

    fn setup() -> (Env, Address, GlobeWalletClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, GlobeWallet);
        let client = GlobeWalletClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    fn xlm(env: &Env) -> AssetInfo {
        AssetInfo { 
            code: String::from_str(env, "XLM"), 
            issuer: None 
        }
    }

    fn usdc(env: &Env, issuer: Option<Address>) -> AssetInfo {
        AssetInfo {
            code: String::from_str(env, "USDC"),
            issuer,
        }
    }

    #[test]
    fn test_initialize() {
        let (_env, admin, client) = setup();
        assert_eq!(client.admin(), admin);
    }

    #[test]
    fn test_initialize_twice_fails() {
        let (_env, admin, client) = setup();
        assert_eq!(
            client.try_initialize(&admin),
            Err(Ok(WalletError::AlreadyInitialized))
        );
    }

    #[test]
    fn test_add_and_get_assets() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        let usdc_issuer = Address::generate(&env);
        
        client.add_asset(&user, &xlm(&env));
        client.add_asset(&user, &usdc(&env, Some(usdc_issuer.clone())));
        
        let assets = client.get_assets(&user);
        assert_eq!(assets.len(), 2);
        assert_eq!(assets.get(0).unwrap().code, String::from_str(&env, "XLM"));
        assert_eq!(assets.get(1).unwrap().code, String::from_str(&env, "USDC"));
    }

    #[test]
    fn test_add_duplicate_asset_fails() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        let issuer = Address::generate(&env);
        
        client.add_asset(&user, &usdc(&env, Some(issuer.clone())));
        assert_eq!(
            client.try_add_asset(&user, &usdc(&env, Some(issuer))),
            Err(Ok(WalletError::AssetAlreadyAdded))
        );
    }

    #[test]
    fn test_same_code_different_issuer_allowed() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        let issuer1 = Address::generate(&env);
        let issuer2 = Address::generate(&env);
        
        client.add_asset(&user, &usdc(&env, Some(issuer1)));
        client.add_asset(&user, &usdc(&env, Some(issuer2)));
        
        let assets = client.get_assets(&user);
        assert_eq!(assets.len(), 2);
    }

    #[test]
    fn test_spend_limit_set_and_get() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        let issuer = Address::generate(&env);
        let asset = usdc(&env, Some(issuer));
        
        client.set_spend_limit(&user, &asset, &1_000_000_i128);
        assert_eq!(client.get_spend_limit(&user, &asset), 1_000_000);
    }

    #[test]
    fn test_record_spend_within_limit() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        let issuer = Address::generate(&env);
        let asset = usdc(&env, Some(issuer));
        
        client.set_spend_limit(&user, &asset, &1_000_000_i128);
        client.record_spend(&user, &asset, &500_000_i128);
        client.record_spend(&user, &asset, &499_999_i128);
    }

    #[test]
    fn test_record_spend_exceeds_limit_fails() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        let issuer = Address::generate(&env);
        let asset = usdc(&env, Some(issuer));
        
        client.set_spend_limit(&user, &asset, &1_000_000_i128);
        client.record_spend(&user, &asset, &999_999_i128);
        assert_eq!(
            client.try_record_spend(&user, &asset, &2_i128),
            Err(Ok(WalletError::SpendLimitExceeded))
        );
    }

    #[test]
    fn test_disambiguated_spend_limits() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);

        // Two assets with same code but different issuers
        let issuer1 = Address::generate(&env);
        let issuer2 = Address::generate(&env);

        let asset1 = usdc(&env, Some(issuer1));
        let asset2 = usdc(&env, Some(issuer2));

        // Add both assets to wallet
        client.add_asset(&user, &asset1);
        client.add_asset(&user, &asset2);

        // Set different spend limits
        client.set_spend_limit(&user, &asset1, &1_000_i128);
        client.set_spend_limit(&user, &asset2, &2_000_i128);

        // Verify each has its own limit
        assert_eq!(client.get_spend_limit(&user, &asset1), 1_000);
        assert_eq!(client.get_spend_limit(&user, &asset2), 2_000);

        // Spend from asset1 up to its limit
        client.record_spend(&user, &asset1, &999_i128);
        assert!(client.try_record_spend(&user, &asset1, &2_i128).is_err());

        // Asset2 should still have full 2,000 limit available
        client.record_spend(&user, &asset2, &1_999_i128);
        assert!(client.try_record_spend(&user, &asset2, &2_i128).is_err());
    }

    #[test]
    fn test_no_limit_allows_any_spend() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        let issuer = Address::generate(&env);
        let asset = usdc(&env, Some(issuer));
        
        // No set_spend_limit call → unlimited
        client.record_spend(&user, &asset, &i128::MAX);
    }

    /// Retroactive enforcement: raise limit → spend near it → lower limit
    /// below already-spent amount → must be rejected.
    #[test]
    fn test_raise_spend_then_lower_limit() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        let issuer = Address::generate(&env);
        let asset = usdc(&env, Some(issuer));

        // 1. Set a high limit
        client.set_spend_limit(&user, &asset, &1_000_000_i128);

        // 2. Spend close to the high limit
        client.record_spend(&user, &asset, &900_000_i128);

        // 3. Try to lower the limit below what was already spent → must fail
        assert_eq!(
            client.try_set_spend_limit(&user, &asset, &500_000_i128),
            Err(Ok(WalletError::SpendLimitExceeded))
        );

        // 4. The old limit should still be in effect
        assert_eq!(client.get_spend_limit(&user, &asset), 1_000_000);

        // 5. Lowering to exactly the spent amount should succeed
        client.set_spend_limit(&user, &asset, &900_000_i128);
        assert_eq!(client.get_spend_limit(&user, &asset), 900_000);

        // 6. Further spending is now blocked (at the exact limit)
        assert_eq!(
            client.try_record_spend(&user, &asset, &1_i128),
            Err(Ok(WalletError::SpendLimitExceeded))
        );

        // 7. Removing the limit (setting to 0 = unlimited) should always work
        client.set_spend_limit(&user, &asset, &0_i128);
        assert_eq!(client.get_spend_limit(&user, &asset), 0);
    }

    #[test]
    fn test_migration_from_legacy_key() {
        let (env, admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "USDC");
        let issuer = Address::generate(&env);

        // Simulate legacy state: set spend limit using old API (code-only)
        // We write directly to storage to simulate old format
        let old_key = LegacyDataKey::SpendLimit(user.clone(), code.clone());
        let old_daily_key = LegacyDataKey::DailySpent(user.clone(), code.clone());
        env.as_contract(&client.address, || {
            env.storage().persistent().set(&old_key, &1_000_i128);
            env.storage().temporary().set(&old_daily_key, &SpendRecord { amount: 500, day: 12345 });
        });

        // Now migrate
        let migrated = client.migrate_user_spend_limits(
            &admin,
            &user,
            &code,
            &Some(issuer.clone()),
            &true, // allow_overwrite
        );
        assert!(migrated);

        // Verify new key has the limit
        let asset = AssetInfo { code: code.clone(), issuer: Some(issuer) };
        assert_eq!(client.get_spend_limit(&user, &asset), 1_000);

        // Old key should be gone
        let old_value: i128 = env.as_contract(&client.address, || {
            env.storage().persistent().get(&old_key).unwrap_or(0)
        });
        assert_eq!(old_value, 0);

        // Daily spent should be migrated
        let new_asset_key = GlobeWallet::asset_key(&env, &asset);
        let new_daily_key = DataKey::DailySpent(user.clone(), code, new_asset_key);
        let record: SpendRecord = env.as_contract(&client.address, || {
            env.storage().temporary().get(&new_daily_key).unwrap()
        });
        assert_eq!(record.amount, 500);
        assert_eq!(record.day, 12345);
    }

    #[test]
    fn test_batch_migration() {
        let (env, admin, client) = setup();
        let code = String::from_str(&env, "USDC");
        let issuer = Address::generate(&env);

        // Create 3 users with legacy limits
        let mut users = Vec::new(&env);
        for _ in 0..3 {
            let user = Address::generate(&env);
            users.push_back(user.clone());
            let old_key = LegacyDataKey::SpendLimit(user, code.clone());
            env.as_contract(&client.address, || {
                env.storage().persistent().set(&old_key, &1_000_i128);
            });
        }

        // Batch migrate
        let migrated = client.batch_migrate_spend_limits(
            &admin,
            &users,
            &code,
            &Some(issuer.clone()),
            &true,
        );
        assert_eq!(migrated, 3);

        // Verify all users have migrated limits
        for i in 0..users.len() {
            let user = users.get(i).unwrap();
            let asset = AssetInfo { code: code.clone(), issuer: Some(issuer.clone()) };
            assert_eq!(client.get_spend_limit(&user, &asset), 1_000);
        }
    }

    #[test]
    fn test_migration_no_overwrite() {
        let (env, admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "USDC");
        let issuer = Address::generate(&env);

        // Set legacy limit
        let old_key = LegacyDataKey::SpendLimit(user.clone(), code.clone());
        env.as_contract(&client.address, || {
            env.storage().persistent().set(&old_key, &1_000_i128);
        });

        // Set new limit already
        let asset = AssetInfo { code: code.clone(), issuer: Some(issuer.clone()) };
        client.set_spend_limit(&user, &asset, &2_000_i128);

        // Try migration without overwrite
        let result = client.try_migrate_user_spend_limits(
            &admin,
            &user,
            &code,
            &Some(issuer.clone()),
            &false, // allow_overwrite = false
        );
        assert_eq!(result, Err(Ok(WalletError::MigrationError)));

        // Limit should still be 2_000
        assert_eq!(client.get_spend_limit(&user, &asset), 2_000);
    }

    #[test]
    fn test_max_assets_limit() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        for i in 0..GlobeWallet::MAX_ASSETS {
            let code = String::from_str(&env, &format!("ASSET{}", i));
            let asset = AssetInfo { code, issuer: None };
            client.add_asset(&user, &asset);
        }
        let extra = AssetInfo {
            code: String::from_str(&env, "EXTRA"),
            issuer: None,
        };
        assert_eq!(
            client.try_add_asset(&user, &extra),
            Err(Ok(WalletError::AssetLimitExceeded))
        );
    }

    #[test]
    fn test_migrate_user_assets_trims_excess() {
        let (env, admin, client) = setup();
        let user = Address::generate(&env);
        for i in 0..GlobeWallet::MAX_ASSETS + 5 {
            let code = String::from_str(&env, &format!("ASSET{}", i));
            let asset = AssetInfo { code, issuer: None };
            client.add_asset(&user, &asset);
        }
        let removed = client.migrate_user_assets(&admin, &user);
        assert_eq!(removed, 5);
        let assets = client.get_assets(&user);
        assert_eq!(assets.len(), GlobeWallet::MAX_ASSETS as u32);
    }

    #[test]
    fn test_migrate_user_assets_requires_admin() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        let non_admin = Address::generate(&env);
        assert_eq!(
            client.try_migrate_user_assets(&non_admin, &user),
            Err(Ok(WalletError::Unauthorized))
        );
    }

    #[test]
    fn test_transfer_admin() {
        let (env, admin, client) = setup();
        let new_admin = Address::generate(&env);
        client.transfer_admin(&admin, &new_admin);
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
}
