#![no_std]

//! # globe-wallet
//!
//! Core GlobeWallet smart contract on Stellar / Soroban.
//!
//! ## Features
//! - Multi-asset wallet registry: track whitelisted assets per user
//! - Admin-gated asset management
//! - Spend limits: per-asset daily caps to limit loss on key compromise
//! - Guardian-based social recovery of the admin role (see `RECOVERY.md`)
//! - Event emission for all state-changing operations
//!
//! ## Spend Limits
//! Each user can set a `spend_limit` (in stroops/smallest unit) per asset.
//! Payments that would exceed the daily limit are rejected with `SpendLimitExceeded`.
//! Limits reset automatically on ledger-time day boundary.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, BytesN, Env, String, Symbol, Vec,
};

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
    /// Ordered set of guardian addresses authorized to co-sign admin recovery.
    Guardians,
    /// M-of-N approvals required, and the ledger-count timelock delay
    /// between quorum being reached and a recovery becoming executable.
    RecoveryConfig,
    /// The single in-flight recovery proposal, if any.
    RecoveryProposal,
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

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RecoveryConfig {
    /// Number of distinct guardian approvals required to reach quorum.
    pub threshold: u32,
    /// Ledger-count delay between reaching quorum and `execute_recovery`
    /// becoming callable. Gives the legitimate admin a window to notice
    /// and cancel a malicious or mistaken recovery.
    pub delay_in_ledgers: u32,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RecoveryProposal {
    pub new_admin: Address,
    pub approvals: Vec<Address>,
    /// Set once quorum is first reached; cleared again if approvals drop
    /// back below threshold. `execute_recovery` requires `ledger seq >= ready_at`.
    pub ready_at: Option<u32>,
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
    UpgradeAlreadyPending = 11,
    UpgradeNotPending = 12,
    UpgradeNotReady = 13,
    UpgradeHashMismatch = 14,
    UpgradeFailed = 15,
    /// Guardian address already registered.
    GuardianAlreadyAdded = 16,
    /// Address is not a registered guardian.
    GuardianNotFound = 17,
    /// Recovery threshold must be `1 < threshold <= guardians.len()`.
    InvalidRecoveryThreshold = 18,
    /// `add_guardian`/`set_recovery_config` would leave threshold >
    /// guardian count, or guardians.len() below the required minimum.
    NotEnoughGuardians = 19,
    /// No recovery threshold/delay configured yet — call `set_recovery_config` first.
    RecoveryNotConfigured = 20,
    /// A recovery proposal is already in flight; cancel or execute it first.
    RecoveryAlreadyPending = 21,
    /// No recovery proposal is currently pending.
    NoPendingRecovery = 22,
    /// Guardian has already approved the pending proposal.
    AlreadyApproved = 23,
    /// Guardian has not approved the pending proposal (nothing to revoke).
    ApprovalNotFound = 24,
    /// Quorum reached but the timelock delay has not yet elapsed.
    RecoveryNotReady = 25,
    /// Approvals dropped below threshold since quorum was reached; timelock reset.
    RecoveryNotQuorate = 26,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct GlobeWallet;

#[contractimpl]
impl GlobeWallet {
    /// Minimum number of guardians a wallet must have before a recovery
    /// threshold can be configured. Below this, "M-of-N social recovery"
    /// degenerates into "one or two people can unilaterally seize the wallet".
    const MIN_GUARDIANS_FOR_RECOVERY: u32 = 3;

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
        env.storage()
            .instance()
            .remove(&DataKey::PendingAdmin(admin.clone()));
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
        env.events()
            .publish((Symbol::new(&env, "admin_transfer_cancelled"),), current);
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
            (proposer, wasm_hash, ready_at),
        );
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
        env.deployer().update_current_contract_wasm(&wasm_hash);
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        env.events().publish(
            (Symbol::new(&env, "upgrade_executed"),),
            (executor, wasm_hash),
        );
        Ok(())
    }

    // ── Guardian-Based Admin Recovery ────────────────────────────────────────
    //
    // See `docs/design/recovery/RECOVERY.md` in the mobile repo for the full
    // design rationale, threat model, and interaction spec this section
    // implements. Summary of the invariants enforced here:
    //
    // 1. `execute_recovery` never calls `require_admin`/`current.require_auth()`
    //    — by construction the whole point is that the admin key is gone.
    //    It is instead gated purely by guardian quorum + timelock.
    // 2. The *current* admin (if still able to sign) can unilaterally cancel
    //    a pending recovery at any time via `cancel_recovery`. This is the
    //    primary defense against a malicious guardian majority: they can only
    //    ever succeed if the admin key is truly unavailable to object during
    //    the entire delay window.
    // 3. The timelock clock starts only when quorum is first reached, not at
    //    initiation — a single (or minority) guardian cannot start a live
    //    countdown alone.
    // 4. Dropping below threshold after quorum (via `revoke_recovery_approval`)
    //    clears `ready_at` and re-arms the timelock on the next requorum,
    //    so a guardian having second thoughts can't be steam-rolled by a
    //    stale countdown started earlier.

    /// Register a new guardian. Admin-authorized.
    pub fn add_guardian(env: Env, admin: Address, guardian: Address) -> Result<(), WalletError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        let mut guardians = Self::guardians(env.clone());
        for i in 0..guardians.len() {
            if guardians.get(i).unwrap() == guardian {
                return Err(WalletError::GuardianAlreadyAdded);
            }
        }
        guardians.push_back(guardian.clone());
        env.storage().instance().set(&DataKey::Guardians, &guardians);
        env.events()
            .publish((Symbol::new(&env, "guardian_added"),), guardian);
        Ok(())
    }

    /// Remove a guardian. Admin-authorized.
    ///
    /// # Errors
    /// * [`WalletError::NotEnoughGuardians`] — would drop the guardian count
    ///   below the configured recovery threshold.
    pub fn remove_guardian(env: Env, admin: Address, guardian: Address) -> Result<(), WalletError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        let guardians = Self::guardians(env.clone());
        let mut new_guardians: Vec<Address> = Vec::new(&env);
        let mut found = false;
        for i in 0..guardians.len() {
            let g = guardians.get(i).unwrap();
            if g == guardian {
                found = true;
            } else {
                new_guardians.push_back(g);
            }
        }
        if !found {
            return Err(WalletError::GuardianNotFound);
        }
        if let Some(config) = Self::recovery_config(env.clone()) {
            if new_guardians.len() < config.threshold {
                return Err(WalletError::NotEnoughGuardians);
            }
        }
        env.storage()
            .instance()
            .set(&DataKey::Guardians, &new_guardians);
        env.events()
            .publish((Symbol::new(&env, "guardian_removed"),), guardian);
        Ok(())
    }

    /// Return the current guardian set.
    pub fn guardians(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::Guardians)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Configure (or reconfigure) the M-of-N recovery threshold and the
    /// post-quorum timelock delay. Admin-authorized.
    ///
    /// # Errors
    /// * [`WalletError::InvalidRecoveryThreshold`] — `threshold <= 1` (a
    ///   single guardian must never be able to unilaterally recover admin).
    /// * [`WalletError::NotEnoughGuardians`] — fewer than
    ///   [`Self::MIN_GUARDIANS_FOR_RECOVERY`] guardians registered, or
    ///   `threshold > guardians.len()`.
    pub fn set_recovery_config(
        env: Env,
        admin: Address,
        threshold: u32,
        delay_in_ledgers: u32,
    ) -> Result<(), WalletError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        let guardians = Self::guardians(env.clone());
        if threshold <= 1 {
            return Err(WalletError::InvalidRecoveryThreshold);
        }
        if guardians.len() < Self::MIN_GUARDIANS_FOR_RECOVERY || threshold > guardians.len() {
            return Err(WalletError::NotEnoughGuardians);
        }
        let config = RecoveryConfig {
            threshold,
            delay_in_ledgers,
        };
        env.storage()
            .instance()
            .set(&DataKey::RecoveryConfig, &config);
        env.events().publish(
            (Symbol::new(&env, "recovery_config_set"),),
            (threshold, delay_in_ledgers),
        );
        Ok(())
    }

    /// Return the current recovery configuration, if any.
    pub fn recovery_config(env: Env) -> Option<RecoveryConfig> {
        env.storage().instance().get(&DataKey::RecoveryConfig)
    }

    /// A guardian initiates a recovery to `new_admin`. Counts as that
    /// guardian's own approval.
    ///
    /// # Errors
    /// * [`WalletError::RecoveryNotConfigured`]
    /// * [`WalletError::Unauthorized`] — caller is not a registered guardian.
    /// * [`WalletError::RecoveryAlreadyPending`]
    pub fn initiate_recovery(
        env: Env,
        guardian: Address,
        new_admin: Address,
    ) -> Result<(), WalletError> {
        guardian.require_auth();
        Self::require_guardian(&env, &guardian)?;
        Self::require_recovery_configured(&env)?;
        if env.storage().instance().has(&DataKey::RecoveryProposal) {
            return Err(WalletError::RecoveryAlreadyPending);
        }
        let mut approvals: Vec<Address> = Vec::new(&env);
        approvals.push_back(guardian.clone());
        let proposal = RecoveryProposal {
            new_admin: new_admin.clone(),
            approvals,
            ready_at: None,
        };
        env.storage()
            .instance()
            .set(&DataKey::RecoveryProposal, &proposal);
        env.events().publish(
            (Symbol::new(&env, "recovery_initiated"),),
            (guardian, new_admin),
        );
        Ok(())
    }

    /// A guardian approves the pending recovery proposal.
    ///
    /// Once approvals reach the configured threshold, the timelock is
    /// armed: `ready_at = current_ledger_sequence + delay_in_ledgers`.
    pub fn approve_recovery(env: Env, guardian: Address) -> Result<(), WalletError> {
        guardian.require_auth();
        Self::require_guardian(&env, &guardian)?;
        let config = Self::require_recovery_configured(&env)?;
        let mut proposal = Self::require_pending_recovery(&env)?;
        for i in 0..proposal.approvals.len() {
            if proposal.approvals.get(i).unwrap() == guardian {
                return Err(WalletError::AlreadyApproved);
            }
        }
        proposal.approvals.push_back(guardian.clone());
        if proposal.approvals.len() >= config.threshold && proposal.ready_at.is_none() {
            let ready_at = env
                .ledger()
                .sequence()
                .saturating_add(config.delay_in_ledgers);
            proposal.ready_at = Some(ready_at);
            env.events().publish(
                (Symbol::new(&env, "recovery_quorum_reached"),),
                (proposal.new_admin.clone(), ready_at),
            );
        }
        env.storage()
            .instance()
            .set(&DataKey::RecoveryProposal, &proposal);
        env.events()
            .publish((Symbol::new(&env, "recovery_approved"),), guardian);
        Ok(())
    }

    /// A guardian revokes their own approval of the pending recovery.
    ///
    /// If approvals drop below threshold, the timelock is disarmed
    /// (`ready_at` cleared) — quorum must be reached again from scratch,
    /// restarting the delay window.
    pub fn revoke_recovery_approval(env: Env, guardian: Address) -> Result<(), WalletError> {
        guardian.require_auth();
        let config = Self::require_recovery_configured(&env)?;
        let mut proposal = Self::require_pending_recovery(&env)?;
        let mut new_approvals: Vec<Address> = Vec::new(&env);
        let mut found = false;
        for i in 0..proposal.approvals.len() {
            let a = proposal.approvals.get(i).unwrap();
            if a == guardian {
                found = true;
            } else {
                new_approvals.push_back(a);
            }
        }
        if !found {
            return Err(WalletError::ApprovalNotFound);
        }
        proposal.approvals = new_approvals;
        if proposal.approvals.len() < config.threshold {
            proposal.ready_at = None;
        }
        env.storage()
            .instance()
            .set(&DataKey::RecoveryProposal, &proposal);
        env.events()
            .publish((Symbol::new(&env, "recovery_approval_revoked"),), guardian);
        Ok(())
    }

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
    /// guards against any future code path that forgets to).
    ///
    /// Any in-flight *normal* `propose_admin`/`accept_admin` transfer is
    /// cancelled as part of executing a recovery, so the two flows can't race.
    pub fn execute_recovery(env: Env) -> Result<(), WalletError> {
        let config = Self::require_recovery_configured(&env)?;
        let proposal = Self::require_pending_recovery(&env)?;
        if proposal.approvals.len() < config.threshold {
            return Err(WalletError::RecoveryNotQuorate);
        }
        let ready_at = proposal.ready_at.ok_or(WalletError::RecoveryNotQuorate)?;
        if env.ledger().sequence() < ready_at {
            return Err(WalletError::RecoveryNotReady);
        }
        let old_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(WalletError::NotInitialized)?;
        env.storage()
            .instance()
            .remove(&DataKey::PendingAdmin(old_admin.clone()));
        env.storage()
            .instance()
            .set(&DataKey::Admin, &proposal.new_admin);
        env.storage().instance().remove(&DataKey::RecoveryProposal);
        // Same event name/shape as a normal transfer: downstream indexers
        // and the mobile app don't need to special-case recovery-driven
        // admin changes.
        env.events().publish(
            (Symbol::new(&env, "admin_transferred"),),
            (old_admin, proposal.new_admin),
        );
        Ok(())
    }

    /// The current admin cancels a pending recovery. This is the primary
    /// abuse/griefing defense: as long as the legitimate admin key is still
    /// usable, a colluding guardian majority can be stopped at any point
    /// before `execute_recovery` succeeds — including after quorum, during
    /// the timelock window.
    pub fn cancel_recovery(env: Env, admin: Address) -> Result<(), WalletError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        Self::require_pending_recovery(&env)?;
        env.storage().instance().remove(&DataKey::RecoveryProposal);
        env.events()
            .publish((Symbol::new(&env, "recovery_cancelled"),), admin);
        Ok(())
    }

    /// Return the pending recovery proposal, if any.
    pub fn recovery_proposal(env: Env) -> Option<RecoveryProposal> {
        env.storage().instance().get(&DataKey::RecoveryProposal)
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

    // ── Spend Limits ──────────────────────────────────────────────────────────

    /// Set a daily spend limit (in stroops) for a specific asset.
    ///
    /// `limit = 0` removes the limit.
    ///
    /// # Errors
    /// * [`WalletError::InvalidSpendLimit`] — negative limit.
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

    fn require_guardian(env: &Env, caller: &Address) -> Result<(), WalletError> {
        let guardians = Self::guardians(env.clone());
        for i in 0..guardians.len() {
            if &guardians.get(i).unwrap() == caller {
                return Ok(());
            }
        }
        Err(WalletError::Unauthorized)
    }

    fn require_recovery_configured(env: &Env) -> Result<RecoveryConfig, WalletError> {
        env.storage()
            .instance()
            .get(&DataKey::RecoveryConfig)
            .ok_or(WalletError::RecoveryNotConfigured)
    }

    fn require_pending_recovery(env: &Env) -> Result<RecoveryProposal, WalletError> {
        env.storage()
            .instance()
            .get(&DataKey::RecoveryProposal)
            .ok_or(WalletError::NoPendingRecovery)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, Env, String};

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
        client.add_asset(&user, &xlm(&env));
        client.add_asset(&user, &usdc(&env));
        let assets = client.get_assets(&user);
        assert_eq!(assets.len(), 2);
        assert_eq!(assets.get(0).unwrap().code, String::from_str(&env, "XLM"));
    }

    #[test]
    fn test_add_duplicate_asset_fails() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        client.add_asset(&user, &xlm(&env));
        assert_eq!(
            client.try_add_asset(&user, &xlm(&env)),
            Err(Ok(WalletError::AssetAlreadyAdded))
        );
    }

    #[test]
    fn test_remove_asset() {
        let (env, _admin, client) = setup();
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
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        assert_eq!(
            client.try_remove_asset(&user, &String::from_str(&env, "XLM")),
            Err(Ok(WalletError::AssetNotFound))
        );
    }

    #[test]
    fn test_spend_limit_set_and_get() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");
        client.set_spend_limit(&user, &code, &1_000_000_i128);
        assert_eq!(client.get_spend_limit(&user, &code), 1_000_000);
    }

    #[test]
    fn test_record_spend_within_limit() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");
        client.set_spend_limit(&user, &code, &1_000_000_i128);
        client.record_spend(&user, &code, &500_000_i128);
        client.record_spend(&user, &code, &499_999_i128);
    }

    #[test]
    fn test_record_spend_exceeds_limit_fails() {
        let (env, _admin, client) = setup();
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
        let (env, _admin, client) = setup();
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
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");
        // No set_spend_limit call → unlimited
        client.record_spend(&user, &code, &i128::MAX);
    }

    #[test]
    fn test_transfer_admin() {
        let (env, admin, client) = setup();
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
        let (env, admin, client) = setup();
        let new_admin = Address::generate(&env);
        client.propose_admin(&admin, &new_admin);
        assert_eq!(client.admin(), admin);
    }

    #[test]
    fn test_accept_by_wrong_address_fails() {
        let (env, admin, client) = setup();
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
        let (env, admin, client) = setup();
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

        let wasm_hash = BytesN::from_array(&env, &[7u8; 32]);
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

        let wasm_hash = BytesN::from_array(&env, &[8u8; 32]);
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
        client.propose_upgrade(&admin, &wasm_hash, &0u32);
        env.ledger().set_sequence_number(1);
        let other_hash = BytesN::from_array(&env, &[10u8; 32]);
        assert_eq!(
            client.try_execute_upgrade(&admin, &other_hash),
            Err(Ok(WalletError::UpgradeHashMismatch))
        );
    }

    // ── Guardian Recovery ─────────────────────────────────────────────────

    fn setup_with_guardians(n: u32) -> (Env, Address, Vec<Address>, GlobeWalletClient<'static>) {
        let (env, admin, client) = setup();
        let mut guardians: Vec<Address> = Vec::new(&env);
        for _ in 0..n {
            let g = Address::generate(&env);
            client.add_guardian(&admin, &g);
            guardians.push_back(g);
        }
        (env, admin, guardians, client)
    }

    #[test]
    fn test_add_and_list_guardians() {
        let (env, _admin, guardians, client) = setup_with_guardians(3);
        let stored = client.guardians();
        assert_eq!(stored.len(), 3);
        for i in 0..3 {
            assert_eq!(stored.get(i).unwrap(), guardians.get(i).unwrap());
        }
    }

    #[test]
    fn test_add_duplicate_guardian_fails() {
        let (_env, admin, guardians, client) = setup_with_guardians(1);
        assert_eq!(
            client.try_add_guardian(&admin, &guardians.get(0).unwrap()),
            Err(Ok(WalletError::GuardianAlreadyAdded))
        );
    }

    #[test]
    fn test_non_admin_cannot_add_guardian() {
        let (env, _admin, _guardians, client) = setup_with_guardians(1);
        let stranger = Address::generate(&env);
        let candidate = Address::generate(&env);
        assert_eq!(
            client.try_add_guardian(&stranger, &candidate),
            Err(Ok(WalletError::Unauthorized))
        );
    }

    #[test]
    fn test_remove_guardian_below_threshold_fails() {
        let (_env, admin, guardians, client) = setup_with_guardians(3);
        client.set_recovery_config(&admin, &3u32, &10u32);
        assert_eq!(
            client.try_remove_guardian(&admin, &guardians.get(0).unwrap()),
            Err(Ok(WalletError::NotEnoughGuardians))
        );
    }

    #[test]
    fn test_set_recovery_config_requires_min_guardians() {
        let (_env, admin, _guardians, client) = setup_with_guardians(2);
        assert_eq!(
            client.try_set_recovery_config(&admin, &2u32, &10u32),
            Err(Ok(WalletError::NotEnoughGuardians))
        );
    }

    #[test]
    fn test_set_recovery_config_rejects_single_guardian_threshold() {
        let (_env, admin, _guardians, client) = setup_with_guardians(3);
        assert_eq!(
            client.try_set_recovery_config(&admin, &1u32, &10u32),
            Err(Ok(WalletError::InvalidRecoveryThreshold))
        );
    }

    #[test]
    fn test_set_recovery_config_rejects_threshold_above_guardian_count() {
        let (_env, admin, _guardians, client) = setup_with_guardians(3);
        assert_eq!(
            client.try_set_recovery_config(&admin, &4u32, &10u32),
            Err(Ok(WalletError::NotEnoughGuardians))
        );
    }

    #[test]
    fn test_recovery_happy_path_2_of_3() {
        let (env, admin, guardians, client) = setup_with_guardians(3);
        client.set_recovery_config(&admin, &2u32, &10u32);
        let new_admin = Address::generate(&env);

        client.initiate_recovery(&guardians.get(0).unwrap(), &new_admin);
        // Quorum not yet reached with 1 approval.
        assert_eq!(
            client.try_execute_recovery(),
            Err(Ok(WalletError::RecoveryNotQuorate))
        );

        client.approve_recovery(&guardians.get(1).unwrap());
        // Quorum reached, but timelock not yet elapsed.
        assert_eq!(
            client.try_execute_recovery(),
            Err(Ok(WalletError::RecoveryNotReady))
        );

        env.ledger().with_mut(|l| l.sequence_number += 10);
        client.execute_recovery();
        assert_eq!(client.admin(), new_admin);
        assert!(client.recovery_proposal().is_none());
    }

    #[test]
    fn test_recovery_rejects_non_guardian() {
        let (env, admin, _guardians, client) = setup_with_guardians(3);
        client.set_recovery_config(&admin, &2u32, &10u32);
        let stranger = Address::generate(&env);
        let new_admin = Address::generate(&env);
        assert_eq!(
            client.try_initiate_recovery(&stranger, &new_admin),
            Err(Ok(WalletError::Unauthorized))
        );
    }

    #[test]
    fn test_admin_can_cancel_recovery_even_after_quorum() {
        let (env, admin, guardians, client) = setup_with_guardians(3);
        client.set_recovery_config(&admin, &2u32, &10u32);
        let new_admin = Address::generate(&env);

        client.initiate_recovery(&guardians.get(0).unwrap(), &new_admin);
        client.approve_recovery(&guardians.get(1).unwrap());
        // Quorum reached, still within timelock — admin key is still alive
        // and can stop a colluding guardian majority.
        client.cancel_recovery(&admin);

        assert!(client.recovery_proposal().is_none());
        env.ledger().with_mut(|l| l.sequence_number += 100);
        assert_eq!(
            client.try_execute_recovery(),
            Err(Ok(WalletError::NoPendingRecovery))
        );
        assert_eq!(client.admin(), admin);
    }

    #[test]
    fn test_revoking_approval_below_threshold_resets_timelock() {
        let (env, admin, guardians, client) = setup_with_guardians(3);
        client.set_recovery_config(&admin, &2u32, &10u32);
        let new_admin = Address::generate(&env);

        client.initiate_recovery(&guardians.get(0).unwrap(), &new_admin);
        client.approve_recovery(&guardians.get(1).unwrap());
        env.ledger().with_mut(|l| l.sequence_number += 10);

        // A guardian has second thoughts and revokes right as the timelock
        // would otherwise have expired.
        client.revoke_recovery_approval(&guardians.get(1).unwrap());
        assert_eq!(
            client.try_execute_recovery(),
            Err(Ok(WalletError::RecoveryNotQuorate))
        );

        // Re-approving requires a fresh timelock window.
        client.approve_recovery(&guardians.get(1).unwrap());
        assert_eq!(
            client.try_execute_recovery(),
            Err(Ok(WalletError::RecoveryNotReady))
        );
        env.ledger().with_mut(|l| l.sequence_number += 10);
        client.execute_recovery();
        assert_eq!(client.admin(), new_admin);
    }

    #[test]
    fn test_double_approval_rejected() {
        let (env, admin, guardians, client) = setup_with_guardians(3);
        client.set_recovery_config(&admin, &2u32, &10u32);
        let new_admin = Address::generate(&env);
        client.initiate_recovery(&guardians.get(0).unwrap(), &new_admin);
        assert_eq!(
            client.try_approve_recovery(&guardians.get(0).unwrap()),
            Err(Ok(WalletError::AlreadyApproved))
        );
    }

    #[test]
    fn test_cannot_initiate_second_recovery_while_one_pending() {
        let (env, admin, guardians, client) = setup_with_guardians(3);
        client.set_recovery_config(&admin, &2u32, &10u32);
        let new_admin_a = Address::generate(&env);
        let new_admin_b = Address::generate(&env);
        client.initiate_recovery(&guardians.get(0).unwrap(), &new_admin_a);
        assert_eq!(
            client.try_initiate_recovery(&guardians.get(1).unwrap(), &new_admin_b),
            Err(Ok(WalletError::RecoveryAlreadyPending))
        );
    }

    #[test]
    fn test_recovery_clears_any_in_flight_normal_admin_transfer() {
        let (env, admin, guardians, client) = setup_with_guardians(3);
        client.set_recovery_config(&admin, &2u32, &10u32);
        let normal_candidate = Address::generate(&env);
        let recovery_admin = Address::generate(&env);

        // Admin starts a normal (non-recovery) transfer...
        client.propose_admin(&admin, &normal_candidate);

        // ...but the device is lost before it's accepted, so guardians recover instead.
        client.initiate_recovery(&guardians.get(0).unwrap(), &recovery_admin);
        client.approve_recovery(&guardians.get(1).unwrap());
        env.ledger().with_mut(|l| l.sequence_number += 10);
        client.execute_recovery();

        assert_eq!(client.admin(), recovery_admin);
        // The stale normal-transfer proposal must not let the old candidate
        // still claim admin after recovery has already happened.
        assert_eq!(
            client.try_accept_admin(&normal_candidate),
            Err(Ok(WalletError::NoPendingAdmin))
        );
    }
}
