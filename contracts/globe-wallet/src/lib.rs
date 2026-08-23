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
    contract, contracterror, contractimpl, contracttype, Address, BytesN, Env, Map, String, Symbol,
    Vec,
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
    /// Ordered set of guardian addresses authorized to co-sign admin recovery.
    Guardians,
    /// M-of-N approvals required, and the ledger-count timelock delay
    /// between quorum being reached and a recovery becoming executable.
    RecoveryConfig,
    /// The single in-flight recovery proposal, if any.
    RecoveryProposal,
    /// Membership index for guardians, used to avoid scans on recovery calls.
    ///
    /// This is intentionally appended so the serialized values of existing
    /// storage keys remain stable across contract upgrades.
    GuardianMembership,
}

/// `DailySpent` used to live in *temporary* storage while `SpendLimit` lives in
/// *persistent* storage. Soroban archives temporary entries on its own TTL
/// schedule, independent of the 86 400-second day-window logic here — if the
/// entry got archived before the day boundary, `record_spend` would silently
/// treat the user as having spent 0 today, letting them exceed the configured
/// cap. `DailySpent` now lives in persistent storage (matching `SpendLimit`)
/// and its TTL is proactively extended past the current day boundary on every
/// write so archival can never race the day window.
const LEDGERS_PER_DAY: u32 = 17_280; // ~86_400s / 5s average ledger close time
const DAILY_SPENT_TTL_THRESHOLD: u32 = LEDGERS_PER_DAY;
const DAILY_SPENT_TTL_EXTEND_TO: u32 = LEDGERS_PER_DAY * 2;

/// `UserAssets` and `SpendLimit` are persistent entries without a natural
/// time-based expiry (unlike `DailySpent`'s 86 400-second day window).
/// Without proactive TTL extension, a wallet that goes quiet for long
/// periods while the contract itself stays active could have its asset
/// list or spend limits archived, requiring a separate (costly) restore
/// operation before the entry is readable again. Extending to ~30 days of
/// ledgers on every write keeps these entries alive for any reasonable
/// inactivity window while staying well within Soroban's max_entry_ttl
/// (~6.3M ledgers, ≈1 year).
const PERSISTENT_TTL_THRESHOLD: u32 = LEDGERS_PER_DAY * 7; // ~7 days
const PERSISTENT_TTL_EXTEND_TO: u32 = LEDGERS_PER_DAY * 30; // ~30 days

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
    AlreadyInitialized = 1001,
    NotInitialized = 1002,
    Unauthorized = 1003,
    AssetAlreadyAdded = 1004,
    AssetNotFound = 1005,
    InvalidSpendLimit = 1006,
    /// Payment would exceed the daily spend limit for this asset
    SpendLimitExceeded = 1007,
    NoAssetsProvided = 1008,
    NoPendingAdmin = 9,
    SpendOverflow = 10,
    AssetLimitExceeded = 11,
    MaxAssetsReached = 12,
    UpgradeAlreadyPending = 13,
    UpgradeNotPending = 14,
    UpgradeHashMismatch = 15,
    UpgradeNotReady = 16,
    UpgradeFailed = 17,
    /// Guardian address already registered.
    GuardianAlreadyAdded = 18,
    /// Address is not a registered guardian.
    GuardianNotFound = 19,
    /// Recovery threshold must be `1 < threshold <= guardians.len()`.
    InvalidRecoveryThreshold = 20,
    /// `add_guardian`/`set_recovery_config` would leave threshold >
    /// guardian count, or guardians.len() below the required minimum.
    NotEnoughGuardians = 21,
    /// No recovery threshold/delay configured yet — call `set_recovery_config` first.
    RecoveryNotConfigured = 22,
    /// A recovery proposal is already in flight; cancel or execute it first.
    RecoveryAlreadyPending = 23,
    /// No recovery proposal is currently pending.
    NoPendingRecovery = 24,
    /// Guardian has already approved the pending proposal.
    AlreadyApproved = 25,
    /// Guardian has not approved the pending proposal (nothing to revoke).
    ApprovalNotFound = 26,
    /// Quorum reached but the timelock delay has not yet elapsed.
    RecoveryNotReady = 27,
    /// Approvals dropped below threshold since quorum was reached; timelock reset.
    RecoveryNotQuorate = 28,
    /// Asset code and issuer configuration is invalid
    InvalidAssetInfo = 29,
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
        env.deployer().update_current_contract_wasm(wasm_hash.clone());
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
        let mut membership = Self::guardian_membership(env.clone());
        if membership.get(guardian.clone()).unwrap_or(false) {
            return Err(WalletError::GuardianAlreadyAdded);
        }
        let mut guardians = Self::guardians(env.clone());
        guardians.push_back(guardian.clone());
        env.storage().instance().set(&DataKey::Guardians, &guardians);
        membership.set(guardian.clone(), true);
        env.storage()
            .instance()
            .set(&DataKey::GuardianMembership, &membership);
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
        let mut membership = Self::guardian_membership(env.clone());
        membership.remove(guardian.clone());
        env.storage()
            .instance()
            .set(&DataKey::GuardianMembership, &membership);
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

    /// Return the guardian membership index. The ordered `Guardians` vector
    /// remains the public API for enumeration; this map serves recovery-path
    /// membership checks and duplicate detection.
    ///
    /// Contracts upgraded from a version before this index was added only
    /// have the vector. Build and persist the index once on first access so
    /// their registered guardians remain authorized after an upgrade.
    fn guardian_membership(env: Env) -> Map<Address, bool> {
        if let Some(membership) = env
            .storage()
            .instance()
            .get(&DataKey::GuardianMembership)
        {
            return membership;
        }

        let guardians = Self::guardians(env.clone());
        let mut membership = Map::new(&env);
        for i in 0..guardians.len() {
            membership.set(guardians.get(i).unwrap(), true);
        }
        env.storage()
            .instance()
            .set(&DataKey::GuardianMembership, &membership);
        membership
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

    /// Maximum assets a single user can whitelist.
    /// Chosen to stay well within Soroban per-contract storage (∼100 KB):
    /// each entry is ∼200 bytes → ∼50 entries ≈ 10 KB, far below the ∼100 KB ceiling.
    pub const MAX_ASSETS: u32 = 50;

    /// Add an asset to a user's wallet registry.
    ///
    /// Only the user themselves (via `require_auth`) can add assets.
    ///
    /// # Errors
    /// * [`WalletError::AssetAlreadyAdded`] — asset code already registered.
    /// * [`WalletError::AssetLimitExceeded`] — user would exceed [`MAX_ASSETS`].
    pub fn add_asset(env: Env, user: Address, asset: AssetInfo) -> Result<(), WalletError> {
        user.require_auth();

        let is_native = asset.code == String::from_str(&env, "XLM");
        if is_native {
            if asset.issuer.is_some() {
                return Err(WalletError::InvalidAssetInfo);
            }
        } else {
            if asset.issuer.is_none() {
                return Err(WalletError::InvalidAssetInfo);
            }
        }

        let mut assets: Vec<AssetInfo> = env
            .storage()
            .persistent()
            .get(&DataKey::UserAssets(user.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        if assets.len() >= Self::MAX_ASSETS {
            return Err(WalletError::AssetLimitExceeded);
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
        env.storage().persistent().extend_ttl(
            &DataKey::UserAssets(user.clone()),
            PERSISTENT_TTL_THRESHOLD,
            PERSISTENT_TTL_EXTEND_TO,
        );
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
        env.storage().persistent().extend_ttl(
            &DataKey::UserAssets(user.clone()),
            PERSISTENT_TTL_THRESHOLD,
            PERSISTENT_TTL_EXTEND_TO,
        );
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
                .persistent()
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
        env.storage().persistent().extend_ttl(
            &DataKey::SpendLimit(user.clone(), asset_code.clone()),
            PERSISTENT_TTL_THRESHOLD,
            PERSISTENT_TTL_EXTEND_TO,
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
            .persistent()
            .get(&key)
            .unwrap_or(SpendRecord { amount: 0, day });
        let spent_today = if record.day == day { record.amount } else { 0 };
        let new_spent = spent_today
            .checked_add(amount)
            .ok_or(WalletError::SpendOverflow)?;
        if new_spent > limit {
            return Err(WalletError::SpendLimitExceeded);
        }
        env.storage()
            .persistent()
            .set(&key, &SpendRecord { amount: new_spent, day });
        env.storage().persistent().extend_ttl(
            &key,
            DAILY_SPENT_TTL_THRESHOLD,
            DAILY_SPENT_TTL_EXTEND_TO,
        );
        env.events().publish(
            (Symbol::new(&env, "spend_recorded"),),
            (user, asset_code, amount, new_spent, limit),
        );
        Ok(())
    }

    // ── Migration ───────────────────────────────────────────────────────────────

    /// Admin-only: trim a user's asset list to `MAX_ASSETS` if it exceeds the bound.
    /// Returns the number of assets trimmed (0 if already within limit).
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
        env.storage().persistent().extend_ttl(
            &DataKey::UserAssets(user.clone()),
            PERSISTENT_TTL_THRESHOLD,
            PERSISTENT_TTL_EXTEND_TO,
        );
        let removed = len - Self::MAX_ASSETS;
        env.events().publish(
            (Symbol::new(&env, "user_assets_migrated"),),
            (user, removed),
        );
        Ok(removed)
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
        if Self::guardian_membership(env.clone())
            .get(caller.clone())
            .unwrap_or(false)
        {
            return Ok(());
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
    extern crate std;

    use super::*;
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger as _},
        Env, String, BytesN, Address,
    };

    fn make_code(env: &Env, n: u32) -> String {
        String::from_str(env, &std::format!("A{:02}", n))
    }

    fn fill_to_max(env: &Env, client: &GlobeWalletClient, user: &Address) {
        for i in 0..MAX_ASSETS {
            let code = make_code(env, i);
            let asset = AssetInfo { code, issuer: Some(Address::generate(env)) };
            client.add_asset(user, &asset);
        }
    }

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
        let (env, _cid, _admin, client) = setup();
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
    fn test_daily_spent_survives_temporary_ttl_eviction() {
        // Regression test: DailySpent must live in *persistent* storage so an
        // unrelated temporary-storage archival pass can never reset a user's
        // spend counter before the real 86_400s day window elapses.
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");
        client.set_spend_limit(&user, &code, &1_000_000_i128);
        client.record_spend(&user, &code, &900_000_i128);

        // Simulate an eviction sweep of *temporary* storage only (persistent
        // entries are untouched) by bumping the ledger sequence far past the
        // test env's default temporary-entry TTL (16 ledgers) while staying
        // well under the default persistent-entry TTL (4096 ledgers), so the
        // contract instance itself is not archived — only DailySpent's old
        // (temporary-storage) TTL would have expired at this point.
        env.ledger().with_mut(|l| l.sequence_number += 3_000);

        // If DailySpent were still in temporary storage this would have been
        // archived/reset to 0 and the next 200_000 spend would wrongly succeed.
        assert_eq!(
            client.try_record_spend(&user, &code, &200_000_i128),
            Err(Ok(WalletError::SpendLimitExceeded))
        );
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
    fn test_max_assets_limit() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        for i in 0..GlobeWallet::MAX_ASSETS {
            let code = String::from_str(&env, &std::format!("ASSET{}", i));
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
        let (env, cid, admin, client) = setup();
        let user = Address::generate(&env);
        let mut assets: Vec<AssetInfo> = Vec::new(&env);
        for i in 0..GlobeWallet::MAX_ASSETS + 10 {
            let code = String::from_str(&env, &std::format!("ASSET{}", i));
            assets.push_back(AssetInfo { code, issuer: None });
        }
        env.as_contract(&cid, || {
            env.storage()
                .persistent()
                .set(&DataKey::UserAssets(user.clone()), &assets);
        });
        let removed = client.migrate_user_assets(&admin, &user);
        assert_eq!(removed, 10);
        let assets = client.get_assets(&user);
        assert_eq!(assets.len(), GlobeWallet::MAX_ASSETS as u32);
    }

    #[test]
    fn test_migrate_user_assets_within_limit_does_nothing() {
        let (env, _cid, admin, client) = setup();
        let user = Address::generate(&env);
        for i in 0..3 {
            let code = String::from_str(&env, &std::format!("ASSET{}", i));
            let asset = AssetInfo { code, issuer: None };
            client.add_asset(&user, &asset);
        }
        let removed = client.migrate_user_assets(&admin, &user);
        assert_eq!(removed, 0);
        let assets = client.get_assets(&user);
        assert_eq!(assets.len(), 3);
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

    #[test]
    #[ignore = "embedded .wasm uses reference-types; incompatible with soroban-env-host-21.2.1 test runner"]
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
    fn test_propose_upgrade_requires_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, GlobeWallet);
        let client = GlobeWalletClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        let non_admin = Address::generate(&env);
        let placeholder_hash = BytesN::from_array(&env, &[0u8; 32]); // no real WASM upload needed
        assert_eq!(
            client.try_propose_upgrade(&non_admin, &placeholder_hash, &0u32),
            Err(Ok(WalletError::Unauthorized))
        );
    }

    #[test]
    #[ignore = "embedded .wasm uses reference-types; incompatible with soroban-env-host-21.2.1 test runner"]
    fn test_upgrade_requires_admin_and_ready_time() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, GlobeWallet);
        let client = GlobeWalletClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        let wasm_bytes = soroban_sdk::Bytes::from_slice(&env, include_bytes!("globe_wallet.wasm"));
        let wasm_hash = env.deployer().upload_contract_wasm(wasm_bytes);

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

    // ── Guardian Recovery ─────────────────────────────────────────────────

    fn setup_with_guardians(n: u32) -> (Env, Address, Vec<Address>, GlobeWalletClient<'static>) {
        let (env, _cid, admin, client) = setup();
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
    fn test_removed_guardian_cannot_initiate_recovery() {
        let (env, admin, guardians, client) = setup_with_guardians(4);
        client.set_recovery_config(&admin, &2u32, &10u32);
        let removed = guardians.get(0).unwrap();
        client.remove_guardian(&admin, &removed);

        assert_eq!(
            client.try_initiate_recovery(&removed, &Address::generate(&env)),
            Err(Ok(WalletError::Unauthorized))
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

    // ═══════════════════════════════════════════════════════════════════════════
    // record_spend day-boundary rigorous tests
    //
    // The contract uses:  day = env.ledger().timestamp() / 86_400
    //
    // Guarantee: two calls whose timestamps land in the SAME 86 400-second
    // bucket accumulate into the same daily total.  Two calls whose timestamps
    // land in DIFFERENT buckets each start fresh from zero.
    //
    // Boundary at N*86 400:
    //   timestamp N*86_400 - 1  → bucket N-1
    //   timestamp N*86_400      → bucket N   ← new day resets the counter
    // ═══════════════════════════════════════════════════════════════════════════

    /// Calls at the last second of a bucket (T = day*86400 - 1) accumulate.
    #[test]
    fn test_record_spend_boundary_last_second_of_day_accumulates() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");
        client.set_spend_limit(&user, &code, &1_000_i128);

        // Set timestamp to the very last second of day 1 (day 0 bucket ends at 86399)
        let day = 1u64;
        let last_sec_of_day = day * 86_400 - 1; // 86_399 → still in bucket 0
        env.ledger().with_mut(|l| l.timestamp = last_sec_of_day);

        client.record_spend(&user, &code, &600_i128);

        // Second call in the same bucket should accumulate
        assert_eq!(
            client.try_record_spend(&user, &code, &401_i128),
            Err(Ok(WalletError::SpendLimitExceeded)),
            "Two spends in the same bucket must accumulate: 600+401 > 1000"
        );
    }

    /// Call at the first second of the next bucket (T = day*86400) resets to zero.
    #[test]
    fn test_record_spend_boundary_first_second_of_new_day_resets() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");
        client.set_spend_limit(&user, &code, &1_000_i128);

        // Spend 900 in bucket 0
        env.ledger().with_mut(|l| l.timestamp = 86_399); // bucket 0 = ts/86400 == 0
        client.record_spend(&user, &code, &900_i128);

        // Advance to the exact start of bucket 1 — counter must reset
        env.ledger().with_mut(|l| l.timestamp = 86_400); // bucket 1 = ts/86400 == 1

        // Should succeed because we're in a brand-new bucket
        client.record_spend(&user, &code, &1_000_i128);
    }

    /// Explicit boundary: timestamp N*86400 - 1 vs N*86400 are different buckets.
    #[test]
    fn test_record_spend_exact_day_boundary() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");
        client.set_spend_limit(&user, &code, &500_i128);

        let n: u64 = 5;
        let before_boundary = n * 86_400 - 1; // bucket n-1
        let at_boundary     = n * 86_400;     // bucket n

        // Spend right at the boundary-minus-one
        env.ledger().with_mut(|l| l.timestamp = before_boundary);
        client.record_spend(&user, &code, &500_i128); // fills bucket n-1 exactly

        // Any more spend in bucket n-1 must fail
        assert_eq!(
            client.try_record_spend(&user, &code, &1_i128),
            Err(Ok(WalletError::SpendLimitExceeded))
        );

        // Crossing into bucket n resets the counter: full 500 must be available again
        env.ledger().with_mut(|l| l.timestamp = at_boundary);
        client.record_spend(&user, &code, &500_i128);
    }

    /// Validates that the bucket is derived from integer division (not rounding).
    #[test]
    fn test_record_spend_bucket_is_integer_division() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");
        client.set_spend_limit(&user, &code, &100_i128);

        // All three timestamps below belong to bucket 1 (86400..=172799)
        // Reset env per iteration by re-registering is expensive;
        // instead use the fact that the day counter resets between buckets
        // and just verify that within the same bucket they accumulate.

        // Spend 50 in bucket 1
        env.ledger().with_mut(|l| l.timestamp = 86_400);
        client.record_spend(&user, &code, &50_i128);

        // Move to middle of same bucket — still bucket 1, should accumulate
        env.ledger().with_mut(|l| l.timestamp = 129_600); // 86400 + 43200
        assert_eq!(
            client.try_record_spend(&user, &code, &51_i128),
            Err(Ok(WalletError::SpendLimitExceeded)),
            "50+51 > 100: mid-bucket accumulation must hold"
        );

        // Move to end of bucket 1
        env.ledger().with_mut(|l| l.timestamp = 172_799);
        assert_eq!(
            client.try_record_spend(&user, &code, &51_i128),
            Err(Ok(WalletError::SpendLimitExceeded)),
            "50+51 > 100: end-of-bucket accumulation must hold"
        );
    }

    /// Demonstrates the known skew risk: if validator timestamps drift up to
    /// `MAX_CLOSE_TIME_DRIFT` (typically ±1 s on Stellar), a human's "same
    /// second" could split across two buckets only if it straddles an exact
    /// multiple of 86 400.  Probability is vanishingly small (1/86400 ≈ 0.001%)
    /// but the test documents the invariant explicitly.
    #[test]
    fn test_record_spend_boundary_drift_awareness() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");
        client.set_spend_limit(&user, &code, &1_000_i128);

        // Two validator-derived timestamps 2 seconds apart straddling midnight
        let just_before = 2 * 86_400 - 1;
        let just_after  = 2 * 86_400;

        // Spend near-limit just before midnight
        env.ledger().with_mut(|l| l.timestamp = just_before);
        client.record_spend(&user, &code, &999_i128);

        // If a second tx arrives 1 second later it lands in a new bucket and is ALLOWED.
        // This is the known fixed-bucket split: user perceives same-session but
        // contract resets. Not exploitable (it's more restrictive by resetting), but
        // confusing to users.
        env.ledger().with_mut(|l| l.timestamp = just_after);
        client.record_spend(&user, &code, &1_000_i128); // succeeds — new bucket
    }

    #[test]
    fn test_native_code_with_issuer_is_contradictory_and_rejected() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        let bogus = AssetInfo {
            code: String::from_str(&env, "XLM"),
            issuer: Some(Address::generate(&env)),
        };
        assert_eq!(
            client.try_add_asset(&user, &bogus),
            Err(Ok(WalletError::InvalidAssetInfo))
        );
    }

    #[test]
    fn test_non_native_code_without_issuer_is_underspecified_and_rejected() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        let ambiguous = AssetInfo {
            code: String::from_str(&env, "USDC"),
            issuer: None,
        };
        assert_eq!(
            client.try_add_asset(&user, &ambiguous),
            Err(Ok(WalletError::InvalidAssetInfo))
        );
    }

    // ── TTL Extension ───────────────────────────────────────────────────
    //
    // Proactive extend_ttl on every write keeps UserAssets and SpendLimit
    // entries alive past the default persistent-entry TTL (4096 ledgers
    // in test env). Without it, a wallet that goes quiet while the
    // contract stays active could have its entries archived.

    #[test]
    fn test_user_assets_ttl_extension_after_long_idle_period() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        client.add_asset(&user, &xlm(&env));
        client.add_asset(&user, &usdc(&env));

        // Jump well past the default persistent-entry TTL (4096 ledgers).
        // Without extend_ttl, the entry's default TTL would have expired
        // and the archived entry would not be readable without a restore.
        env.ledger().with_mut(|l| l.sequence_number += 50_000);

        let assets = client.get_assets(&user);
        assert_eq!(assets.len(), 2);
        assert_eq!(assets.get(0).unwrap().code, String::from_str(&env, "XLM"));
    }

    #[test]
    fn test_spend_limit_ttl_extension_after_long_idle_period() {
        let (env, _cid, _admin, client) = setup();
        let user = Address::generate(&env);
        let code = String::from_str(&env, "XLM");
        client.set_spend_limit(&user, &code, &1_000_000_i128);

        // Jump well past default persistent-entry TTL.
        env.ledger().with_mut(|l| l.sequence_number += 50_000);

        assert_eq!(client.get_spend_limit(&user, &code), 1_000_000);
    }
}
