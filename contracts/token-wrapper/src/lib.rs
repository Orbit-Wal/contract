#![no_std]

//! # token-wrapper
//!
//! Thin wrapper around the Soroban token interface that adds
//! allowance-gated transfers for the GlobeWallet protocol.
//! Enables the globe-wallet contract to move tokens on behalf
//! of users who have granted a per-session allowance.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, token, Address, Env, Symbol,
};

#[contracttype]
pub enum DataKey {
    /// (owner, spender, token_id) → (amount, expiry_ledger)
    Allowance(Address, Address, Address),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Allowance {
    pub amount: i128,
    pub expiry_ledger: u32,
}

// ── Errors ────────────────────────────────────────────────────────────────────
//
// Code namespace for token-wrapper contract errors. Codes start at 2001,
// reserved range 2001-2999, kept distinct from globe-wallet's WalletError
// range (1001-1030+, see contracts/globe-wallet/src/lib.rs) so a raw
// `Error(Contract, #N)` code is unambiguous about which contract raised it
// without also needing the contract address alongside it.

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum WrapperError {
    AllowanceExpired = 2001,
    InsufficientAllowance = 2002,
    InvalidAmount = 2003,
    InvalidExpiry = 2004,
}

#[contract]
pub struct TokenWrapper;

#[contractimpl]
impl TokenWrapper {
    /// Grant a spender allowance over the caller's tokens for a specific asset.
    ///
    /// **Overwrite semantics:** calling `approve` for an existing
    /// `(owner, spender, token_id)` tuple **replaces** the previous allowance
    /// wholesale — it does **not** add to the remaining balance.
    /// If a spender has already used part of their allowance and
    /// the owner calls `approve` again for the same token, the new `amount` becomes the
    /// *total* allowance, not an increment on top of what's left.
    ///
    /// `expiry_ledger` must be in the future.
    pub fn approve(
        env: Env,
        owner: Address,
        spender: Address,
        token_id: Address,
        amount: i128,
        expiry_ledger: u32,
    ) -> Result<(), WrapperError> {
        owner.require_auth();
        if amount < 0 {
            return Err(WrapperError::InvalidAmount);
        }
        if expiry_ledger <= env.ledger().sequence() {
            return Err(WrapperError::InvalidExpiry);
        }
        let key = DataKey::Allowance(owner.clone(), spender.clone(), token_id.clone());
        env.storage()
            .persistent()
            .set(&key, &Allowance { amount, expiry_ledger });
        // Allowance carries an explicit `expiry_ledger` contract; storage TTL
        // must never expire *before* that ledger or the allowance would vanish
        // early through archival rather than through its own stated semantics.
        let extend_to = expiry_ledger.saturating_sub(env.ledger().sequence());
        env.storage().persistent().extend_ttl(&key, extend_to, extend_to);
        env.events().publish(
            (Symbol::new(&env, "approved"),),
            (owner, spender, token_id, amount, expiry_ledger),
        );
        Ok(())
    }

    /// Return current allowance for (owner, spender, token_id).
    pub fn allowance(env: Env, owner: Address, spender: Address, token_id: Address) -> Allowance {
        let key = DataKey::Allowance(owner, spender, token_id);
        env.storage()
            .persistent()
            .get(&key)
            .unwrap_or(Allowance { amount: 0, expiry_ledger: 0 })
    }

    /// Transfer tokens from `from` to `to` using a previously granted allowance.
    ///
    /// Decrements the allowance; fails if expired or insufficient.
    /// An allowance is usable through and including its `expiry_ledger`.
    pub fn transfer_from(
        env: Env,
        spender: Address,
        token_id: Address,
        from: Address,
        to: Address,
        amount: i128,
    ) -> Result<(), WrapperError> {
        spender.require_auth();
        if amount <= 0 {
            return Err(WrapperError::InvalidAmount);
        }
        let key = DataKey::Allowance(from.clone(), spender.clone(), token_id.clone());
        let current: Allowance = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Allowance { amount: 0, expiry_ledger: 0 });
        if current.expiry_ledger < env.ledger().sequence() {
            return Err(WrapperError::AllowanceExpired);
        }
        if current.amount < amount {
            return Err(WrapperError::InsufficientAllowance);
        }
        let new_allowance = Allowance {
            amount: current.amount - amount,
            expiry_ledger: current.expiry_ledger,
        };
        env.storage().persistent().set(&key, &new_allowance);
        let extend_to = current.expiry_ledger.saturating_sub(env.ledger().sequence());
        env.storage().persistent().extend_ttl(&key, extend_to, extend_to);
        let token_client = token::Client::new(&env, &token_id);
        token_client.transfer(&from, &to, &amount);
        env.events().publish(
            (Symbol::new(&env, "transfer_from"),),
            (spender, from, to, amount),
        );
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};

    fn create_token_contract<'a>(
        env: &Env,
        admin: &Address,
    ) -> (Address, token::StellarAssetClient<'a>, token::Client<'a>) {
        let sac = env.register_stellar_asset_contract_v2(admin.clone());
        let address = sac.address();
        (
            address.clone(),
            token::StellarAssetClient::new(env, &address),
            token::Client::new(env, &address),
        )
    }

    fn setup() -> (Env, Address, TokenWrapperClient<'static>) {
        let env = Env::default();
        env.mock_all_auths_allowing_non_root_auth();
        let id = env.register_contract(None, TokenWrapper);
        let client = TokenWrapperClient::new(&env, &id);
        (env, id, client)
    }

    #[test]
    fn test_approve_and_allowance() {
        let (env, _id, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let (token_id, _token_admin, _token) = create_token_contract(&env, &admin);
        env.ledger().with_mut(|l| l.sequence_number = 100);
        client.approve(&owner, &spender, &token_id, &1_000, &200);
        let a = client.allowance(&owner, &spender, &token_id);
        assert_eq!(a.amount, 1_000);
        assert_eq!(a.expiry_ledger, 200);
    }

    #[test]
    fn test_allowance_unset_pair_returns_zero() {
        let (env, _id, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let (token_id, _token_admin, _token) = create_token_contract(&env, &admin);
        // Cold read: never approved — hits unwrap_or default branch.
        let a = client.allowance(&owner, &spender, &token_id);
        assert_eq!(a.amount, 0);
        assert_eq!(a.expiry_ledger, 0);
    }

    #[test]
    fn test_approve_negative_amount_fails() {
        let (env, _id, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let (token_id, _token_admin, _token) = create_token_contract(&env, &admin);
        env.ledger().with_mut(|l| l.sequence_number = 100);
        assert_eq!(
            client.try_approve(&owner, &spender, &token_id, &-1, &200),
            Err(Ok(WrapperError::InvalidAmount))
        );
    }

    #[test]
    fn test_approve_past_expiry_fails() {
        let (env, _id, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let (token_id, _token_admin, _token) = create_token_contract(&env, &admin);
        env.ledger().with_mut(|l| l.sequence_number = 100);
        assert_eq!(
            client.try_approve(&owner, &spender, &token_id, &1_000, &50),
            Err(Ok(WrapperError::InvalidExpiry))
        );
    }

    #[test]
    fn test_approve_overwrites_previous_allowance() {
        let (env, _id, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let to = Address::generate(&env);
        let (token_id, token_admin, _token) = create_token_contract(&env, &admin);
        token_admin.mint(&owner, &1_000);

        // Grant 500 allowance and spend 300, leaving 200 remaining.
        env.ledger().with_mut(|l| l.sequence_number = 100);
        client.approve(&owner, &spender, &token_id, &500, &300);
        client.transfer_from(&spender, &token_id, &owner, &to, &300);
        let remaining = client.allowance(&owner, &spender, &token_id);
        assert_eq!(remaining.amount, 200);

        // Calling approve again for the same token replaces (not adds to) the allowance.
        client.approve(&owner, &spender, &token_id, &500, &400);
        let a = client.allowance(&owner, &spender, &token_id);
        assert_eq!(a.amount, 500); // NOT 700 — overwrite, not additive
        assert_eq!(a.expiry_ledger, 400);
    }

    #[test]
    fn test_transfer_from_happy_path() {
        let (env, _id, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let to = Address::generate(&env);
        let (token_id, token_admin, token) = create_token_contract(&env, &admin);
        token_admin.mint(&owner, &1_000);

        env.ledger().with_mut(|l| l.sequence_number = 100);
        client.approve(&owner, &spender, &token_id, &500, &200);
        client.transfer_from(&spender, &token_id, &owner, &to, &300);

        assert_eq!(token.balance(&owner), 700);
        assert_eq!(token.balance(&to), 300);
        let remaining = client.allowance(&owner, &spender, &token_id);
        assert_eq!(remaining.amount, 200);
    }

    #[test]
    fn test_transfer_from_insufficient_allowance_fails() {
        let (env, _id, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let to = Address::generate(&env);
        let (token_id, token_admin, _token) = create_token_contract(&env, &admin);
        token_admin.mint(&owner, &1_000);

        env.ledger().with_mut(|l| l.sequence_number = 100);
        client.approve(&owner, &spender, &token_id, &100, &200);
        assert_eq!(
            client.try_transfer_from(&spender, &token_id, &owner, &to, &300),
            Err(Ok(WrapperError::InsufficientAllowance))
        );
    }

    #[test]
    fn test_transfer_from_expired_allowance_fails() {
        let (env, _id, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let to = Address::generate(&env);
        let (token_id, token_admin, _token) = create_token_contract(&env, &admin);
        token_admin.mint(&owner, &1_000);

        env.ledger().with_mut(|l| l.sequence_number = 100);
        client.approve(&owner, &spender, &token_id, &500, &150);
        env.ledger().with_mut(|l| l.sequence_number = 200);
        assert_eq!(
            client.try_transfer_from(&spender, &token_id, &owner, &to, &100),
            Err(Ok(WrapperError::AllowanceExpired))
        );
    }

    #[test]
    fn test_transfer_from_zero_amount_fails() {
        let (env, _id, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let to = Address::generate(&env);
        let (token_id, _token_admin, _token) = create_token_contract(&env, &admin);

        env.ledger().with_mut(|l| l.sequence_number = 100);
        assert_eq!(
            client.try_transfer_from(&spender, &token_id, &owner, &to, &0),
            Err(Ok(WrapperError::InvalidAmount))
        );
    }

    #[test]
    fn test_transfer_from_rolls_back_allowance_when_underlying_transfer_fails() {
        // issue #38: `transfer_from` persists the debited allowance *before*
        // calling into the underlying token contract's `transfer`. If that
        // underlying call itself fails (e.g. the owner's real balance is
        // less than the amount being moved, even though it's within the
        // allowance this contract tracks), Soroban's atomic transaction
        // semantics roll back *all* state changes from the failed
        // invocation, including the allowance write made earlier in the
        // same call. This test locks in that expectation: the allowance
        // read afterward must show the original, pre-attempt value, proving
        // the storage write was rolled back rather than left partially
        // applied.
        let (env, _id, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let to = Address::generate(&env);
        let (token_id, token_admin, token) = create_token_contract(&env, &admin);
        // Owner has only 100 real tokens...
        token_admin.mint(&owner, &100);

        env.ledger().with_mut(|l| l.sequence_number = 100);
        // ...but is approved for far more (500), so transfer_from's own
        // allowance check passes and it proceeds to persist the debited
        // allowance before calling the underlying token contract.
        client.approve(&owner, &spender, &token_id, &500, &200);

        // Attempt to move 300 — passes the allowance check (500 >= 300) but
        // exceeds the owner's real underlying balance (100), so the token
        // contract's own `transfer` call fails.
        assert!(client
            .try_transfer_from(&spender, &token_id, &owner, &to, &300)
            .is_err());

        // The allowance must still read the ORIGINAL, pre-attempt value.
        let a = client.allowance(&owner, &spender, &token_id);
        assert_eq!(a.amount, 500);
        assert_eq!(a.expiry_ledger, 200);
        // And no tokens actually moved.
        assert_eq!(token.balance(&owner), 100);
        assert_eq!(token.balance(&to), 0);
    }

    #[test]
    fn test_transfer_from_succeeds_exactly_at_expiry_ledger() {
        let (env, _id, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let to = Address::generate(&env);
        let (token_id, token_admin, _token) = create_token_contract(&env, &admin);
        token_admin.mint(&owner, &1_000);
        env.ledger().with_mut(|l| l.sequence_number = 100);
        client.approve(&owner, &spender, &token_id, &500, &200);
        env.ledger().with_mut(|l| l.sequence_number = 200); // exactly at expiry_ledger
        client.transfer_from(&spender, &token_id, &owner, &to, &100); // currently succeeds — lock this in explicitly
    }

    #[test]
    fn test_approving_second_token_does_not_destroy_first_tokens_allowance() {
        // Issue #85: approving spender for a second token must not overwrite
        // or destroy the allowance in place for the first token.
        let (env, _id, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let (token_a, token_a_admin, _) = create_token_contract(&env, &admin);
        let (token_b, _, _) = create_token_contract(&env, &admin);
        token_a_admin.mint(&owner, &1_000);

        env.ledger().with_mut(|l| l.sequence_number = 100);

        // Owner grants spender 500 of token_a.
        client.approve(&owner, &spender, &token_a, &500, &300);
        assert_eq!(client.allowance(&owner, &spender, &token_a).amount, 500);

        // Owner separately grants the SAME spender an allowance for a
        // DIFFERENT token, token_b.
        client.approve(&owner, &spender, &token_b, &300, &300);

        // The token_a allowance is preserved independent of token_b.
        assert_eq!(client.allowance(&owner, &spender, &token_a).amount, 500);
        assert_eq!(client.allowance(&owner, &spender, &token_b).amount, 300);
    }

    #[test]
    fn test_allowances_for_different_tokens_are_independent() {
        let (env, _id, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let to = Address::generate(&env);
        let (token_a, token_a_admin, token_a_client) = create_token_contract(&env, &admin);
        let (token_b, token_b_admin, token_b_client) = create_token_contract(&env, &admin);
        token_a_admin.mint(&owner, &1_000);
        token_b_admin.mint(&owner, &1_000);

        env.ledger().with_mut(|l| l.sequence_number = 100);

        // Owner grants spender 500 of token_a.
        client.approve(&owner, &spender, &token_a, &500, &300);
        assert_eq!(client.allowance(&owner, &spender, &token_a).amount, 500);

        // Owner separately grants the SAME spender an allowance for a DIFFERENT token, token_b.
        client.approve(&owner, &spender, &token_b, &300, &400);

        // Assert token_a allowance remains untouched (500, expiry 300)
        let allowance_a = client.allowance(&owner, &spender, &token_a);
        assert_eq!(allowance_a.amount, 500);
        assert_eq!(allowance_a.expiry_ledger, 300);

        // Assert token_b allowance is set properly (300, expiry 400)
        let allowance_b = client.allowance(&owner, &spender, &token_b);
        assert_eq!(allowance_b.amount, 300);
        assert_eq!(allowance_b.expiry_ledger, 400);

        // Spending against token_a debits only token_a allowance
        client.transfer_from(&spender, &token_a, &owner, &to, &200);
        assert_eq!(client.allowance(&owner, &spender, &token_a).amount, 300);
        assert_eq!(client.allowance(&owner, &spender, &token_b).amount, 300);
        assert_eq!(token_a_client.balance(&to), 200);
        assert_eq!(token_b_client.balance(&to), 0);

        // Spending against token_b debits only token_b allowance
        client.transfer_from(&spender, &token_b, &owner, &to, &150);
        assert_eq!(client.allowance(&owner, &spender, &token_a).amount, 300);
        assert_eq!(client.allowance(&owner, &spender, &token_b).amount, 150);
        assert_eq!(token_a_client.balance(&to), 200);
    }
}

