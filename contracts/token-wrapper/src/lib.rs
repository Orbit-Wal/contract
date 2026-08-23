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
    /// (owner, spender) → (amount, expiry_ledger)
    Allowance(Address, Address),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Allowance {
    pub amount: i128,
    pub expiry_ledger: u32,
}

// Error code namespace for token-wrapper contract. Codes start at 2001.
// Reserved range: 2001-2999 for future extensions.
    AllowanceExpired = 2001,
    InsufficientAllowance = 2002,
    InvalidAmount = 2003,
    InvalidExpiry = 2004,
// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum WrapperError {
    AllowanceExpired = 1,
    InsufficientAllowance = 2,
    InvalidAmount = 3,
    InvalidExpiry = 4,
}

#[contract]
pub struct TokenWrapper;

#[contractimpl]
impl TokenWrapper {
    /// Grant a spender allowance over the caller's tokens.
    ///
    /// **Overwrite semantics:** calling `approve` for an existing
    /// `(owner, spender)` pair **replaces** the previous allowance
    /// wholesale — it does **not** add to the remaining balance.
    /// If a spender has already used part of their allowance and
    /// the owner calls `approve` again, the new `amount` becomes the
    /// *total* allowance, not an increment on top of what's left.
    ///
    /// `expiry_ledger` must be in the future.
    pub fn approve(
        env: Env,
        owner: Address,
        spender: Address,
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
        let key = DataKey::Allowance(owner.clone(), spender.clone());
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
            (owner, spender, amount, expiry_ledger),
        );
        Ok(())
    }

    /// Return current allowance for (owner, spender).
    pub fn allowance(env: Env, owner: Address, spender: Address) -> Allowance {
        let key = DataKey::Allowance(owner, spender);
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
        let key = DataKey::Allowance(from.clone(), spender.clone());
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
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        env.ledger().with_mut(|l| l.sequence_number = 100);
        client.approve(&owner, &spender, &1_000, &200);
        let a = client.allowance(&owner, &spender);
        assert_eq!(a.amount, 1_000);
        assert_eq!(a.expiry_ledger, 200);
    }

    #[test]
    fn test_approve_negative_amount_fails() {
        let (env, _id, client) = setup();
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        env.ledger().with_mut(|l| l.sequence_number = 100);
        assert_eq!(
            client.try_approve(&owner, &spender, &-1, &200),
            Err(Ok(WrapperError::InvalidAmount))
        );
    }

    #[test]
    fn test_approve_past_expiry_fails() {
        let (env, _id, client) = setup();
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        env.ledger().with_mut(|l| l.sequence_number = 100);
        assert_eq!(
            client.try_approve(&owner, &spender, &1_000, &50),
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
        client.approve(&owner, &spender, &500, &300);
        client.transfer_from(&spender, &token_id, &owner, &to, &300);
        let remaining = client.allowance(&owner, &spender);
        assert_eq!(remaining.amount, 200);

        // Calling approve again replaces (not adds to) the allowance.
        client.approve(&owner, &spender, &500, &400);
        let a = client.allowance(&owner, &spender);
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
        client.approve(&owner, &spender, &500, &200);
        client.transfer_from(&spender, &token_id, &owner, &to, &300);

        assert_eq!(token.balance(&owner), 700);
        assert_eq!(token.balance(&to), 300);
        let remaining = client.allowance(&owner, &spender);
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
        client.approve(&owner, &spender, &100, &200);
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
        client.approve(&owner, &spender, &500, &150);
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
    fn test_transfer_from_succeeds_exactly_at_expiry_ledger() {
        let (env, _id, client) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let to = Address::generate(&env);
        let (token_id, token_admin, _token) = create_token_contract(&env, &admin);
        token_admin.mint(&owner, &1_000);
        env.ledger().with_mut(|l| l.sequence_number = 100);
        client.approve(&owner, &spender, &500, &200);
        env.ledger().with_mut(|l| l.sequence_number = 200); // exactly at expiry_ledger
        client.transfer_from(&spender, &token_id, &owner, &to, &100); // currently succeeds — lock this in explicitly
    }
}
