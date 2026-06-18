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
            .temporary()
            .set(&key, &Allowance { amount, expiry_ledger });
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
            .temporary()
            .get(&key)
            .unwrap_or(Allowance { amount: 0, expiry_ledger: 0 })
    }

    /// Transfer tokens from `from` to `to` using a previously granted allowance.
    ///
    /// Decrements the allowance; fails if expired or insufficient.
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
            .temporary()
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
        env.storage().temporary().set(&key, &new_allowance);
        let token_client = token::Client::new(&env, &token_id);
        token_client.transfer(&from, &to, &amount);
        env.events().publish(
            (Symbol::new(&env, "transfer_from"),),
            (spender, from, to, amount),
        );
        Ok(())
    }
}
