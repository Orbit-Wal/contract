use globe_wallet::{GlobeWallet, GlobeWalletClient, WalletError};
use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, Env, String};

#[contract]
struct SameInvocationBatcher;

#[contractimpl]
impl SameInvocationBatcher {
    pub fn record_twice(
        env: Env,
        wallet: Address,
        user: Address,
        asset_code: String,
        first: i128,
        second: i128,
    ) {
        let wallet = GlobeWalletClient::new(&env, &wallet);
        wallet.record_spend(&user, &asset_code, &first);
        wallet.record_spend(&user, &asset_code, &second);
    }
}

#[test]
fn two_spends_in_one_host_invocation_accumulate() {
    let env = Env::default();
    env.mock_all_auths_allowing_non_root_auth();

    let wallet_id = env.register(GlobeWallet, ());
    let wallet = GlobeWalletClient::new(&env, &wallet_id);
    let batcher_id = env.register(SameInvocationBatcher, ());
    let batcher = SameInvocationBatcherClient::new(&env, &batcher_id);
    let user = Address::generate(&env);
    let asset_code = String::from_str(&env, "XLM");

    wallet.set_spend_limit(&user, &asset_code, &1_000_i128);

    // Both calls share one root host invocation. The second call must observe
    // the first call's write rather than overwrite a stale zero value.
    batcher.record_twice(
        &wallet_id,
        &user,
        &asset_code,
        &600_i128,
        &400_i128,
    );

    assert_eq!(
        wallet.try_record_spend(&user, &asset_code, &1_i128),
        Err(Ok(WalletError::SpendLimitExceeded))
    );
}
