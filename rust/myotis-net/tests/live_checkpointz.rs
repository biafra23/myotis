//! Live: the checkpointz servers answer the way this engine reads them, and
//! unanimously. `#[ignore]`d like every live test; run with
//! `NET=mainnet|sepolia|gnosis|chiado cargo test -p myotis-net --test live_checkpointz -- --ignored --nocapture`.

use myotis_net::sync::ChainConfig;

fn config() -> ChainConfig {
    match std::env::var("NET").as_deref() {
        Ok("gnosis") => ChainConfig::gnosis(),
        Ok("sepolia") => ChainConfig::sepolia(),
        Ok("chiado") => ChainConfig::chiado(),
        _ => ChainConfig::mainnet(),
    }
}

#[tokio::test]
#[ignore]
async fn checkpointz_servers_agree_on_a_finalized_root() {
    let config = config();
    let fresh = myotis_net::checkpointz::fetch_agreed(&config.checkpointz_servers, config.slots_per_epoch)
        .await
        .unwrap_or_else(|e| panic!("{}: {e}", config.name));
    eprintln!("{}: epoch {} slot {} agreed by {:?}", config.name, fresh.epoch, fresh.slot, fresh.operators);
    assert!(fresh.operators.len() >= myotis_net::checkpointz::MIN_AGREEING_OPERATORS);
}
