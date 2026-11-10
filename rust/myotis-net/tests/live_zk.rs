//! Live: Colibri's provers and the checkpointz servers answer the way this
//! engine reads them. `#[ignore]`d like every live test; run with
//! `NET=mainnet|sepolia|gnosis cargo test -p myotis-net --test live_zk -- --ignored --nocapture`.

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
async fn the_current_periods_proof_is_served_and_verifies() {
    let config = config();
    let Some(zk) = config.zk_sync.clone() else {
        eprintln!("{}: no ZK proof chain configured", config.name);
        return;
    };
    let period = config.wall_clock_period();
    let proven = myotis_net::zksync::fetch_proven_committee(&config, &zk, period)
        .await
        .unwrap_or_else(|e| panic!("{} period {period}: {e}", config.name));
    eprintln!("{}: period {} committee proven (attested slot {})",
        config.name, proven.period, proven.attested_header.slot);
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
