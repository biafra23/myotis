//! Live-network test for the EIP-1459 DNS tree walk (#539, part 3): walk a
//! network's node list over this host's system resolver with the filter the
//! reader ships, and report what it found — dial candidates, discovery-only
//! nodes, nodes on other chains, records that did not verify.
//!
//! Ignored by default (DNS queries to the EF's `ethdisco.net` zones). Run with:
//!
//! ```bash
//! NET=mainnet cargo test -p myotis-net --test live_dns_tree -- --ignored --nocapture
//! NET=sepolia cargo test -p myotis-net --test live_dns_tree -- --ignored --nocapture
//! ```
use std::time::Duration;

use myotis_net::el::dnsdisco::{walk, EnrTreeUrl, SystemResolver, WalkLimits};
use myotis_net::el::reader::{fork_filter_for, ElConfig};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network test: walks a network's EIP-1459 DNS tree over the system resolver"]
async fn the_tree_walk_yields_dial_candidates() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,myotis_net::el::dnsdisco=debug".into()),
        )
        .try_init();
    let net = std::env::var("NET").unwrap_or_else(|_| "mainnet".to_string());
    let cfg = match net.as_str() {
        "sepolia" => ElConfig::sepolia(),
        "gnosis" => ElConfig::gnosis(),
        _ => ElConfig::mainnet(),
    };
    assert!(
        !cfg.enr_tree_urls.is_empty(),
        "{net} publishes no EL node list — nothing to walk (Gnosis dials its pinned enodes instead)"
    );
    let resolver = SystemResolver::new().expect("this host has a resolver configuration");
    let filter = fork_filter_for(&cfg);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for url in &cfg.enr_tree_urls {
        let url = EnrTreeUrl::parse(url).unwrap();
        let started = std::time::Instant::now();
        let report = walk(&resolver, &url, WalkLimits::default(), &filter, now)
            .await
            .expect("the root record resolves and verifies under the pinned key");
        eprintln!(
            "[live_dns_tree {net}] {} seq={} lookups={} leaves={} candidates={} discovery_only={} foreign={} unusable={} mismatched={} links={} timed_out={} in {:?}",
            url.domain,
            report.seq,
            report.lookups,
            report.leaves,
            report.candidates.len(),
            report.discovery_only.len(),
            report.foreign,
            report.unusable,
            report.mismatched,
            report.links,
            report.timed_out,
            started.elapsed()
        );
        assert!(report.leaves > 0, "the walk met no node records");
        assert!(
            !report.candidates.is_empty(),
            "no leaf on {net} named a TCP port and passed the fork filter"
        );
        assert_eq!(report.mismatched, 0, "every record hashed to its label");
        assert!(started.elapsed() < WalkLimits::default().deadline + Duration::from_secs(5));
    }
}
