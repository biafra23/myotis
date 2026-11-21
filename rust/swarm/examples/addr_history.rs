//! Reads one address's history from an addr1 index over Swarm, through the embedded node:
//! the origin, the newest head update, and pages of entries, newest first. A development
//! tool for a local network; every chunk is checked as in the engine.
//!
//! ```text
//! cargo run --release --manifest-path rust/swarm/Cargo.toml --example addr_history -- \
//!   --network-id <id> --bootnode <multiaddr> \
//!   --owner 0x… --chain 1 --address 0x… [--limit 20] [--pages 2] [--hint N]
//! ```

use std::time::{Duration, Instant};

use myotis_addr1::client::Index;
use myotis_addr1::records::role;
use myotis_swarm::{SwarmConfig, SwarmNode};

fn hex20(s: &str) -> [u8; 20] {
    let s = s.trim_start_matches("0x");
    let v: Vec<u8> = (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex")).collect();
    v.try_into().expect("20 bytes")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| args.iter().position(|a| a == name).map(|i| args[i + 1].clone());
    let network_id: u64 = arg("--network-id").expect("--network-id").parse().unwrap();
    let bootnodes = args
        .iter()
        .enumerate()
        .filter(|(_, a)| *a == "--bootnode")
        .map(|(i, _)| args[i + 1].parse().expect("multiaddr"))
        .collect();
    let owner = hex20(&arg("--owner").expect("--owner"));
    let chain: u64 = arg("--chain").expect("--chain").parse().unwrap();
    let address = hex20(&arg("--address").expect("--address"));
    let limit: usize = arg("--limit").unwrap_or("20".into()).parse().unwrap();
    let pages: usize = arg("--pages").unwrap_or("1".into()).parse().unwrap();
    let hint: u64 = arg("--hint").unwrap_or("0".into()).parse().unwrap();
    let before: Option<(u64, u32)> = arg("--before").map(|b| (b.parse().unwrap(), 0));

    let node = SwarmNode::start(SwarmConfig::dev(network_id, bootnodes)).expect("node");
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let t = Instant::now();
        while node.connected_peers() < 4 && t.elapsed() < Duration::from_secs(30) {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        println!("peers {} after {:?}", node.connected_peers(), t.elapsed());
        let index = Index::new(&node, chain, owner);
        let t = Instant::now();
        let origin = index.origin().await.expect("origin");
        let (n, head) = index.head(&origin, hint).await.expect("head");
        println!(
            "origin units {} from block {}; head update {n}: {} units, blocks {}..={} ({:?})",
            origin.units,
            origin.first_block(),
            head.units,
            head.first_block(),
            head.last_block(),
            t.elapsed()
        );
        let mut cursor = before;
        for p in 0..pages {
            let t = Instant::now();
            let page = index.page(&head, &address, cursor, limit, &myotis_addr1::client::Filter::default()).await.expect("page");
            println!("page {p}: {} entries, gaps {:?}, next {:?} ({:?})", page.entries.len(), page.gaps, page.next, t.elapsed());
            for e in &page.entries {
                println!("  block {} slot {} {}", e.block, e.slot, role::names(e.roles));
            }
            match page.next {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
    });
    node.shutdown(Duration::from_secs(5));
}
