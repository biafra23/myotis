//! Look up a node's record in the public discv5 DHT, from an ephemeral client.
//!
//! This is the inbound-UDP verifier the roost README §Ports asks for: a node
//! only enters OTHER nodes' routing tables after they complete the endpoint
//! proof against it (an exchange THEY initiate, inbound). So if third-party
//! peers hand back the target's ENR, inbound UDP demonstrably works — even
//! when this probe runs on the same LAN, because the records come from the
//! remote peers' tables, not from the target.
//!
//!   cargo run --release --example enr_lookup -- <network> <target-enr>
//!
//! Exit 0 and `FOUND seq=N` when third-party tables serve the record;
//! exit 1 with `NOT FOUND` when they don't (yet — propagation takes minutes).

use discv5::enr::{CombinedKey, Enr, NodeId};
use myotis_net::sync::ChainConfig;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let (net, target) = match (args.next(), args.next()) {
        (Some(n), Some(t)) => (n, t),
        _ => {
            eprintln!("usage: enr_lookup <mainnet|sepolia|gnosis> <target-enr>");
            std::process::exit(2);
        }
    };
    let target_enr: Enr<CombinedKey> = target.parse().expect("target is not a valid ENR");
    let target_id: NodeId = target_enr.node_id();
    let published_seq = target_enr.seq();

    let config = match net.as_str() {
        "mainnet" => ChainConfig::mainnet(),
        "sepolia" => ChainConfig::sepolia(),
        "gnosis" => ChainConfig::gnosis(),
        other => {
            eprintln!("unknown network {other}");
            std::process::exit(2);
        }
    };

    // Ephemeral client identity on a random port: this probe must NOT look
    // like roost itself, or peers could answer from a session rather than
    // from their tables.
    let key = CombinedKey::generate_secp256k1();
    let enr = Enr::builder().build(&key).unwrap();
    let discv5_config = discv5::ConfigBuilder::new(discv5::ListenConfig::Ipv4 {
        ip: "0.0.0.0".parse().unwrap(),
        port: 0,
    })
    .build();
    let mut discv5: discv5::Discv5 = discv5::Discv5::new(enr, key, discv5_config).unwrap();

    let mut seeded = 0;
    for enr_str in &config.bootstrap_enrs {
        if let Ok(e) = enr_str.parse::<Enr<CombinedKey>>() {
            // NEVER seed the target: the bootstrap lists now carry roost's own
            // record, and a FOUND satisfied by the target vouching for itself
            // proves inbound UDP but not what this tool claims — that THIRD
            // PARTIES hand its record back from their tables. Same reason the
            // direct-endpoint probe runs AFTER the walk: it opens a session
            // that tables the target locally.
            if e.node_id() == target_id {
                continue;
            }
            if discv5.add_enr(e).is_ok() {
                seeded += 1;
            }
        }
    }
    eprintln!("[{net}] seeded {seeded} bootnodes (target excluded); looking up {target_id}");
    discv5.start().await.expect("discv5 start");

    // find_node toward the target id walks the DHT via third parties. A few
    // rounds, because propagation after a fresh publication takes time.
    for round in 1..=5 {
        match discv5.find_node(target_id).await {
            Ok(found) => {
                if let Some(hit) = found.iter().find(|e| e.node_id() == target_id) {
                    println!(
                        "FOUND seq={} (published seq={}) ip={:?} udp={:?} — inbound UDP verified by third-party tables",
                        hit.seq(),
                        published_seq,
                        hit.ip4(),
                        hit.udp4()
                    );
                    std::process::exit(0);
                }
                eprintln!(
                    "[round {round}] {} records, target not among them",
                    found.len()
                );
            }
            Err(e) => eprintln!("[round {round}] find_node failed: {e}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
    // Failure diagnostic, deliberately LAST (it would pollute the walk's
    // verdict): a direct FINDNODE(0) at the target's advertised endpoint.
    // Success here with NOT FOUND above means inbound UDP works but the record
    // has not propagated yet; failure here too points at the endpoint itself
    // (router forward, dead address in the record).
    match discv5
        .find_node_designated_peer(target_enr.clone(), vec![0])
        .await
    {
        Ok(returned) => eprintln!(
            "[direct] session ESTABLISHED with the advertised endpoint; it returned {} record(s), seq={:?}",
            returned.len(),
            returned.first().map(|e| e.seq())
        ),
        Err(e) => eprintln!("[direct] session FAILED against the advertised endpoint: {e}"),
    }
    println!("NOT FOUND — record not in third-party tables (yet)");
    std::process::exit(1);
}
