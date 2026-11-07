//! LIVE cross-check of account reads answered from block access lists
//! (docs/how-it-works/address-activity.md, *Answering from block access lists*).
//!
//! Starts the Rust engine on a network whose blocks commit to a BAL (Sepolia
//! since Amsterdam), watches the senders of the latest block (busy accounts,
//! so their balances and nonces move while it runs), and reads them at
//! `latest` over and over. Each read the engine answered from its BALs
//! (`verifyMethod` `blockAccessList`) is compared field by field with an
//! `eth_getProof` at the SAME block, which is always a fresh snap proof.
//! A mismatch is a failure; so is a run in which no BAL answer carried a
//! change, since that would compare nothing a BAL applied.
//!
//! ```bash
//! cd rust
//! cargo run --release -p myotis-engine --example bal_follow_check -- sepolia 10
//! ```
//!
//! Arguments: the network (default `sepolia`) and the minutes to run
//! (default 10). It prints one line per compared read and a summary.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use myotis_engine::ffi;
use serde_json::Value;

fn main() {
    let mut args = std::env::args().skip(1);
    let network = args.next().unwrap_or_else(|| "sepolia".to_string());
    let minutes: u64 = args.next().and_then(|m| m.parse().ok()).unwrap_or(10);
    let dir = std::env::temp_dir().join(format!("myotis-bal-follow-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("data dir");
    let handle = ffi::create_handle(network.clone(), dir.to_string_lossy().into_owned());
    assert!(handle > 0, "create failed: {handle}");
    assert!(ffi::start_handle(handle), "start failed");
    println!("started {network} in {}", dir.display());

    // Synced once a head block reads verified, with its transactions.
    let started = Instant::now();
    let senders = loop {
        assert!(started.elapsed() < Duration::from_secs(900), "not synced within 15 minutes");
        std::thread::sleep(Duration::from_secs(5));
        let block: Value = serde_json::from_str(&ffi::get_block_by_number_json(handle, "latest".into(), true))
            .unwrap_or(Value::Null);
        let Some(txs) = block.get("transactions").and_then(Value::as_array) else { continue };
        let mut senders: Vec<String> = txs
            .iter()
            .filter_map(|tx| tx.get("from").and_then(Value::as_str).map(str::to_lowercase))
            .collect();
        senders.sort();
        senders.dedup();
        if senders.len() >= 3 {
            senders.truncate(16);
            break senders;
        }
    };
    println!("synced after {:?}; watching {} senders", started.elapsed(), senders.len());
    let push = serde_json::json!({ "watch": senders }).to_string();
    assert!(ffi::set_activity_watch(handle, push), "watch push refused");

    let deadline = Instant::now() + Duration::from_secs(minutes * 60);
    let (mut bal_answers, mut proven, mut compared, mut carried, mut mismatches, mut no_proof) = (0, 0, 0, 0, 0, 0);
    // Per address: the values of its last read, to tell a BAL answer that
    // carried a change from one that carried nothing.
    let mut last: HashMap<String, (String, String)> = HashMap::new();
    while Instant::now() < deadline {
        for address in &senders {
            let account: Value = serde_json::from_str(&ffi::request_account_json(handle, address.clone(), "latest".into()))
                .unwrap_or(Value::Null);
            let Some(method) = account.get("verifyMethod").and_then(Value::as_str) else { continue };
            let nonce = account["nonce"].as_i64().unwrap_or(-1).max(0);
            let balance = account["balanceWei"].as_str().unwrap_or("0").to_string();
            let previous = last.insert(address.clone(), (nonce.to_string(), balance.clone()));
            if method != "blockAccessList" {
                proven += 1;
                continue;
            }
            bal_answers += 1;
            let block = account["blockNumber"].as_u64().expect("blockNumber");
            let proof: Value = serde_json::from_str(&ffi::get_proof_json(
                handle,
                address.clone(),
                "[]".into(),
                format!("0x{block:x}"),
            ))
            .unwrap_or(Value::Null);
            if proof.get("accountProof").is_none() {
                no_proof += 1;
                println!("{address} @{block}: no proof to compare ({})", proof);
                continue;
            }
            let quantity = |v: &Value| u128::from_str_radix(v.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16).ok();
            let want_balance = quantity(&proof["balance"]).map(|b| b.to_string());
            let want_nonce = quantity(&proof["nonce"]).map(|n| n as i64);
            let same = want_balance.as_deref() == Some(balance.as_str())
                && want_nonce == Some(nonce)
                && proof["codeHash"].as_str() == account["codeHashHex"].as_str()
                && proof["storageHash"].as_str() == account["storageRootHex"].as_str();
            compared += 1;
            let changed = previous.is_some_and(|p| p != (nonce.to_string(), balance.clone()));
            if changed {
                carried += 1;
            }
            if same {
                println!("{address} @{block}: match (nonce {nonce}, balance {balance}{})", if changed { ", CARRIED A CHANGE" } else { "" });
            } else {
                mismatches += 1;
                println!("{address} @{block}: MISMATCH\n  bal:   {account}\n  proof: {proof}");
            }
        }
        std::thread::sleep(Duration::from_secs(6));
    }
    println!(
        "summary: {bal_answers} BAL answers, {proven} proven reads, {compared} compared, \
         {carried} carried a change, {mismatches} mismatches, {no_proof} without a proof to compare"
    );
    ffi::stop_handle(handle);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(mismatches, 0, "a BAL answer disagreed with a proof at its block");
    assert!(carried > 0, "no BAL answer carried a change: nothing a BAL applied was compared");
}
