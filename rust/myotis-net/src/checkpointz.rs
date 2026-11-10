//! A fresh trust anchor from checkpoint-sync servers — the recovery a host may
//! offer at a `STALE_ANCHOR` park, next to "Sync anyway" (docs/how-it-works/zk-sync.md,
//! *Fresh checkpoint*).
//!
//! What Colibri does when it has no state is the same idea in its simplest
//! form: ask one checkpointz server for `/eth/v1/beacon/states/head/finality_checkpoints`
//! and trust the finalized root it names. This module asks EVERY configured
//! server and accepts a root only when servers of at least
//! [`MIN_AGREEING_OPERATORS`] distinct operators (registrable domains — two
//! hostnames of one operator are one voice) name the same finalized epoch and
//! root, and none names a different root for that epoch. That is the same gate
//! `./gradlew refreshCheckpoint` applies before it writes the embedded anchor.
//!
//! **Trust.** The root is NOT verified by this engine — it cannot be, that is
//! what an anchor is. It is the agreeing operators' word, exactly as the
//! embedded checkpoint is the release's word; everything after it (the
//! bootstrap Merkle-pinned to it, every later update BLS-verified) is verified
//! as usual. A host must present it to the user as that: "these N independent
//! servers agree the chain finalized this block".

use std::time::Duration;

use crate::https;

/// Distinct operators that must name the same finalized root.
pub const MIN_AGREEING_OPERATORS: usize = 2;

const FETCH_DEADLINE: Duration = Duration::from_secs(15);
const MAX_BODY: usize = 16 * 1024;

/// An agreed finalized checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshCheckpoint {
    /// The finalized checkpoint's block root.
    pub root: [u8; 32],
    pub epoch: u64,
    /// The epoch's first slot. The block at `root` is at this slot or, when it
    /// was skipped, an earlier one; only the sync-committee PERIOD derived from
    /// it is load-bearing, and the bootstrap reads the true slot from the
    /// header it verifies against `root`.
    pub slot: u64,
    /// The operators that agreed, for the host to show.
    pub operators: Vec<String>,
}

/// Ask every server and apply the agreement gate.
pub async fn fetch_agreed(servers: &[String], slots_per_epoch: u64) -> Result<FreshCheckpoint, String> {
    let futures = servers.iter().map(|base| async move {
        let url = format!("{}/eth/v1/beacon/states/head/finality_checkpoints", base.trim_end_matches('/'));
        let res = https::get(&url, "application/json", MAX_BODY, FETCH_DEADLINE).await;
        (base.clone(), res)
    });
    let mut answers = Vec::new();
    let mut failures = Vec::new();
    for (base, res) in futures::future::join_all(futures).await {
        match res {
            Ok(r) if r.status == 200 => match parse_finalized(&r.body) {
                Some((epoch, root)) => {
                    tracing::info!(server = %base, epoch, root = %hex(&root), "checkpointz answer");
                    answers.push(Answer { operator: operator_of(&base), epoch, root });
                }
                None => failures.push(format!("{base}: unparseable answer")),
            },
            Ok(r) => failures.push(format!("{base}: HTTP {}", r.status)),
            Err(e) => failures.push(format!("{base}: {e}")),
        }
    }
    for f in &failures {
        tracing::info!(failure = %f, "checkpointz server did not answer");
    }
    let (epoch, root, operators) = agree(&answers).map_err(|e| {
        if failures.is_empty() {
            e
        } else {
            format!("{e} (unreachable: {})", failures.join("; "))
        }
    })?;
    let slot = epoch.checked_mul(slots_per_epoch).ok_or("epoch overflows")?;
    Ok(FreshCheckpoint { root, epoch, slot, operators })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Answer {
    pub operator: String,
    pub epoch: u64,
    pub root: [u8; 32],
}

/// The newest (epoch, root) that at least [`MIN_AGREEING_OPERATORS`] operators
/// name. Any epoch for which two answers name DIFFERENT roots refuses the whole
/// round: one of them is lying or forked, and picking either would be a guess.
pub(crate) fn agree(answers: &[Answer]) -> Result<(u64, [u8; 32], Vec<String>), String> {
    for a in answers {
        if let Some(b) = answers.iter().find(|b| b.epoch == a.epoch && b.root != a.root) {
            return Err(format!(
                "servers disagree on epoch {}: {} says {}, {} says {}",
                a.epoch, a.operator, hex(&a.root), b.operator, hex(&b.root)
            ));
        }
    }
    let mut epochs: Vec<u64> = answers.iter().map(|a| a.epoch).collect();
    epochs.sort_unstable();
    epochs.dedup();
    for epoch in epochs.into_iter().rev() {
        let mut ops: Vec<String> = answers.iter().filter(|a| a.epoch == epoch).map(|a| a.operator.clone()).collect();
        ops.sort();
        ops.dedup();
        if ops.len() >= MIN_AGREEING_OPERATORS {
            let root = answers.iter().find(|a| a.epoch == epoch).map(|a| a.root).unwrap();
            return Ok((epoch, root, ops));
        }
    }
    Err(format!(
        "fewer than {MIN_AGREEING_OPERATORS} independent operators agree on a finalized checkpoint \
         ({} answered)",
        answers.len()
    ))
}

/// `https://a.b.example.org/...` → `example.org`: the voice a server counts as.
pub(crate) fn operator_of(base: &str) -> String {
    let host = base
        .trim_start_matches("https://")
        .split(['/', ':'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        host
    } else {
        labels[labels.len() - 2..].join(".")
    }
}

/// `data.finalized.{epoch, root}` from a `finality_checkpoints` answer. Parsed
/// by hand (the engine carries no JSON crate): the `finalized` key whose value
/// is an OBJECT — the top level has a boolean `"finalized": true` as well.
pub(crate) fn parse_finalized(body: &[u8]) -> Option<(u64, [u8; 32])> {
    let s = std::str::from_utf8(body).ok()?;
    let data = &s[s.find("\"data\"")?..];
    let mut rest = data;
    let obj = loop {
        let i = rest.find("\"finalized\"")?;
        let after = rest[i + "\"finalized\"".len()..].trim_start();
        let after = after.strip_prefix(':')?.trim_start();
        if let Some(obj) = after.strip_prefix('{') {
            break &obj[..obj.find('}')?];
        }
        rest = after;
    };
    let epoch: u64 = string_field(obj, "epoch")?.parse().ok()?;
    let root_hex = string_field(obj, "root")?;
    let root_hex = root_hex.strip_prefix("0x").unwrap_or(root_hex);
    if root_hex.len() != 64 {
        return None;
    }
    let mut root = [0u8; 32];
    for (i, b) in root.iter_mut().enumerate() {
        *b = u8::from_str_radix(&root_hex[2 * i..2 * i + 2], 16).ok()?;
    }
    (root != [0u8; 32]).then_some((epoch, root))
}

fn string_field<'a>(obj: &'a str, key: &str) -> Option<&'a str> {
    let k = format!("\"{key}\"");
    let after = obj[obj.find(&k)? + k.len()..].trim_start().strip_prefix(':')?.trim_start();
    let after = after.strip_prefix('"')?;
    Some(&after[..after.find('"')?])
}

fn hex(b: &[u8]) -> String {
    let mut s = String::from("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = r#"{"execution_optimistic":false,"finalized":true,"data":{"previous_justified":{"epoch":"10","root":"0x1111111111111111111111111111111111111111111111111111111111111111"},"current_justified":{"epoch":"11","root":"0x2222222222222222222222222222222222222222222222222222222222222222"},"finalized" : {"epoch":"9","root":"3333333333333333333333333333333333333333333333333333333333333333"}}}"#;

    #[test]
    fn parses_the_finalized_object_not_the_flag() {
        assert_eq!(parse_finalized(BODY.as_bytes()), Some((9, [0x33; 32])));
        assert_eq!(parse_finalized(b"{\"data\":{}}"), None);
        assert_eq!(parse_finalized(b"not json"), None);
    }

    fn a(op: &str, epoch: u64, r: u8) -> Answer {
        Answer { operator: op.into(), epoch, root: [r; 32] }
    }

    #[test]
    fn two_operators_must_agree() {
        assert!(agree(&[a("x.io", 5, 1)]).is_err());
        // Two hostnames of one operator are one voice.
        assert!(agree(&[a("x.io", 5, 1), a("x.io", 5, 1)]).is_err());
        assert_eq!(agree(&[a("x.io", 5, 1), a("y.io", 5, 1)]).unwrap(), (5, [1; 32], vec!["x.io".into(), "y.io".into()]));
    }

    #[test]
    fn the_newest_agreed_epoch_wins_and_a_lagging_server_is_not_a_conflict() {
        let got = agree(&[a("x.io", 6, 2), a("y.io", 5, 1), a("z.io", 5, 1)]).unwrap();
        assert_eq!((got.0, got.1), (5, [1; 32]));
        let got = agree(&[a("x.io", 6, 2), a("y.io", 6, 2), a("z.io", 5, 1)]).unwrap();
        assert_eq!((got.0, got.1), (6, [2; 32]));
    }

    #[test]
    fn any_conflict_refuses_the_round() {
        let err = agree(&[a("x.io", 5, 1), a("y.io", 5, 1), a("z.io", 5, 9)]).unwrap_err();
        assert!(err.contains("disagree"), "{err}");
    }

    #[test]
    fn operators_are_registrable_domains() {
        assert_eq!(operator_of("https://rpc-gbc.gnosischain.com"), "gnosischain.com");
        assert_eq!(operator_of("https://checkpoint.gnosischain.com/"), "gnosischain.com");
        assert_eq!(operator_of("https://beaconstate.info"), "beaconstate.info");
        assert_eq!(operator_of("https://mainnet.checkpoint.sigp.io:443/x"), "sigp.io");
    }
}
