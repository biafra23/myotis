//! A fresh trust anchor from checkpoint-sync servers — the recovery a host may
//! offer at a `STALE_ANCHOR` park, next to "Sync anyway" (docs/how-it-works/zk-sync.md,
//! *Fresh checkpoint*).
//!
//! What Colibri does when it has no state is the same idea in its simplest
//! form: ask one checkpointz server for `/eth/v1/beacon/states/head/finality_checkpoints`
//! and trust the finalized root it names. This module asks EVERY configured
//! server and accepts a root only when it is named by a strict majority of the
//! operators that answered, and by at least [`MIN_AGREEING_OPERATORS`]
//! (registrable domains — two hostnames of one operator are one voice); any two
//! answers naming different roots for one epoch refuse the round, and an
//! `execution_optimistic` answer does not count. `./gradlew refreshCheckpoint`
//! is stricter still (every responder must return the same root at one slot);
//! this gate tolerates a server one epoch behind, which a device asking at an
//! arbitrary moment routinely meets.
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
            // An optimistic node has not verified its own head: its finality
            // is not an answer.
            Ok(r) if r.status == 200 && is_optimistic(&r.body) => {
                failures.push(format!("{base}: execution_optimistic answer"))
            }
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

/// The (epoch, root) named by the most operators, accepted only when that is
/// at least [`MIN_AGREEING_OPERATORS`] AND a strict majority of all the
/// operators that answered. A lagging minority (a server one epoch behind) is
/// tolerated; a minority naming another epoch can never override the rest —
/// every answer votes against every other, not only those for the same epoch.
/// Any epoch for which two answers name DIFFERENT roots refuses the whole
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
    let mut all_ops: Vec<&str> = answers.iter().map(|a| a.operator.as_str()).collect();
    all_ops.sort_unstable();
    all_ops.dedup();
    let mut candidates: Vec<(u64, [u8; 32])> = answers.iter().map(|a| (a.epoch, a.root)).collect();
    candidates.sort_unstable();
    candidates.dedup();
    let support = |c: &(u64, [u8; 32])| {
        let mut ops: Vec<String> = answers
            .iter()
            .filter(|a| (a.epoch, a.root) == *c)
            .map(|a| a.operator.clone())
            .collect();
        ops.sort();
        ops.dedup();
        ops
    };
    // Most supporters first; among equals, the newer epoch.
    let best = candidates
        .iter()
        .map(|c| (c, support(c)))
        .max_by(|(ca, oa), (cb, ob)| oa.len().cmp(&ob.len()).then(ca.0.cmp(&cb.0)));
    match best {
        Some((c, ops)) if ops.len() >= MIN_AGREEING_OPERATORS && ops.len() * 2 > all_ops.len() => {
            Ok((c.0, c.1, ops))
        }
        Some((c, ops)) => Err(format!(
            "no finalized checkpoint has a majority: the best, epoch {}, is named by {} of {} \
             operators (needs at least {MIN_AGREEING_OPERATORS} and more than half) — servers \
             may be between epochs, try again in a minute",
            c.0,
            ops.len(),
            all_ops.len()
        )),
        None => Err("no checkpoint-sync server answered".into()),
    }
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

/// `"execution_optimistic": true` anywhere in the answer.
pub(crate) fn is_optimistic(body: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(body) else { return false };
    let Some(i) = s.find("\"execution_optimistic\"") else { return false };
    let after = s[i + "\"execution_optimistic\"".len()..].trim_start();
    after.strip_prefix(':').is_some_and(|v| v.trim_start().starts_with("true"))
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
    // Bytes, not str slices: a 64-byte root with a multi-byte character would
    // pass the length check and panic on a non-boundary slice (#761 review),
    // and from_str_radix would accept a sign ("+f").
    let root_hex = root_hex.strip_prefix("0x").unwrap_or(root_hex).as_bytes();
    if root_hex.len() != 64 || !root_hex.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let nibble = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
    let mut root = [0u8; 32];
    for (i, b) in root.iter_mut().enumerate() {
        *b = (nibble(root_hex[2 * i]) << 4) | nibble(root_hex[2 * i + 1]);
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

    #[test]
    fn a_root_that_is_not_ascii_hex_is_refused_not_sliced() {
        // 'a' + 'é' (2 bytes) + 61 ASCII digits = 64 bytes (#761 review).
        let body = format!(r#"{{"data":{{"finalized":{{"epoch":"1","root":"0xaé{}"}}}}}}"#, "0".repeat(61));
        assert_eq!(parse_finalized(body.as_bytes()), None);
        let signed = format!(r#"{{"data":{{"finalized":{{"epoch":"1","root":"0x+f{}"}}}}}}"#, "0".repeat(62));
        assert_eq!(parse_finalized(signed.as_bytes()), None);
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
    fn a_majority_wins_and_a_lagging_server_is_not_a_conflict() {
        let got = agree(&[a("x.io", 6, 2), a("y.io", 5, 1), a("z.io", 5, 1)]).unwrap();
        assert_eq!((got.0, got.1), (5, [1; 32]));
        let got = agree(&[a("x.io", 6, 2), a("y.io", 6, 2), a("z.io", 5, 1)]).unwrap();
        assert_eq!((got.0, got.1), (6, [2; 32]));
    }

    #[test]
    fn a_minority_naming_another_epoch_cannot_override_the_rest() {
        // #761 review: two operators at an epoch nobody else reports must not
        // win over seven at the epoch before.
        let mut answers: Vec<Answer> = (0..7).map(|i| a(&format!("h{i}.io"), 5, 1)).collect();
        answers.push(a("evil1.io", 6, 9));
        answers.push(a("evil2.io", 6, 9));
        let got = agree(&answers).unwrap();
        assert_eq!((got.0, got.1, got.2.len()), (5, [1; 32], 7));
        // Two of five is no majority, even when they are the only pair.
        let split = [a("v.io", 6, 2), a("w.io", 6, 2), a("x.io", 5, 1), a("y.io", 4, 3), a("z.io", 7, 4)];
        assert!(agree(&split).unwrap_err().contains("majority"));
    }

    #[test]
    fn optimistic_answers_are_recognised() {
        assert!(is_optimistic(br#"{"execution_optimistic": true,"data":{}}"#));
        assert!(!is_optimistic(BODY.as_bytes()));
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
