//! A fresh trust anchor from checkpoint-sync servers — the recovery a host may
//! offer at a `STALE_ANCHOR` park, next to "Sync anyway" (docs/how-it-works/zk-sync.md,
//! *Fresh checkpoint*).
//!
//! What Colibri does when it has no state is the same idea in its simplest
//! form: ask one checkpointz server for `/eth/v1/beacon/states/head/finality_checkpoints`
//! and trust the finalized root it names. This module asks EVERY configured
//! server and accepts a root only when the vote is UNANIMOUS: every server that
//! answers names the same finalized epoch and root, and they span at least
//! [`MIN_AGREEING_OPERATORS`] operators (registrable domains — two hostnames of
//! one operator are one voice). One differing answer — another root, another
//! epoch, an `execution_optimistic` node, an answer that does not parse — is
//! an alarm, not a vote to outweigh: the round is refused and the outliers are
//! named (owner's ruling on #761, 2026-11-11). Nothing retries on its own; the
//! user asks again. A server that does not answer at all (unreachable, an HTTP
//! error) names nothing and is only reported.
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
    let mut unusable = Vec::new();
    let mut silent = Vec::new();
    for (base, res) in futures::future::join_all(futures).await {
        match res {
            // An optimistic node has not verified its own head: what it calls
            // finalized is not an answer anyone may build on.
            Ok(r) if r.status == 200 && is_optimistic(&r.body) => {
                unusable.push(format!("{base} (execution_optimistic)"))
            }
            Ok(r) if r.status == 200 => match parse_finalized(&r.body) {
                Some((epoch, root)) => {
                    tracing::info!(server = %base, epoch, root = %hex(&root), "checkpointz answer");
                    answers.push(Answer { server: base.clone(), operator: operator_of(&base), epoch, root });
                }
                None => unusable.push(format!("{base} (unparseable answer)")),
            },
            Ok(r) => silent.push(format!("{base}: HTTP {}", r.status)),
            Err(e) => silent.push(format!("{base}: {e}")),
        }
    }
    for f in &silent {
        tracing::info!(failure = %f, "checkpointz server did not answer");
    }
    let verdict = agree(&answers, &unusable);
    if let Err(e) = &verdict {
        tracing::error!(reason = %e, "checkpointz: no fresh checkpoint — the servers do not agree");
    }
    let (epoch, root, operators) = verdict.map_err(|e| {
        if silent.is_empty() {
            e
        } else {
            format!("{e} (no answer from: {})", silent.join("; "))
        }
    })?;
    let slot = epoch.checked_mul(slots_per_epoch).ok_or("epoch overflows")?;
    Ok(FreshCheckpoint { root, epoch, slot, operators })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Answer {
    /// The server's base URL, as an outlier is named.
    pub server: String,
    pub operator: String,
    pub epoch: u64,
    pub root: [u8; 32],
}

/// A finalized checkpoint as a server names it: (epoch, block root).
type Checkpoint = (u64, [u8; 32]);

/// The unanimity gate. Accepted only when there is no unusable answer, every
/// answer names the same `(epoch, root)`, and the servers naming it span at
/// least [`MIN_AGREEING_OPERATORS`] operators. Otherwise refused, naming each
/// outlier: the servers outside the largest group, with what they named, or
/// every group when no group is the largest. A different ROOT for an epoch some
/// other server also names is called out on its own — that server, or the
/// others, is serving another chain.
pub(crate) fn agree(answers: &[Answer], unusable: &[String]) -> Result<(u64, [u8; 32], Vec<String>), String> {
    if !unusable.is_empty() {
        return Err(format!(
            "REFUSED: unusable answer from {} — no fresh checkpoint is trusted while any \
             server's answer cannot be checked against the others",
            unusable.join(", ")
        ));
    }
    if answers.is_empty() {
        return Err("REFUSED: no checkpoint-sync server answered".into());
    }
    let mut groups: Vec<(Checkpoint, Vec<&Answer>)> = Vec::new();
    for a in answers {
        match groups.iter_mut().find(|(k, _)| *k == (a.epoch, a.root)) {
            Some((_, members)) => members.push(a),
            None => groups.push(((a.epoch, a.root), vec![a])),
        }
    }
    if let [((epoch, root), members)] = groups.as_slice() {
        let mut ops: Vec<String> = members.iter().map(|a| a.operator.clone()).collect();
        ops.sort();
        ops.dedup();
        if ops.len() < MIN_AGREEING_OPERATORS {
            return Err(format!(
                "REFUSED: only {} answered ({}) — at least {MIN_AGREEING_OPERATORS} independent \
                 operators must agree",
                if ops.len() == 1 { "one operator".to_string() } else { format!("{} operators", ops.len()) },
                ops.join(", ")
            ));
        }
        return Ok((*epoch, *root, ops));
    }

    let describe = |(epoch, root): &Checkpoint| format!("epoch {epoch}, root {}", hex(root));
    let servers = |members: &[&Answer]| members.iter().map(|a| a.server.as_str()).collect::<Vec<_>>().join(", ");
    // Same epoch, different root: not lag, a fork or a lie.
    let conflict = groups.iter().any(|((e, r), _)| groups.iter().any(|((e2, r2), _)| e == e2 && r != r2));
    let headline = if conflict {
        "REFUSED — ALARM: checkpoint-sync servers name DIFFERENT roots for the same finalized \
         epoch; one side is serving another chain"
    } else {
        "REFUSED: checkpoint-sync servers do not all name the same finalized checkpoint"
    };
    groups.sort_by_key(|g| std::cmp::Reverse(g.1.len()));
    let largest = groups[0].1.len();
    if groups.iter().filter(|(_, m)| m.len() == largest).count() == 1 {
        let (key, members) = &groups[0];
        let outliers: Vec<String> = groups[1..]
            .iter()
            .map(|(k, m)| format!("{} ({})", servers(m), describe(k)))
            .collect();
        Err(format!(
            "{headline}. Outlier{}: {} — against {} server{} naming {}",
            if outliers.len() == 1 { "" } else { "s" },
            outliers.join("; "),
            members.len(),
            if members.len() == 1 { "" } else { "s" },
            describe(key)
        ))
    } else {
        let all: Vec<String> = groups.iter().map(|(k, m)| format!("{} ({})", servers(m), describe(k))).collect();
        Err(format!("{headline}, and no side has more servers. Answers: {}", all.join("; ")))
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
        Answer { server: format!("https://cp.{op}"), operator: op.into(), epoch, root: [r; 32] }
    }

    #[test]
    fn a_unanimous_vote_of_two_operators_is_accepted() {
        assert_eq!(
            agree(&[a("x.io", 5, 1), a("y.io", 5, 1)], &[]).unwrap(),
            (5, [1; 32], vec!["x.io".into(), "y.io".into()])
        );
    }

    #[test]
    fn one_operator_is_not_enough() {
        assert!(agree(&[a("x.io", 5, 1)], &[]).unwrap_err().contains("one operator"));
        // Two hostnames of one operator are one voice.
        assert!(agree(&[a("x.io", 5, 1), a("x.io", 5, 1)], &[]).is_err());
        assert!(agree(&[], &[]).unwrap_err().contains("no checkpoint-sync server answered"));
    }

    #[test]
    fn a_single_differing_server_refuses_the_round_and_is_named() {
        // Eight agree, one names the next epoch: refused, the one named.
        let mut answers: Vec<Answer> = (0..8).map(|i| a(&format!("h{i}.io"), 5, 1)).collect();
        answers.push(a("odd.io", 6, 2));
        let err = agree(&answers, &[]).unwrap_err();
        assert!(err.starts_with("REFUSED:"), "{err}");
        assert!(err.contains("Outlier: https://cp.odd.io (epoch 6"), "{err}");
        assert!(err.contains("against 8 servers naming epoch 5"), "{err}");
        assert!(!err.contains("ALARM"), "an epoch apart is not a root conflict: {err}");
        // A server one epoch BEHIND differs just the same.
        let mut answers: Vec<Answer> = (0..8).map(|i| a(&format!("h{i}.io"), 5, 1)).collect();
        answers.push(a("slow.io", 4, 3));
        assert!(agree(&answers, &[]).unwrap_err().contains("Outlier: https://cp.slow.io (epoch 4"));
    }

    #[test]
    fn a_different_root_for_the_same_epoch_is_an_alarm() {
        let err = agree(&[a("x.io", 5, 1), a("y.io", 5, 1), a("z.io", 5, 9)], &[]).unwrap_err();
        assert!(err.contains("ALARM"), "{err}");
        assert!(err.contains("Outlier: https://cp.z.io (epoch 5, root 0x0909"), "{err}");
    }

    #[test]
    fn a_tie_names_every_side() {
        let err = agree(&[a("w.io", 5, 1), a("x.io", 5, 1), a("y.io", 6, 2), a("z.io", 6, 2)], &[]).unwrap_err();
        assert!(err.contains("no side has more servers"), "{err}");
        assert!(err.contains("https://cp.w.io, https://cp.x.io (epoch 5") && err.contains("https://cp.y.io, https://cp.z.io (epoch 6"), "{err}");
    }

    #[test]
    fn an_unusable_answer_refuses_even_a_unanimous_rest() {
        let err = agree(
            &[a("x.io", 5, 1), a("y.io", 5, 1)],
            &["https://cp.z.io (execution_optimistic)".into()],
        )
        .unwrap_err();
        assert!(err.contains("unusable answer from https://cp.z.io (execution_optimistic)"), "{err}");
    }

    #[test]
    fn optimistic_answers_are_recognised() {
        assert!(is_optimistic(br#"{"execution_optimistic": true,"data":{}}"#));
        assert!(!is_optimistic(BODY.as_bytes()));
    }

    #[test]
    fn operators_are_registrable_domains() {
        assert_eq!(operator_of("https://rpc-gbc.gnosischain.com"), "gnosischain.com");
        assert_eq!(operator_of("https://checkpoint.gnosischain.com/"), "gnosischain.com");
        assert_eq!(operator_of("https://beaconstate.info"), "beaconstate.info");
        assert_eq!(operator_of("https://mainnet.checkpoint.sigp.io:443/x"), "sigp.io");
    }
}
