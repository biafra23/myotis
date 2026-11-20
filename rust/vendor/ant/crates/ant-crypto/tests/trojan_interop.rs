//! Cross-implementation interop for PSS trojan chunks.
//!
//! `trojan_gen.jsonl` was produced by bee's own `pkg/pss` (Go) via the
//! `cmd/trojan-vectors` generator: each line is a real bee-wrapped trojan
//! chunk plus the recipient key and expected message. Unwrapping every
//! one in ant proves ant receives bee-originated PSS byte-for-byte.
//!
//! The test also re-wraps each message with ant and writes the result to
//! `../../../scratchpad/ant_pss_out.jsonl` (best-effort) so the reverse
//! direction — bee decrypting ant-produced chunks — can be checked with
//! `go run ./cmd/trojan-vectors check < ant_pss_out.jsonl` in the bee
//! tree. That direction is validated live in the e2e harness; here we
//! keep the offline half that needs no network.

use ant_crypto::act::{parse_public_key, public_key_of};
use ant_crypto::pss::{topic_from_string, unwrap, wrap, Recipient};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}
fn h32(s: &str) -> [u8; 32] {
    h(s).try_into().unwrap()
}

#[test]
fn unwraps_every_bee_produced_trojan_chunk() {
    let raw = include_str!("trojan_gen.jsonl");
    let mut n = 0;
    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let case = v["case"].as_str().unwrap();
        let topic = h32(v["topic_hex"].as_str().unwrap());
        let recipient_priv = h32(v["recipient_priv_hex"].as_str().unwrap());
        let data = h(v["chunk_data_hex"].as_str().unwrap());
        let want_msg = h(v["msg_hex"].as_str().unwrap());

        let got = unwrap(&recipient_priv, &data, &[topic])
            .unwrap_or_else(|| panic!("ant failed to unwrap bee chunk: {case}"));
        assert_eq!(got.0, topic, "topic mismatch on {case}");
        assert_eq!(got.1, want_msg, "message mismatch on {case}");
        // The vector's address must be the BMT hash ant computes for the
        // wire data — the binding a storer (and our pullsync delivery
        // vetting) enforces, not just the payload round-trip.
        let want_addr = h32(v["chunk_addr_hex"].as_str().unwrap());
        let (span, payload) = data.split_at(8);
        let addr = ant_crypto::bmt_hash_with_span(span.try_into().unwrap(), payload)
            .unwrap_or_else(|| panic!("bmt hash failed on {case}"));
        assert_eq!(addr, want_addr, "chunk address mismatch on {case}");
        n += 1;
    }
    assert!(n >= 60, "expected the full bee vector set, got {n}");
}

/// ant-wrapped chunks must round-trip through ant's own unwrap for both
/// recipient modes, across the same message-length matrix bee uses.
#[test]
fn ant_wrap_round_trips_all_modes() {
    let topics = ["test", "pss-demo"];
    let lengths = [0usize, 1, 32, 100, 4000];
    // A fixed recipient key (arbitrary valid 32-byte secret).
    let recipient_priv = h32("5c3f9a1d2e4b6c8d0f1a2b3c4d5e6f70819293a4b5c6d7e8f90a1b2c3d4e5f60");
    let recipient_pub = public_key_of(&recipient_priv).unwrap();

    for t in topics {
        let topic = topic_from_string(t);
        for len in lengths {
            let msg = vec![0x5au8; len];
            for recipient in [Recipient::Key(recipient_pub), Recipient::TopicDerived] {
                let secret = match &recipient {
                    Recipient::Key(_) => recipient_priv,
                    // topic-derived: any key can read; use an unrelated one.
                    Recipient::TopicDerived => {
                        h32("0909090909090909090909090909090909090909090909090909090909090909")
                    }
                };
                let (_addr, data) = wrap(&topic, &msg, &recipient, &[vec![0x5au8]]).unwrap();
                let got = unwrap(&secret, &data, &[topic]).expect("ant self round-trip");
                assert_eq!(got.1, msg, "len {len} topic {t}");
            }
        }
    }
}

/// Sanity: a bee "fixed" recipient public key parses and matches the
/// private key bee paired it with (guards against key-encoding drift).
#[test]
fn bee_fixed_recipient_key_consistency() {
    let raw = include_str!("trojan_gen.jsonl");
    let line = raw
        .lines()
        .find(|l| l.contains("\"recipient_mode\":\"fixed\""))
        .expect("a fixed-recipient vector");
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    let priv_hex = v["recipient_priv_hex"].as_str().unwrap();
    let pub_hex = v["recipient_pub_hex"].as_str().unwrap();
    let derived = public_key_of(&h32(priv_hex)).unwrap();
    let stated = parse_public_key(&h(pub_hex)).unwrap();
    assert_eq!(derived, stated);
}

/// Emit ant-wrapped chunks for bee's Go `check` tool. Run with:
///   `ANT_EMIT_PSS=1` cargo test -p ant-crypto --test `trojan_interop` `emit_ant`
/// then in the bee tree:
///   go run ./cmd/trojan-vectors check < `$TMPDIR/ant_pss_out.jsonl`
/// (override the output directory with `ANT_EMIT_PSS_DIR`).
#[test]
fn emit_ant_wrapped_for_bee_check() {
    if std::env::var("ANT_EMIT_PSS").is_err() {
        return;
    }
    use std::io::Write;
    let recipient_priv = h32("5c3f9a1d2e4b6c8d0f1a2b3c4d5e6f70819293a4b5c6d7e8f90a1b2c3d4e5f60");
    let recipient_pub = public_key_of(&recipient_priv).unwrap();
    // Write to the temp dir (or an explicit override), not into the
    // repo tree — the old repo-root `scratchpad/` wasn't gitignored and
    // the create panicked when the directory didn't exist.
    let dir = std::env::var("ANT_EMIT_PSS_DIR").unwrap_or_else(|_| {
        std::env::temp_dir()
            .to_str()
            .expect("temp dir is utf-8")
            .to_string()
    });
    let path = format!("{dir}/ant_pss_out.jsonl");
    let mut f = std::fs::File::create(&path).unwrap();
    for (i, (t, msg)) in [
        ("test", &b""[..]),
        ("pss-demo", &b"hi"[..]),
        ("test", &b"ant-to-bee interop message"[..]),
    ]
    .into_iter()
    .enumerate()
    {
        let topic = topic_from_string(t);
        let (addr, data) =
            wrap(&topic, msg, &Recipient::Key(recipient_pub), &[vec![0xa5u8]]).unwrap();
        let line = serde_json::json!({
            "case": format!("ant_{i}"),
            "topic_hex": hex::encode(topic),
            "recipient_priv_hex": hex::encode(recipient_priv),
            "msg_hex": hex::encode(msg),
            "chunk_addr_hex": hex::encode(addr),
            "chunk_data_hex": hex::encode(data),
        });
        writeln!(f, "{line}").unwrap();
    }
    eprintln!("wrote {path}");
}
