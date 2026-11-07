# myotis-wire: the protocols as pure functions

*Stop 5 · crate `myotis-wire`* · 25 files · 5,821 lines · about 2½ hours

Every byte Myotis sends to or reads from a peer is shaped here: discv4 packets, the RLPx handshake and its encrypted frames, the eth and snap messages, the proofs that make a snap answer trustworthy, and the eth2 req/resp framing. None of it opens a socket, reads a clock or draws a random number. The crate was split out of `myotis-net` so that a host without tokio (firmware, a browser, a blocking client) can drive the same code. Along the way you will see how one crate builds with and without the standard library, and how a decoder can read a 10 MiB peer message without copying it.

## Rust you will practise

- **Features and `cfg`** — `#![cfg_attr(not(feature = "std"), no_std)]`, optional dependencies, and `#[cfg]` blocks that pick one of two function bodies at compile time.
- **Borrowed views** — `rlp::View<'a>`, `Cow<'_, RawList>` and slices that point into the caller's buffer, so a peer's message is checked and read in place.
- **State only `&mut` can advance** — the frame codec's keystreams, `split(self)` into two owned halves, and a handshake struct that borrows its key.

## Why a crate with no I/O

Until issue #505 this code lived inside `myotis-net`, mixed in with the tokio tasks that drive it. It was already written “sans-I/O”: the codecs took entropy and time as parameters, and only a few service types touched sockets. The split made that a crate boundary. `myotis-wire` has no tokio, no sockets, no clock and no entropy. A caller passes in every random value (the ECIES ephemeral key, the IV, the EIP-8 padding) and every timestamp (a discv4 expiry). In return it gets plain functions from bytes to bytes or to typed values.

Two things follow. First, the crate builds as `no_std` + `alloc` with `--no-default-features`: it needs a heap allocator, but no operating system. The Gradle task `cargoBuildNoStd` proves it by building for `x86_64-unknown-none`, a target that has no `std` at all, and `cargoCheckWasm` checks it for `wasm32-unknown-unknown`. Second, `myotis-net` keeps working unchanged: it depends on `myotis-wire` and re-exports each moved module at its old path through tiny shim files, which you meet at the end of this stop.

![Dependency graph. myotis-net, which owns tokio, sockets and OS entropy, and any other host with its own event loop both depend on myotis-wire. myotis-net re-exports it at the old paths. myotis-wire depends on myotis-core always, and on myotis-consensus, and through it myotis-bls and the blst C library, only with the eth2 feature.](img/05-wire-1.svg)

*Arrows point from a crate to what it depends on. Dashed: optional.*

### Where each part goes

| Module | What it does | Driven by (in `myotis-net`) |
|---|---|---|
| `discv4` | Sign, hash and parse discovery packets; decode Neighbors, Pong, ENR replies. | `el::discv4::Discv4Service` (stop 11) |
| `rlpx` | ECIES, the EIP-8 auth/ack handshake, the encrypted frame codec, the p2p Hello. | `el::rlpx::transport` (stop 11) |
| `eth` | eth/66–71 messages: Status, headers, bodies, receipts, transaction gossip. | `el::eth::session`, `el::peer` |
| `snap` | snap/1 and snap/2 messages, and verification of their Merkle proofs. | `el::peer`, `el::reader` (stop 14) |
| `snappy` | Snappy raw and framed formats: the `snap` crate with `std`, a built-in codec without. | used inside this crate |
| `eth2` | Consensus-layer req/resp framing, `Status`/`MetaData`, fork digests, protocol ids. | `reqresp`, `sync` (stops 9–10); also `roost` |

> [!TIP]
> **What changed since September**In the old tour these files were part of `myotis-net` (stops 7 and 9 of that edition). Besides the move, three changes run through them. Peer messages are now read in place through `rlp::View` and stored in `RawList` instead of being decoded into owned trees (#454). The eth side gained eth/70 (receipts that continue across responses) and eth/71 (block access lists), and snap gained snap/2. Snappy goes through the new `snappy` module, and `hello.rs` was cut out of the RLPx transport.

> [!NOTE]
> **Java/Kotlin**In the Java engine these are classes in `com.jaeckel.ethp2p.networking.*` that are mostly static encoders plus Netty handlers. The Rust side keeps the encoders apart from the event loop on purpose: a Netty `ChannelHandler` is tied to Netty, while a function from `&[u8]` to `Result<T, E>` runs anywhere.

## The crate manifest

The manifest is the best summary of the design. Read the feature table first.

`rust/myotis-wire/Cargo.toml` · lines 17–27

```toml
[features]
default = ["std", "eth2"]
std = ["myotis-core/std", "myotis-consensus?/std", "tracing?/std", "dep:snap"]
# The consensus-layer req/resp wire (eth2::{codec, status, protocols}). It is
# the only part that needs myotis-consensus -- and through it myotis-bls and the
# blst C library -- so an execution-layer-only host (discv4, RLPx, eth, snap)
# can turn it off and skip cross-compiling blst.
eth2 = ["dep:myotis-consensus", "dep:tracing"]
# `SessionSecrets::test_pair` for other crates' tests (myotis-net's frame/session tests).
test-util = []

```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Features are additive switches.** `default = ["std", "eth2"]` is what you get unless a dependent writes `default-features = false`. A feature can turn on features of dependencies (`"myotis-core/std"`) and optional dependencies (`"dep:snap"`). The question mark in `"myotis-consensus?/std"` means “turn on `std` in that crate *if* it is already enabled for another reason”, so `std` alone does not drag in the consensus crate.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Protocol & domain](01-primer.md#primer-domain)* **Why `eth2` is optional.** The consensus wire needs a few SSZ helpers from `myotis-consensus`, which depends on `myotis-bls`, which compiles the `blst` C library. An execution-layer-only host can switch `eth2` off and avoid cross-compiling C for its target. The no\_std canary builds exactly that combination: no `std`, no `eth2`.
- *[Tests](01-primer.md#primer-testing) · [Crates, modules & features](01-primer.md#primer-modules-cargo)* `test-util` exposes test helpers to *other* crates. `#[cfg(test)]` code is only compiled for this crate's own tests, so `myotis-net`'s tests could not see it. `myotis-net` turns `test-util` on in its `[dev-dependencies]` only, so production builds never contain the helpers. The comment names `SessionSecrets::test_pair`; the feature also gates `discv4::encode_packet_for_test`.

`rust/myotis-wire/Cargo.toml` · lines 28–41

```toml
[dependencies]
myotis-core = { path = "../myotis-core", default-features = false }
# eth2 status/fork-digest SSZ helpers.
myotis-consensus = { path = "../myotis-consensus", default-features = false, optional = true }
# Diagnostics in the eth2 multi-chunk decoder (I/O-free facade).
tracing = { version = "=0.1.44", default-features = false, optional = true }
aes = { version = "=0.8.4", default-features = false }
ctr = { version = "=0.9.2", default-features = false }
cipher = { version = "=0.4.4", default-features = false }
hmac = { version = "=0.12.1", default-features = false }
sha2 = { version = "=0.10.9", default-features = false }
sha3 = { version = "=0.10.9", default-features = false }
subtle = { version = "=2.6.1", default-features = false }
snap = { version = "=1.1.1", optional = true }
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* Every dependency is pinned with `=` and has `default-features = false`. Most RustCrypto crates turn on `std` by default; leaving one default on would pull `std` into a no\_std build and fail only on the canary. `snap` is the exception: it needs `std`, so it is optional and enabled only by this crate's `std` feature. The remaining lines of the manifest (43–48) force the software SHA-2 backend on bare-metal targets, where the SSE-enabling code cannot be compiled.

> [!WARNING]
> **Stale or inaccurate comments**The manifest says that on bare-metal targets you must build “with `RUSTFLAGS="--cfg aes_force_soft"` (the no\_std canary does…)”. The canary does not set `RUSTFLAGS`. The flag comes from per-target `rustflags` entries in `rust/.cargo/config.toml`, whose own comment says it was put there “rather than RUSTFLAGS in CI”. The effect is the same for builds inside the repo; an embedder building from outside it still has to set the cfg.

<a id="f-myotis-wire-src-lib-rs"></a>

### myotis-wire/src/lib.rs

*crate root · 28 lines*

The crate root: a doc comment that lists the five protocol areas, the `no_std` switch, and the module list. Only `eth2` is behind a feature.

`rust/myotis-wire/src/lib.rs` · lines 18–28

```rust
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod discv4;
pub mod eth;
#[cfg(feature = "eth2")]
pub mod eth2;
pub mod rlpx;
pub mod snap;
pub mod snappy;
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **A conditional crate attribute.** `cfg_attr(condition, attribute)` applies the attribute only when the condition holds. Without the `std` feature the crate is `#![no_std]`: the implicit `extern crate std` disappears and the prelude becomes `core`'s, which has no heap types.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **`extern crate alloc;`** brings in the crate that defines `Vec`, `String`, `Box` and `format!`. It needs no operating system, only a global allocator that the final binary provides. With `std` on, these are the very same types: `std::vec::Vec` is a re-export of `alloc::vec::Vec`.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* Every source file starts with the same line, `#[allow(unused_imports)] use alloc::{borrow::ToOwned, format, string::{String, ToString}, vec, vec::Vec};`. In a no\_std build those names are not in scope without it. Each file copies the whole list, and not every file uses every name, so the `allow` silences the warnings for the unused ones.

<a id="f-myotis-wire-src-snappy-rs"></a>

### myotis-wire/src/snappy.rs

*library · 444 lines*

New since the old tour. Snappy is the compression both peer-to-peer stacks use: RLPx compresses each message with the *raw* format, and eth2 req/resp uses the *framed* format (a stream identifier, then checksummed chunks). With `std`, every function here forwards to the `snap` crate, exactly what `myotis-net` used before. Without `std` (the `snap` crate needs it) a small in-house codec takes over: a complete raw decoder, a literal-only raw encoder, and a framed encoder and decoder that write uncompressed chunks.

| Lines | What happens |
|---|---|
| 1–57 | Raw format: `compress`, `decompress_len`, `decompress`, each with a `std` and a built-in body. |
| 59–186 | Framed format: `compress_framed`, `decompress_framed`, bitwise CRC-32C, and the built-in framed codec with `snap`'s acceptance rules. |
| 188–294 | Varint, the literal-only encoder, and the full raw decoder. |
| 296–444 | Tests (with `std` only): the built-in codec against `snap` in both directions, plus a property test. |

`rust/myotis-wire/src/snappy.rs` · lines 15–37

```rust
/// Compress `input`.
pub fn compress(input: &[u8]) -> Vec<u8> {
    #[cfg(feature = "std")]
    {
        snap::raw::Encoder::new().compress_vec(input).unwrap_or_else(|_| input.to_vec())
    }
    #[cfg(not(feature = "std"))]
    {
        compress_literal(input)
    }
}

/// The decoded length a payload declares, without decoding it.
pub fn decompress_len(input: &[u8]) -> Option<usize> {
    #[cfg(feature = "std")]
    {
        snap::raw::decompress_len(input).ok()
    }
    #[cfg(not(feature = "std"))]
    {
        read_varint(input).map(|(n, _)| n)
    }
}
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Two bodies, one survives.** `#[cfg]` works on blocks inside a function as well as on items. After configuration only one of the two blocks remains, and it becomes the function's tail expression. That is how one signature gets two implementations with no runtime `if` and no trait.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `compress` cannot fail in its signature. In the `std` body, `unwrap_or_else(|_| input.to_vec())` turns `snap`'s error into an uncompressed copy. `decompress_len` turns the error into `None` with `.ok()`.
- *[Protocol & domain](01-primer.md#primer-domain)* **A literal-only encoder is still valid Snappy.** Snappy output is a sequence of “literal” (copy these bytes) and “copy” (repeat earlier output) elements. An encoder that emits only literals never compresses, but every decoder accepts it. The doc comment argues that a light client's outgoing RLPx messages are a few hundred bytes, so the lost ratio does not matter, and having no match-finder leaves nothing to get wrong.

`rust/myotis-wire/src/snappy.rs` · lines 81–98

```rust
/// Decompress a framed stream, producing at most `limit` bytes (the caller
/// passes declared+1 to detect overrun). The error carries the reason.
pub fn decompress_framed(input: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    #[cfg(feature = "std")]
    {
        use std::io::Read;
        let mut out = Vec::with_capacity(limit.min(1 << 20));
        snap::read::FrameDecoder::new(input)
            .take(limit as u64)
            .read_to_end(&mut out)
            .map_err(|e| e.to_string())?;
        Ok(out)
    }
    #[cfg(not(feature = "std"))]
    {
        decompress_framed_builtin(input, limit)
    }
}
```

- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* **Readers stack like Java `InputStream` wrappers.** `&[u8]` implements `Read`, `FrameDecoder` decompresses it, `.take(n)` caps it at `limit` bytes, and `read_to_end` fills a `Vec`. The `use std::io::Read;` sits inside the block, because the trait (and `std` itself) only exists in that configuration.
- *[Protocol & domain](01-primer.md#primer-domain)* `limit` is how the eth2 codec bounds memory: it passes the declared length plus one (see [eth2/codec.rs](#f-myotis-wire-src-eth2-codec-rs)). The initial capacity is capped at 1 MiB, so a large declared limit does not allocate up front. The built-in framed decoder applies the same limit, and also refuses a chunk with more than 64 KiB of uncompressed data, as `snap` does.

`rust/myotis-wire/src/snappy.rs` · lines 258–294

```rust
            kind => {
                let (l, off) = match kind {
                    1 => {
                        let b = *input.get(pos)? as usize;
                        pos += 1;
                        (4 + ((tag >> 2) & 0x07) as usize, (((tag >> 5) as usize) << 8) | b)
                    }
                    2 => {
                        let b = input.get(pos..pos.checked_add(2)?)?;
                        pos += 2;
                        (1 + (tag >> 2) as usize, u16::from_le_bytes([b[0], b[1]]) as usize)
                    }
                    _ => {
                        let b = input.get(pos..pos.checked_add(4)?)?;
                        pos += 4;
                        (1 + (tag >> 2) as usize, u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
                    }
                };
                if off == 0 || off > out.len() {
                    return None;
                }
                if out.len().checked_add(l)? > len {
                    return None;
                }
                let start = out.len() - off;
                for i in 0..l {
                    let b = out[start + i];
                    out.push(b);
                }
            }
        }
        if out.len() > len {
            return None;
        }
    }
    (out.len() == len).then_some(out)
}
```

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* This is the “copy” half of the built-in raw decoder: repeat `l` bytes starting `off` bytes back in the output. The obvious line, `out.extend_from_slice(&out[start..start + l])`, does not compile: it borrows `out` immutably (the slice) and mutably (the push) at the same time, error E0502. It would also be wrong, because in Snappy a copy may overlap its own output (`l > off`, for example “repeat the last byte 20 times”). The byte loop handles both: `let b = out[start + i];` copies one `u8` (a `Copy` type), so the immutable borrow ends on that line, and `out.push(b)` then has `out` to itself. `start + i` is always below `out.len()`, because the vector grows by one each round.

- *[Result, ? and panics](01-primer.md#primer-error-handling)* **`?` on `Option`.** The function returns `Option<Vec<u8>>`, so `input.get(pos)?` and `pos.checked_add(2)?` return `None` early, like Kotlin's `?: return null`. `get` instead of indexing and `checked_add` instead of `+` mean a hostile input yields `None`, never a panic or an overflow. The earlier literal arm (lines 242–257) does the same, and the function refuses a declared length above `max` before it allocates anything.
- *[Ownership & moves](01-primer.md#primer-ownership)* `(out.len() == len).then_some(out)` moves `out` into `Some` when the length is exactly right, and drops it otherwise.

*[Tests](01-primer.md#primer-testing)* The built-in codec runs in no production build that has `std`, so the tests are its only exercise on a normal machine. They run it against `snap` both ways. The property test `builtin_raw_decoder_agrees_with_snap_or_refuses` feeds 3,000 random inputs and many mutated `snap` encodings, generated with a deterministic xorshift so a failure reproduces, and asserts that the built-in decoder either returns what `snap` returns or returns `None`. The `let mut next = move || { … }` closure owns its state `x` and mutates it, which makes it an `FnMut`.

> [!WARNING]
> **Stale or inaccurate comments**The module's first line calls it “Snappy *raw* format (no framing) for RLPx message payloads”. Lines 59–186 implement the framed format for eth2 req/resp as well.

<a id="f-myotis-wire-src-discv4-rs"></a>

### myotis-wire/src/discv4.rs

*library · 292 lines · Java twin · networking.discv4*

The discv4 packet codec, moved out of `myotis-net::el::discv4`. A packet is `hash(32) ‖ signature(65) ‖ type(1) ‖ RLP data`. The file has encoders for Ping, Pong, FindNode, and the EIP-868 ENR request and response, and decoders for what comes back. The Kademlia routing table, the ping rate limiter and the UDP service stayed in `myotis-net` ([stop 11](11-el-transport.md)), which re-exports this module with `pub use myotis_wire::discv4::*;`.

`rust/myotis-wire/src/discv4.rs` · lines 174–194

```rust
/// Parse and verify an inbound packet: hash check, then sender recovery.
pub fn parse(packet: &[u8]) -> Result<Parsed, CoreError> {
    if packet.len() < 98 {
        return Err(CoreError(format!("Packet too short: {}", packet.len())));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&packet[..32]);
    if keccak256(&packet[32..]) != hash {
        return Err(CoreError("Packet hash mismatch".into()));
    }
    let mut sig = [0u8; 65];
    sig.copy_from_slice(&packet[32..97]);
    let msg_hash = keccak256(&packet[97..]); // type ‖ data
    let sender_pubkey = recover_public_key(&msg_hash, &sig)?;
    Ok(Parsed {
        hash,
        packet_type: packet[97],
        data: packet[98..].to_vec(),
        sender_pubkey,
    })
}
```

- *[Protocol & domain](01-primer.md#primer-domain)* **Two hashes, two jobs.** The leading hash covers everything after it and only detects corruption. The signature covers `type ‖ data`, and recovering the public key from it gives the sender's node id. There is no separate “from” field to trust: the identity is whatever key signed the packet.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Borrowing & slices](01-primer.md#primer-borrowing)* The length check at the top makes every fixed range below safe to index. `copy_from_slice` copies into stack arrays (`[u8; 32]`, `[u8; 65]`); it panics on a length mismatch, which the ranges rule out. `packet[98..].to_vec()` is the one heap copy: `Parsed` owns its data, so the caller's receive buffer can be reused at once.

`rust/myotis-wire/src/discv4.rs` · lines 255–280

```rust
for node in nodes {
    let fields = match node.as_list() {
        Ok(f) if f.len() >= 4 => f,
        _ => break, // malformed entry → stop, keep what we have (Java parity)
    };
    let (Ok(ip), Ok(udp), Ok(tcp), Ok(node_id)) = (
        fields[0].as_bytes(),
        read_u32(&fields[1]),
        read_u32(&fields[2]),
        fields[3].as_bytes(),
    ) else {
        break; // field-level RLP type errors also stop the walk
    };
    // Java skips a node whose InetAddress/InetSocketAddress construction
    // throws: wrong ip length or udp port > 65535.
    if !(ip.len() == 4 || ip.len() == 16) || udp > 65535 {
        continue;
    }
    peers.push(DiscoveredPeer {
        ip: ip.to_vec(),
        udp_port: udp as u16,
        tcp_port: tcp,
        node_id: node_id.to_vec(),
    });
}
Ok(peers)
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* **`let … else`.** `let (Ok(ip), Ok(udp), Ok(tcp), Ok(node_id)) = (…) else { break; };` builds a tuple of four `Result`s and binds all four values only if every one is `Ok`. Otherwise the `else` block runs, and it must leave the scope (`break`, `continue`, `return`). It reads like a guard clause in Kotlin, but it also destructures.
- *[Protocol & domain](01-primer.md#primer-domain)* **Java's leniency, reproduced.** A structurally broken entry stops the walk and keeps the nodes so far (`break`). An entry with a wrong IP length or a UDP port above 65535 is skipped (`continue`), because that is where Java's `InetAddress` construction throws. The cross-language corpus in `rust/testdata/el/discv4/` pins this behaviour.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `udp as u16` is a truncating cast, safe here only because the line above already rejected values over 65535.

*[Tests](01-primer.md#primer-testing) · [Crates, modules & features](01-primer.md#primer-modules-cargo)* `encode_packet` is private: this client never sends Neighbors, so it has no public encoder for it. Tests that play the peer's side need one, so `encode_packet_for_test` exists under `#[cfg(any(test, feature = "test-util"))]`. `myotis-net`'s discv4 tests import it under its real name with `use … as encode_packet`.

> [!WARNING]
> **Stale or inaccurate comments**The module doc, copied from the `myotis-net` original, says “The packet codec, Kademlia table, and rate limiter are pure … pinned by the … corpus”. Only the codec is in this file; `KademliaTable` and `PingRateLimiter` are still in `myotis-net/src/el/discv4.rs`. The file also ends with an orphaned `// ----` separator on line 292, where the original went on to the Kademlia section.

<a id="f-myotis-wire-src-rlpx-mod-rs"></a>

### myotis-wire/src/rlpx/mod.rs

*module index · 7 lines · Java twin · networking.rlpx*

Declares the four RLPx modules: `ecies`, `handshake`, `frame` and `hello`. RLPx is the encrypted TCP transport under the eth and snap protocols. Only the initiator side exists, as in the Java reference. The doc comment states the contract: “the caller owns the socket and the entropy”. The tokio dialer that does own them is `myotis-net/src/el/rlpx/transport.rs` ([stop 11](11-el-transport.md)).

<a id="f-myotis-wire-src-rlpx-ecies-rs"></a>

### myotis-wire/src/rlpx/ecies.rs

*library · 185 lines · Java twin · EciesCodec*

ECIES encryption for the handshake's auth and ack messages: `0x04 ‖ ephemeral pubkey ‖ IV ‖ ciphertext ‖ MAC`, with a concat-KDF over SHA-256 (counter first), AES-128-CTR, and `HMAC-SHA256(SHA256(macKey), IV ‖ ct ‖ aad)`. The ephemeral key and IV are parameters, which keeps the tests deterministic. The file is unchanged since the old tour except for the `alloc` imports.

`rust/myotis-wire/src/rlpx/ecies.rs` · lines 65–99

```rust
/// Decrypt an ECIES message with the recipient's static key. `aad` must match
/// what the sender used (EIP-8 size prefix; empty for legacy).
pub fn decrypt(
    encrypted: &[u8],
    recipient: &NodeKey,
    aad: &[u8],
) -> Result<Vec<u8>, CoreError> {
    // 0x04 ‖ ephPub(64) ‖ IV(16) ‖ ct ‖ MAC(32) — minimum is the empty-ct case.
    if encrypted.len() < 1 + 64 + IV_SIZE + MAC_SIZE {
        return Err(CoreError("ECIES: message too short".into()));
    }
    if encrypted[0] != 0x04 {
        return Err(CoreError("ECIES: expected uncompressed point marker 0x04".into()));
    }
    let mut eph_pub = [0u8; 64];
    eph_pub.copy_from_slice(&encrypted[1..65]);
    let iv = &encrypted[65..65 + IV_SIZE];
    let ct_and_mac = &encrypted[65 + IV_SIZE..];
    let (ciphertext, mac) = ct_and_mac.split_at(ct_and_mac.len() - MAC_SIZE);

    // ecdh_x validates the ephemeral point is on the curve.
    let shared = recipient.ecdh_x(&eph_pub)?;
    let (enc_key, mac_key) = derive_keys(&shared);

    let expected = compute_mac(&mac_key, iv, ciphertext, aad);
    if !bool::from(mac.ct_eq(&expected)) {
        return Err(CoreError("ECIES: MAC verification failed".into()));
    }

    let mut plain = ciphertext.to_vec();
    let mut iv_arr = [0u8; IV_SIZE];
    iv_arr.copy_from_slice(iv);
    Aes128Ctr::new((&enc_key).into(), (&iv_arr).into()).apply_keystream(&mut plain);
    Ok(plain)
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* The IV, ciphertext and MAC are *views* into the input, and nothing is copied. The length check at the top guarantees that `split_at` and the index ranges can't panic.
- *[Ownership & moves](01-primer.md#primer-ownership)* `ciphertext.to_vec()` is the one deliberate allocation: a mutable copy that `apply_keystream(&mut plain)` decrypts in place. The IV slice is copied into a fixed array because the cipher's `.into()` conversion is defined for arrays, not for slices of unknown length.
- *[Protocol & domain](01-primer.md#primer-domain)* The MAC is verified *before* anything is decrypted, and in constant time: `ct_eq` from the audited `subtle` crate returns a `Choice`, so LLVM can't turn the comparison into an early-exit loop that leaks, through timing, how many bytes matched.

<a id="f-myotis-wire-src-rlpx-handshake-rs"></a>

### myotis-wire/src/rlpx/handshake.rs

*library · 298 lines · Java twin · AuthHandshake / SessionSecrets*

The initiator side of the EIP-8 auth/ack handshake. `build_auth` signs `staticShared ⊕ nonce` with an ephemeral key, RLP-encodes the auth body, and ECIES-encrypts it with the 2-byte size prefix as associated data. `process_ack` decrypts the reply and derives `aesSecret` and `macSecret` through a keccak chain. The raw auth and ack bytes are kept in `SessionSecrets`, because they seed the frame MACs.

`rust/myotis-wire/src/rlpx/handshake.rs` · lines 81–88

```rust
pub struct Initiator<'a> {
    local_key: &'a NodeKey,
    remote_pub64: [u8; 64],
    /// Handshake ephemeral key (distinct from the ecies ephemeral inside auth).
    ephemeral: NodeKey,
    local_nonce: [u8; 32],
    auth_wire: Option<Vec<u8>>,
}
```

`rust/myotis-wire/src/rlpx/handshake.rs` · lines 150–183

```rust
    /// Process the responder's EIP-8 ack wire and derive the session secrets.
    pub fn process_ack(&self, ack_wire: &[u8]) -> Result<SessionSecrets, CoreError> {
        let auth_wire = self
            .auth_wire
            .as_ref()
            .ok_or_else(|| CoreError("RLPx: build_auth must precede process_ack".into()))?;
        if ack_wire.len() < 2 {
            return Err(CoreError("RLPx: ack too short".into()));
        }
        let size_prefix = &ack_wire[..2];
        let plain = ecies::decrypt(&ack_wire[2..], self.local_key, size_prefix)?;

        // ack body: [ephemeral-pubkey(64), nonce(32), version(4), …].
        let top = rlp::decode(&plain).or_else(|_| decode_prefix(&plain))?;
        let items = top.as_list()?;
        if items.len() < 2 {
            return Err(CoreError("RLPx: ack body too short".into()));
        }
        let mut remote_eph = [0u8; 64];
        remote_eph.copy_from_slice(items[0].as_fixed_bytes(64)?);
        let mut remote_nonce = [0u8; 32];
        remote_nonce.copy_from_slice(items[1].as_fixed_bytes(32)?);

        let secrets = derive_secrets(
            &self.ephemeral,
            &remote_eph,
            &self.local_nonce,
            &remote_nonce,
            auth_wire.clone(),
            ack_wire.to_vec(),
        )?;
        Ok(secrets)
    }
}
```

- *[Lifetimes](01-primer.md#primer-lifetimes)* **A struct that borrows.** `Initiator<'a>` mixes a *borrowed* field (`local_key: &'a NodeKey`) with owned ones. The compiler proves that the key outlives every `Initiator` built from it. The key is only needed for one handshake, so a checked borrow is enough and no `Arc` is needed. In Java you would hold a reference and hope nobody clears the key in the meantime.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* `auth_wire: Option<Vec<u8>>` works as a precondition: calling `process_ack` before `build_auth` returns an `Err` instead of panicking. `.as_ref()` turns `&Option<Vec<u8>>` into `Option<&Vec<u8>>`, so the check borrows the vector instead of moving it out of `self`.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Ownership & moves](01-primer.md#primer-ownership)* `build_auth(&mut self, …)` records the wire bytes, while `process_ack(&self, …)` only reads them, so the receiver type documents which call changes state. Because `process_ack` only borrows `self`, it cannot move `auth_wire` into the result: `auth_wire.clone()` copies it, and `ack_wire.to_vec()` copies the caller's slice. `SessionSecrets` then owns both.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `rlp::decode(&plain).or_else(|_| decode_prefix(&plain))?` tries the strict decode first and, only on error, a tolerant one that ignores trailing bytes, because some peers pad the ack body.

> [!WARNING]
> **Stale or inaccurate comments**The test `handshake_round_trip_matches_both_sides` is documented as “both derive matching secrets (A via process\_ack, B via derive\_secrets with swapped roles)”. The test body only derives A's secrets and checks that a second derivation gives the same result. Its own later comment (lines 274–279) explains why the responder side is not derived. The trailing `let _ = &b_eph;` does nothing.

<a id="f-myotis-wire-src-rlpx-frame-rs"></a>

### myotis-wire/src/rlpx/frame.rs

*library · 415 lines · Java twin · FrameCodec*

The encrypted, framed channel after the handshake: `header ‖ header-mac ‖ body (padded to 16) ‖ body-mac`. It uses AES-256-CTR with a zero IV and one continuous keystream per direction, streaming Keccak-256 MACs advanced through AES-256-ECB, and Snappy for every payload except Hello. The codec splits into an egress half and an ingress half, so a reader task and a writer can each own one. Compression now goes through [crate::snappy](#f-myotis-wire-src-snappy-rs) instead of the `snap` crate directly.

`rust/myotis-wire/src/rlpx/frame.rs` · lines 56–104

```rust
/// The EGRESS half of the frame codec (outbound): AES-256-CTR keystream +
/// keccak MAC chain. Independent of the ingress half, so the two can live on
/// separate tokio tasks / socket halves (the managed-peer read/write split).
pub struct FrameEncoder {
    encrypt: Aes256Ctr,
    egress_mac: KeccakMac,
}

/// The INGRESS half (inbound): AES-256-CTR + keccak MAC chain.
pub struct FrameDecoder {
    decrypt: Aes256Ctr,
    ingress_mac: KeccakMac,
}

/// Stateful RLPx frame codec — NOT thread-safe (the ciphers and MAC chains are
/// position-dependent; all sends/receives must be serialized, as on the Java
/// side). Composes the two independent halves; [`FrameCodec::split`] hands them
/// out for the managed-peer read/write tasks.
pub struct FrameCodec {
    encoder: FrameEncoder,
    decoder: FrameDecoder,
}

impl FrameCodec {
    /// Initiator-side codec. (For the responder, pass a `SessionSecrets` with
    /// nonce and auth/ack-wire roles swapped — see the handshake tests.)
    pub fn new(secrets: &SessionSecrets) -> FrameCodec {
        let zero_iv = [0u8; 16];
        // egress:  keccak(macSecret XOR ingressNonce ‖ authWire)  [initiator]
        // ingress: keccak(macSecret XOR egressNonce  ‖ ackWire)
        let egress_seed = xor(&secrets.mac_secret, &secrets.ingress_nonce);
        let ingress_seed = xor(&secrets.mac_secret, &secrets.egress_nonce);
        FrameCodec {
            encoder: FrameEncoder {
                encrypt: Aes256Ctr::new((&secrets.aes_secret).into(), (&zero_iv).into()),
                egress_mac: KeccakMac::new(&egress_seed, &secrets.mac_secret, &secrets.auth_wire),
            },
            decoder: FrameDecoder {
                decrypt: Aes256Ctr::new((&secrets.aes_secret).into(), (&zero_iv).into()),
                ingress_mac: KeccakMac::new(&ingress_seed, &secrets.mac_secret, &secrets.ack_wire),
            },
        }
    }

    /// Split into the independent egress/ingress halves for the managed peer's
    /// separate read and write tasks.
    pub fn split(self) -> (FrameEncoder, FrameDecoder) {
        (self.encoder, self.decoder)
    }
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **Splitting one value into two.** `split(self)` takes the codec by value and moves its two fields out. That is allowed because `FrameCodec` has no `Drop` impl; a type with one can't be taken apart (error E0509). Afterwards the codec no longer exists, and the halves are independent values that can go to different tasks without a lock.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* The doc says “NOT thread-safe”, and the types enforce it: every encode and decode method takes `&mut self`, because each call advances a keystream and a MAC chain. Two concurrent users of one encoder don't compile. There is nothing like Java's `synchronized` here; exclusive access is a compile-time fact.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `new(secrets: &SessionSecrets)` only borrows the secrets. The ciphers copy the key material they need, so the caller keeps its `SessionSecrets`.

`rust/myotis-wire/src/rlpx/frame.rs` · lines 146–172

```rust
        // Header: body-size(3 BE) ‖ rlp([0, 0]) ‖ zeros. The header-data MUST be
        // the canonical `0xc2 0x80 0x80` (geth's zeroHeader), not an empty list:
        // Nethermind's FrameHeaderReader unconditionally DecodeInt()s the first
        // sequence item and throws on `0xc0` + zero padding, killing the session
        // with Disconnect reason 0x10 on our first frame (fatal on the
        // Nethermind-dominant gnosis network).
        let mut header = [0u8; 16];
        header[0] = (body_len >> 16) as u8;
        header[1] = (body_len >> 8) as u8;
        header[2] = body_len as u8;
        header[3] = 0xc2;
        header[4] = 0x80;
        header[5] = 0x80;
        self.encrypt.apply_keystream(&mut header);
        let header_mac = self.egress_mac.update_header(&header);

        self.encrypt.apply_keystream(&mut coded_body);
        let body_mac = self.egress_mac.update_body(&coded_body);

        let mut frame = Vec::with_capacity(32 + padded_len + 16);
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&header_mac);
        frame.extend_from_slice(&coded_body);
        frame.extend_from_slice(&body_mac);
        frame
    }
}
```

- *[Protocol & domain](01-primer.md#primer-domain)* The header data must be `0xc2 0x80 0x80`, not `0xc0`. Nethermind disconnects otherwise, which is fatal on gnosis, where most nodes run Nethermind.
- *[Protocol & domain](01-primer.md#primer-domain)* **Order matters, irreversibly.** Encrypt the header, MAC it, encrypt the body, MAC it: each step mutates `self.encrypt` and `self.egress_mac`. A frame written only halfway therefore corrupts every later frame. That is the reason for the `torn` flag in `myotis-net`'s peer code ([stop 12](12-el-pool.md)).
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* Above this excerpt, `(body_len + 15) & !15` rounds the body up to a multiple of 16, and `[u8; 16]` lives on the stack.

*[Ownership & moves](01-primer.md#primer-ownership) · [Protocol & domain](01-primer.md#primer-domain)* Reading the current MAC digest (`current_digest_16`, line 316) clones the hasher first, because `finalize()` takes the hasher by value and would end the chain. `decode_body` checks a peer's *declared* decompressed size with `snappy::decompress_len` before it decompresses, so a 6-byte Snappy header that claims 4 GiB can't make the process allocate 4 GiB and abort. A payload that fails this check, or fails to decompress, is passed up raw; the RLP layer above then rejects it. The bomb test builds its header with a bare `0xc0`, which also shows that the decoder never looks at the header-data bytes.

<a id="f-myotis-wire-src-rlpx-hello-rs"></a>

### myotis-wire/src/rlpx/hello.rs

*library · 133 lines · Java twin · HelloMessage*

New file, moved here from `myotis-net::el::rlpx::transport`: the p2p base message codes (Hello `0x00`, Disconnect, Ping, Pong), the client id, and the Hello encoder and decoder. Hello is the first framed message in both directions. It names the client and lists its capabilities; the eth session in `myotis-net` then picks the highest eth and snap versions both sides share. `transport.rs` re-exports every item by name.

`rust/myotis-wire/src/rlpx/hello.rs` · lines 17–55

```rust
pub const CLIENT_ID: &str = concat!("myotis/", env!("CARGO_PKG_VERSION"));

/// Build a p2p Hello body: `[protocolVersion, clientId, [[cap,ver]…], listenPort, nodeId]`.
/// Advertises eth/66-71 + snap/1 + snap/2 (ascending). The Java `HelloMessage`
/// stops at eth/69: eth/70 (EIP-7975 receipts) and eth/71 (EIP-8159 block
/// access lists) are the Rust engine's alone. Both snap versions are offered
/// so the session runs whichever one the peer has — the highest shared (see
/// `eth::session::negotiate`).
pub fn encode_hello(node_pubkey: &[u8; 64], listen_port: u16) -> Vec<u8> {
    encode_hello_as(node_pubkey, listen_port, CLIENT_ID)
}

/// [`encode_hello`] advertising `client_id` instead of [`CLIENT_ID`] — the Tor
/// path's Hello names the software without its version.
pub fn encode_hello_as(node_pubkey: &[u8; 64], listen_port: u16, client_id: &str) -> Vec<u8> {
    use myotis_core::rlp::{self, Item};
    let cap = |name: &str, ver: u64| {
        Item::List(vec![
            Item::Bytes(name.as_bytes().to_vec()),
            Item::Bytes(rlp::u64_to_minimal_be(ver)),
        ])
    };
    rlp::encode(&Item::List(vec![
        Item::Bytes(rlp::u64_to_minimal_be(5)), // protocol version
        Item::Bytes(client_id.as_bytes().to_vec()),
        Item::List(vec![
            cap("eth", 66),
            cap("eth", 67),
            cap("eth", 68),
            cap("eth", 69),
            cap("eth", 70),
            cap("eth", 71),
            cap("snap", 1),
            cap("snap", 2),
        ]),
        Item::Bytes(rlp::u64_to_minimal_be(u64::from(listen_port))),
        Item::Bytes(node_pubkey.to_vec()),
    ]))
}
```

- *[Macros & attributes](01-primer.md#primer-macros)* **A version string built by the compiler.** `env!("CARGO_PKG_VERSION")` reads an environment variable that Cargo sets *while compiling*, and `concat!` joins string literals at compile time. The result is an ordinary `&'static str` constant such as `"myotis/0.1.19"`. The Java engine derives its Hello id from the same Gradle version, and the build task `verifyCrateVersions` keeps the two equal.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `let cap = |name: &str, ver: u64| { … };` is a closure that captures nothing, used as a local helper function. Its parameter types are written out because the body calls a method on `name`, and the compiler type-checks a closure's body where it is defined, before it has seen any call.
- *[Protocol & domain](01-primer.md#primer-domain)* The capability list advertises eth/66–71 and snap/1–2. eth/70 (EIP-7975, receipts that can be continued) and eth/71 (EIP-8159, block access lists) exist only in the Rust engine. `encode_hello_as` exists for the Tor path, whose Hello names the software without its version.

*[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Result, ? and panics](01-primer.md#primer-error-handling)* `decode_hello` (lines 79–114) first refuses a body over `MAX_CONTROL_MSG_SIZE` (16 KiB) before it builds an RLP tree (#454). It then reads strings with `String::from_utf8_lossy(…).into_owned()`: `from_utf8_lossy` returns a `Cow<str>` that borrows the input when it is valid UTF-8 and owns a repaired copy when it is not, and `into_owned()` turns either into a `String`. Errors become plain strings with `.map_err(|e| e.0)`: the closure owns the `CoreError` and moves its `String` field out.

<a id="f-myotis-wire-src-eth-rs"></a>

### myotis-wire/src/eth.rs

*library · 1,533 lines · Java twin · networking.eth.messages*

Pure encoders and decoders for the eth wire, eth/66 through eth/71, moved here from `myotis-net/src/el/eth/messages.rs`. It covers Status (eth/67–68 carry total difficulty; eth/69 carries a block range), BlockRangeUpdate, header requests and responses (outgoing *and* served to peers), block bodies, receipts (including rebuilding the canonical form from eth/69's bloom-less receipts and continuing an eth/70 response), GetBlockAccessLists, transaction broadcast, and tolerant extraction of hashes from transaction gossip. Message codes are absolute, already offset by the p2p base `0x10`. Much of the file was rewritten for #454 to read peer messages in place.

| Lines | What happens |
|---|---|
| 1–51 | Message codes, with notes on which codes are only free on which eth version. |
| 53–232 | Status for eth/67–68 and eth/69, BlockRangeUpdate, the compatibility gate. |
| 234–364 | GetBlockHeaders (inbound decode, outbound encode), BlockHeaders, `VerifiedHeader`. |
| 366–422 | GetBlockBodies / BlockBodies. |
| 424–540 | GetReceipts (eth/66 and eth/70), GetBlockAccessLists, Transactions, gossip hash extraction. |
| 542–777 | `BlockReceipts`, the receipts decoders for eth/66–68, 69 and 70, and the eth/69 bloom recomputation. |
| 779–864 | `RawList` and its iterator. |
| 866–940 | Shared helpers: request ids, the control-message size cap, `request_and_payload`, `kept`. |
| 942–1533 | Tests, including golden vectors shared with the Java engine. |

#### Status: optional fields for version-specific data

`rust/myotis-wire/src/eth.rs` · lines 57–72

```rust
/// A decoded eth Status. eth/67-68 carries `td`; eth/69 carries block numbers
/// instead (docs/reimplementation/02 §6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub protocol_version: u64,
    pub network_id: u64,
    pub genesis_hash: [u8; 32],
    /// eth/69: the latest block hash; eth/67-68: the peer's best hash.
    pub best_hash: [u8; 32],
    pub fork_id_hash: [u8; 4],
    pub fork_next: u64,
    /// eth/69 only (`None` on 67-68).
    pub latest_block: Option<u64>,
    /// eth/69 only (`None` on 67-68): the oldest block the peer can serve.
    pub earliest_block: Option<u64>,
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns)* One struct serves both layouts: the eth/69-only fields are `Option<u64>`, `None` on 67–68. That is Kotlin's `Long?`, except that the compiler makes every reader handle the `None` case. A few lines further down, `HeadersOrigin` (lines 239–242) is a data-carrying enum, like a Kotlin sealed class: a header request starts either at a block number or at a hash. `decode_status` and the other control decoders call `check_control_size` first, so a 10 MiB “Status” is refused before it is decoded into a tree.

#### Headers: read in place, copy what is kept

`rust/myotis-wire/src/eth.rs` · lines 342–364

```rust
/// Decode a BlockHeaders response `[reqId, [header, …]]` to a request for
/// `requested` headers. Returns `(request_id, headers)`, at most one more than
/// `requested` (see [`kept`]). Each header is read in place from the checked
/// response, never built into a tree (#454).
pub fn decode_block_headers(
    rlp_bytes: &[u8],
    requested: usize,
) -> Result<(u64, Vec<VerifiedHeader>), CoreError> {
    let (request_id, headers) = request_and_payload(rlp_bytes)?;
    // Each element's RAW sub-slice is the canonical header encoding → hash it.
    let mut out = Vec::new();
    for (i, raw) in headers.as_list()?.enumerate() {
        let header = BlockHeader::decode_view(raw)?;
        if i < kept(requested) {
            out.push(VerifiedHeader {
                hash: header::hash(raw.raw()),
                raw_rlp: raw.raw().to_vec(),
                header,
            });
        }
    }
    Ok((request_id, out))
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Lifetimes](01-primer.md#primer-lifetimes)* **Zero-copy parsing.** `request_and_payload` returns a `rlp::View`, a checked, borrowed window into `rlp_bytes` ([stop 4](04-core.md) covers `View` in `myotis-core`). `headers.as_list()?` walks its elements without building anything, and `raw.raw()` is a slice of the caller's buffer. Bytes are copied only at `raw.raw().to_vec()`, for a header that is kept.
- *[Protocol & domain](01-primer.md#primer-domain)* `header::hash(raw.raw())` hashes the exact wire bytes, never a re-encoding: a block hash is keccak over what was sent.
- *[Protocol & domain](01-primer.md#primer-domain) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Check everything, keep a little.** Every header is decoded, so a malformed one fails the whole response exactly as before. Only the first `kept(requested)` (the number asked for, plus one so a caller can still see a peer that over-serves) are stored. A peer that sends a million headers costs a walk, not a million allocations.

#### Receipts: the count is checked before any work

`rust/myotis-wire/src/eth.rs` · lines 576–584

```rust
pub fn canonical(&self, verified_tx_count: usize) -> Result<Cow<'_, RawList>, CoreError> {
    if self.len() != verified_tx_count {
        return Err(CoreError(format!(
            "{} receipts for {verified_tx_count} transactions",
            self.len()
        )));
    }
    self.expand()
}
```

`rust/myotis-wire/src/eth.rs` · lines 616–630

```rust
    /// The expansion itself. Private: every way in bounds the count first.
    fn expand(&self) -> Result<Cow<'_, RawList>, CoreError> {
        match self {
            BlockReceipts::Canonical(list) => Ok(Cow::Borrowed(list)),
            BlockReceipts::Eth69(wire) => {
                // The stored receipts were checked on decode: walk them as views.
                let mut out = RawList::new();
                for receipt in wire.0.iter() {
                    out.push(&canonicalize_eth69_receipt(receipt)?);
                }
                Ok(Cow::Owned(out))
            }
        }
    }
}
```

- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Ownership & moves](01-primer.md#primer-ownership) · [Lifetimes](01-primer.md#primer-lifetimes)* **`Cow`: borrow when you can, own when you must.** `Cow<'_, RawList>` (“clone on write”) is an enum with two variants. For eth/66–68 the stored list already holds the receipts-trie values, so `expand` returns `Cow::Borrowed(list)` and copies nothing. For eth/69 every receipt must be rebuilt with its bloom, so it returns `Cow::Owned(out)`, a new list. The caller uses either as a `&RawList`. The `'_` ties the borrowed case to `&self`, so the borrow checker stops it from outliving the `BlockReceipts` it points into.
- *[Protocol & domain](01-primer.md#primer-domain)* **Why the count comes first.** eth/69 (EIP-7642) removed the 256-byte logs bloom from each receipt, because it can be recomputed from the logs. Recomputing adds 256 bytes to every receipt, however small. If the count were not checked first, a peer could send millions of tiny receipts and make the node expand them. `canonical` demands exactly the transaction count of the block's verified body; `canonical_at_most` (for a caller without the body, #544) accepts at most a bound taken from the trusted header. `expand` is private, so every way in checks a count.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `len()` (line 562) uses an or-pattern, `BlockReceipts::Canonical(list) | BlockReceipts::Eth69(list) => list.len()`, which is allowed because both arms bind `list` with the same type.

`rust/myotis-wire/src/eth.rs` · lines 714–743

```rust
fn eth69_receipt_fields(wire: rlp::View<'_>) -> Result<(u8, [rlp::View<'_>; 3]), CoreError> {
    let mut fields = wire.as_list()?;
    let (Some(ty), Some(status_or_state), Some(cum_gas), Some(logs)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(CoreError("eth/69 receipt: too few fields".into()));
    };
    // The receipt tx-type is a single byte in `0x00..=0x7f` (0 = legacy). Keep
    // the Java last-byte extraction for the valid single-byte case, but reject
    // multi-byte / out-of-range encodings rather than silently truncating.
    let ty = match ty.as_bytes()? {
        [] => 0u8,
        &[b] if b <= 0x7f => b,
        _ => return Err(CoreError("eth/69 receipt: invalid tx type".into())),
    };
    status_or_state.as_bytes()?;
    cum_gas.as_bytes()?;
    for log in logs.as_list()? {
        let mut lf = log.as_list()?;
        let (Some(address), Some(topics), Some(_data)) = (lf.next(), lf.next(), lf.next()) else {
            return Err(CoreError("eth/69 receipt: malformed log".into()));
        };
        // Consensus rules: a log address is exactly 20 bytes, each topic 32.
        address.as_fixed_bytes(20)?;
        for t in topics.as_list()? {
            t.as_fixed_bytes(32)?;
        }
    }
    Ok((ty, [status_or_state, cum_gas, logs]))
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* **Slice patterns.** `[]` matches an empty slice, and `&[b] if b <= 0x7f` matches a one-element slice and binds the byte, with a guard. One `match` checks length and content together. A multi-byte type is rejected instead of truncated to its last byte, which is what the Java code would do.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Lifetimes](01-primer.md#primer-lifetimes)* The function returns `(u8, [rlp::View<'_>; 3])`: an array of three views into the same `wire` buffer. `View` is `Copy` (it is just a slice reference), so returning three of them costs nothing. The elided lifetime ties them to `wire`.
- *[Protocol & domain](01-primer.md#primer-domain)* Lines like `status_or_state.as_bytes()?;` discard the value and keep only the check. The canonical form later copies these fields as they arrived (`canonicalize_eth69_receipt`), which is correct only because they were checked here.

#### RawList: a list that costs what it weighed

`rust/myotis-wire/src/eth.rs` · lines 790–814

```rust
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawList(rlp::ListBuf);

impl RawList {
    pub fn new() -> RawList {
        RawList::default()
    }

    fn with_capacity(bytes: usize) -> RawList {
        RawList(rlp::ListBuf::with_capacity(bytes))
    }

    /// Append an element of a checked peer message as it arrived.
    fn push_item(&mut self, item: rlp::View<'_>) {
        self.0.push_view(item);
    }

    /// Append `bytes`, which [`RawList::get`] gives back unchanged: kept as
    /// itself when it is an RLP list, as a byte string around it otherwise.
    pub fn push(&mut self, bytes: &[u8]) {
        match rlp::View::new(bytes) {
            Ok(list) if list.is_list() => self.0.push_view(list),
            _ => self.0.push_bytes(bytes),
        }
    }
```

`rust/myotis-wire/src/eth.rs` · lines 850–864

```rust
impl<'a> Iterator for RawListIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let item = self.items.next()?;
        self.left = self.left.saturating_sub(1);
        Some(if item.is_list() { item.raw() } else { item.as_bytes().unwrap_or_default() })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl ExactSizeIterator for RawListIter<'_> {}
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* **A newtype.** `pub struct RawList(rlp::ListBuf);` wraps one value and keeps it private. `ListBuf` stores the items' encodings back to back in a single `Vec<u8>`, plus a count. The previous `Vec<Vec<u8>>` paid a heap allocation and about 50 bytes of overhead per element, which a body of millions of one-byte “transactions” turned into hundreds of MiB (#454).
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Lifetimes](01-primer.md#primer-lifetimes) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* **An iterator that lends slices.** `RawListIter<'a>` yields `&'a [u8]`, slices that borrow from the `RawList` itself. `impl<'a> IntoIterator for &'a RawList` (lines 834–841) makes `for tx in &list` work, like Java's `Iterable`. Because the iterator tracks `left`, it can implement `ExactSizeIterator`, and `collect()` can size its vector in one go.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `item.as_bytes().unwrap_or_default()` cannot actually fail: every item was checked on the way in. The default for `&[u8]` is the empty slice.

#### The shared helper every decoder starts with

`rust/myotis-wire/src/eth.rs` · lines 908–925

```rust
/// Split an eth/66-71 `[reqId, payload]` response (all but eth/70's
/// three-field Receipts, [`decode_receipts70`]) into the request id and a
/// view of the payload to read in place (#454). The elements of the message
/// are checked as they always were (each a whole item, anything after the
/// payload checked but not read), so the nesting a response may use is
/// unchanged.
fn request_and_payload(rlp_bytes: &[u8]) -> Result<(u64, rlp::View<'_>), CoreError> {
    let items = rlp::raw_list_prefix(rlp_bytes, 2)?;
    let (Some(id), Some(payload)) = (items.first(), items.get(1)) else {
        return Err(CoreError("eth message: missing [reqId, payload]".into()));
    };
    // `View::new` walks the payload a second time; `raw_list_prefix` has just
    // checked it the same way, so this cannot fail. Both halves stay: the first
    // keeps the nesting budget a response always had (a view over the whole
    // message would count one more level), and checking is the only way to
    // make a view.
    Ok((request_id_at(id)?, rlp::View::new(payload)?))
}
```

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* `rlp::raw_list_prefix(rlp_bytes, 2)` validates the whole message but collects only the first two elements as slices. The `let (Some(id), Some(payload)) = (…) else { … }` form destructures both or returns an error. The result type `(u64, rlp::View<'_>)` again borrows from `rlp_bytes`. The helper `kept` below it is `pub(crate)`: `snap::messages` uses it, but nothing outside the crate can, and the `myotis-net` re-export (a glob of `pub` items) does not carry it.

*[Protocol & domain](01-primer.md#primer-domain)* The gossip decoders (`decode_new_pooled_tx_hashes`, `transactions_gossip_hashes`) are deliberately tolerant. They only feed the “seen in gossip” signal of the sent-transaction watch, never a trust decision, so a malformed announcement yields the hashes that can be read, or none, and at most 256 per message.

> [!WARNING]
> **Stale or inaccurate comments**The module doc links to `` [`super::session`] ``, which does not exist in this crate; the session is `myotis-net`'s `el::eth::session`. The `BlockBody` doc (line 375) says “legacy re-encoded, typed kept as the envelope”, while the code below it (lines 408–414) keeps every transaction exactly as it arrived.

<a id="f-myotis-wire-src-eth2-mod-rs"></a>

### myotis-wire/src/eth2/mod.rs

*module index · 8 lines*

Declares the consensus-layer wire modules, `codec`, `protocols` and `status`, moved here from the root of `myotis-net`. The whole module exists only with the `eth2` feature (see `lib.rs`). The libp2p transport that carries these bytes stays in `myotis-net` ([stop 9](09-net-cl.md)); a host with its own Noise/yamux stack can use these functions directly.

<a id="f-myotis-wire-src-eth2-protocols-rs"></a>

### myotis-wire/src/eth2/protocols.rs

*library · 129 lines · Java twin · BeaconP2PService.registerBinding*

The eth2 req/resp protocol ids, exactly the set and versions the Java engine speaks, plus three lookups: whether responses carry 4 context bytes (the fork digest), whether a request is a root list this node never reads, and the exact SSZ size of each request body (used by the responder to refuse inflated requests). Since the old tour it has gained three inbound-only protocols (BlocksByRoot, DataColumnSidecarsByRoot, ExecutionPayloadEnvelopesByRoot) and `metadata/3`. Their doc comments explain why: Nimbus and Lighthouse drop a peer that cannot negotiate them, and a light client answers each with zero chunks.

`rust/myotis-wire/src/eth2/protocols.rs` · lines 53–77

```rust
/// Whether the protocol's responses carry 4 context bytes (fork digest) between
/// the result byte and the length varint. True for fork-dependent SSZ types
/// (`light_client_*`), false for the fixed ones (status/ping/metadata/goodbye)
/// — mirrors the Java `registerBinding` flags.
pub fn has_context_bytes(protocol: &str) -> bool {
    matches!(
        protocol,
        BOOTSTRAP
            | UPDATES_BY_RANGE
            | FINALITY_UPDATE
            | OPTIMISTIC_UPDATE
            | BLOCKS_BY_ROOT
            | DATA_COLUMN_SIDECARS_BY_ROOT
            | EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT
    )
}

/// The protocols whose request is a root list this node never reads, because
/// its answer is always zero chunks (see [`BLOCKS_BY_ROOT`]).
pub fn is_root_list_request(protocol: &str) -> bool {
    matches!(
        protocol,
        BLOCKS_BY_ROOT | DATA_COLUMN_SIDECARS_BY_ROOT | EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT
    )
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Macros & attributes](01-primer.md#primer-macros) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `const` items can be used as `match` patterns, and for `&str` the comparison is by *content*, not by reference. `matches!(x, A | B)` is a macro that expands to a `match` returning `bool`. The constants are `&'static str`, string literals that live for the whole program, which is also what libp2p's `StreamProtocol::new` demands.

<a id="f-myotis-wire-src-eth2-status-rs"></a>

### myotis-wire/src/eth2/status.rs

*library · 219 lines · Java twin · StatusMessage / computeForkDigest*

The SSZ `Status` message (92 bytes in v2, 84 in v1, which is v2 without its last field), the light-client `MetaData` (17 bytes in v2, 25 in v3), and the fork-digest math including the Fulu/EIP-7892 “BPO” variant. The tests pin the values the Java engine computes. This is the one file that needs `myotis-consensus`, for three SSZ helpers.

`rust/myotis-wire/src/eth2/status.rs` · lines 56–73

```rust
/// v1 decode: 84 bytes, `earliest_available_slot` defaulted to 0.
pub fn decode_v1(ssz_bytes: &[u8]) -> Result<Self, String> {
    if ssz_bytes.len() < Self::SSZ_SIZE_V1 {
        return Err(format!(
            "Status v1 requires {} bytes, got {}",
            Self::SSZ_SIZE_V1,
            ssz_bytes.len()
        ));
    }
    Ok(Self {
        fork_digest: ssz_bytes[0..4].try_into().expect("length checked"),
        finalized_root: ssz_bytes[4..36].try_into().expect("length checked"),
        finalized_epoch: u64::from_le_bytes(ssz_bytes[36..44].try_into().expect("len")),
        head_root: ssz_bytes[44..76].try_into().expect("length checked"),
        head_slot: u64::from_le_bytes(ssz_bytes[76..84].try_into().expect("len")),
        earliest_available_slot: 0,
    })
}
```

- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Result, ? and panics](01-primer.md#primer-error-handling)* Fixed-offset reads, like `ByteBuffer.getLong(36)`. `ssz_bytes[36..44]` borrows 8 bytes (indexing *would* panic if out of range), and `try_into()` turns the slice into the `[u8; 8]` that `u64::from_le_bytes` needs. The length check at the top guarantees every conversion succeeds, so each `.expect("length checked")` documents an impossible case.
- *[Protocol & domain](01-primer.md#primer-domain)* `decode` rejects an 84-byte v1 body, so the caller must pick the decoder by protocol. Trailing bytes are ignored, because only a minimum length is checked.

`rust/myotis-wire/src/eth2/status.rs` · lines 137–158

```rust
/// Fulu / EIP-7892 `compute_fork_digest`, folding the active BPO blob params in:
/// `(fork_data_root XOR sha256(u64_le(epoch) || u64_le(max_blobs)))[0..4]`.
/// `blob_params_epoch == 0` means no BPO is active → the pre-Fulu formula.
/// Mirrors `BeaconLightClient.computeForkDigest` / `NetworkConfig.currentForkDigest`.
pub fn fork_digest_bpo(
    fork_version: [u8; 4],
    genesis_validators_root: [u8; 32],
    blob_params_epoch: u64,
    blob_params_max_blobs: u64,
) -> [u8; 4] {
    let base = fork_data_root(fork_version, genesis_validators_root);
    if blob_params_epoch == 0 {
        return base[..4].try_into().expect("4 <= 32");
    }
    // sha256(epoch_le || max_blobs_le) via the consensus crate's pair hash.
    let bp_hash = ssz::sha256_pair(&blob_params_epoch.to_le_bytes(), &blob_params_max_blobs.to_le_bytes());
    let mut out = [0u8; 4];
    for i in 0..4 {
        out[i] = base[i] ^ bp_hash[i];
    }
    out
}
```

*[Protocol & domain](01-primer.md#primer-domain) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* The fork digest is the 4-byte network tag on every eth2 message: the first 4 bytes of a hash over the fork version and the genesis validators root. Since Fulu, a “blob parameter only” fork changes the digest without a new fork version, so the active BPO epoch and blob limit are hashed and XORed in. `base[..4].try_into()` copies 4 bytes out of the 32-byte root into a `[u8; 4]`. The `CUSTODY_GROUP_COUNT` constant above it (line 99) is a deliberate overstatement of what this node stores, with the reason written out: Lighthouse bans a peer that advertises less than the custody requirement.

<a id="f-myotis-wire-src-eth2-codec-rs"></a>

### myotis-wire/src/eth2/codec.rs

*library · 749 lines · Java twin · ReqRespCodec*

Byte-level framing for eth2 req/resp, with no I/O and nothing async: varints, Snappy *framed* compression, request encode and parse, single- and multi-chunk response decode, and response encode. Every function borrows a byte slice and returns owned bytes or an error. Java-generated golden vectors keep the two engines byte-compatible. Compression now goes through [crate::snappy](#f-myotis-wire-src-snappy-rs), and the multi-chunk decoder now keeps each chunk's fork digest.

| Lines | What happens |
|---|---|
| 1–40 | Wire-format doc, result codes, `CodecError` (with `std::error::Error` only under `std`). |
| 42–119 | Varints; Snappy compress, and decompress bounded by `MAX_UNCOMPRESSED_PAYLOAD` (10 MiB). |
| 121–187 | Request encode (including the `updates_by_range` body) and inbound request parsing. |
| 189–258 | Single-chunk response decode. |
| 260–451 | Multi-chunk decode with per-chunk digests, `leading_error`, `skip_snappy_frames`. |
| 453–479 | Response encoders. |
| 481–749 | Tests: Java golden vectors, a real Lighthouse error response, truncated vs. corrupt input, `malformed_inputs_never_panic`. |

`rust/myotis-wire/src/eth2/codec.rs` · lines 102–119

```rust
pub fn snappy_decompress(input: &[u8], declared_len: usize) -> Result<Vec<u8>, CodecError> {
    if declared_len == 0 || declared_len > MAX_UNCOMPRESSED_PAYLOAD {
        return Err(CodecError(format!(
            "declared uncompressed length {declared_len} outside (0, {MAX_UNCOMPRESSED_PAYLOAD}]"
        )));
    }
    // At most declared+1 bytes: a well-formed frame yields exactly `declared`;
    // anything longer trips the mismatch check below instead of allocating unbounded.
    let out = crate::snappy::decompress_framed(input, declared_len + 1)
        .map_err(|e| CodecError(format!("snappy decompress failed: {e}")))?;
    if out.len() != declared_len {
        return Err(CodecError(format!(
            "snappy output {} bytes != declared {declared_len}",
            out.len()
        )));
    }
    Ok(out)
}
```

*[Protocol & domain](01-primer.md#primer-domain) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Allocation is bounded before it happens.** Snappy can expand data about 21 times, so a hostile peer could turn a 16 MiB frame into hundreds of MiB. The declared length is checked against 10 MiB first, the reader is capped at `declared + 1` (one extra byte reveals an overrun), and any mismatch is rejected, as the spec requires. `.map_err(|e| CodecError(format!(…)))?` converts the `String` error from `snappy` into this module's error, then propagates it.

`rust/myotis-wire/src/eth2/codec.rs` · lines 169–187

```rust
pub fn parse_request_ssz_expecting(raw: &[u8], expected: Option<usize>) -> Option<Vec<u8>> {
    if raw.len() < 2 {
        return None;
    }
    let (uncompressed_len, snappy_start) = read_varint(raw, 0).ok()?;
    if uncompressed_len == 0 || snappy_start >= raw.len() {
        return None;
    }
    if let Some(expected) = expected {
        // Compare as u64 BEFORE narrowing. `uncompressed_len as usize` would
        // truncate on a 32-bit target (android armv7 is one), so a declared
        // 2^32 + expected would pass this check and then be treated as a short
        // request. Equality here makes the conversion below provably safe.
        if uncompressed_len != expected as u64 {
            return None;
        }
    }
    snappy_decompress(&raw[snappy_start..], uncompressed_len as usize).ok()
}
```

*[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* **Narrowing safely.** `as usize` truncates silently, like `(int) someLong`, and on armv7 Android `usize` is 32 bits. So the code compares in the wide type (`u64`) first. Once the values are known to be equal, the narrowing cast is provably lossless. `read_varint(raw, 0).ok()?` turns a parse error into an early `None`.

`rust/myotis-wire/src/eth2/codec.rs` · lines 296–333

```rust
while pos < raw.len() && items.len() < expected_count {
    let result_code = raw[pos];
    if result_code != 0 {
        // Error chunk: <result><varint(len)><snappy(error_msg)>, no fork digest.
        let err_body = decode_error_chunk_message(raw, pos + 1);
        tracing::info!(
            item = items.len(),
            code = result_code,
            raw_len = raw.len(),
            msg = %err_body,
            "multi-chunk response item carries an error code"
        );
        break;
    }
    pos += 1;
    if pos + 4 > raw.len() {
        break;
    }
    let fork_digest: [u8; 4] = raw[pos..pos + 4].try_into().expect("4 bytes");
    pos += 4;
    // A truncated TAIL (the reader's total budget cutting a long paced
    // response mid-chunk) must not discard the complete chunks before it.
    // Salvage ONLY when the failure is consistent with the buffer simply
    // ending (bytes ran out) — a decode failure with substantial data
    // still ahead is mid-response corruption and stays a peer-level
    // error, so a serves-then-corrupts peer cannot farm proven status.
    let (uncompressed_len, next) = match read_varint(raw, pos) {
        Ok(v) => v,
        // 10 bytes is the longest u64 varint — an error with less than
        // that remaining means the varint itself was cut off.
        Err(e) if !items.is_empty() && raw.len() - pos < 10 => {
            tracing::debug!(item = items.len(), raw_len = raw.len(), error = %e,
                "multi-chunk tail truncated at varint — salvaging prior chunks");
            break;
        }
        Err(e) => return Err(e),
    };
    pos = next;
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Truncated or corrupt?** A guard such as `Err(e) if !items.is_empty() && raw.len() - pos < 10 => break` separates “the buffer just ended, keep what we have” from “corruption, fail the whole response”. A serve-then-corrupt peer therefore cannot earn credit for a partial answer. `break` and `return` have the never type `!`, so they fit in a `match` whose other arm yields a tuple.
- *[Protocol & domain](01-primer.md#primer-domain)* **A digest per chunk.** One `updates_by_range` response can span a fork, and the Gloas fork changed the wire shape of light-client updates. So each chunk's own context bytes pick its decoder. `ContextChunk` is a type alias for `([u8; 4], Vec<u8>)`; `raw[pos..pos + 4].try_into()` copies the 4 bytes into the array.
- *[async/await & tokio](01-primer.md#primer-async) · [Protocol & domain](01-primer.md#primer-domain)* `tracing::info!(item = …, msg = %err_body, …)` records structured fields; `%` means “format with `Display`”. `tracing` is only a facade: nothing is printed unless the host installs a subscriber, which keeps the crate I/O-free. It is the reason the `eth2` feature pulls in `tracing`.

*[Ownership & moves](01-primer.md#primer-ownership) · [Iterators & closures](01-primer.md#primer-iterators-closures)* The older entry point `decode_multi_chunk_response` (lines 271–281) calls this one and drops the digests with `.into_iter().map(|(_, payload)| payload).collect()`. `into_iter()` consumes the vector, so each payload `Vec` is moved out, not copied.

> [!WARNING]
> **Stale or inaccurate comments**The module doc links to `` [`crate::reqresp`] `` and `` [`crate::protocols`] ``, paths that existed in `myotis-net`. In this crate there is no `reqresp` (it stayed in `myotis-net`), and the protocols module is `crate::eth2::protocols`. The comment at line 324 justifies the `< 10` threshold with “10 bytes is the longest u64 varint”, but this `read_varint` refuses anything longer than 5 bytes. The threshold is looser than it needs to be, not wrong.

<a id="f-myotis-wire-src-snap-mod-rs"></a>

### myotis-wire/src/snap/mod.rs

*module index · 4 lines*

Declares snap's two modules: `messages` (the codecs) and `fetch` (verification of what a peer returns). snap shares the eth peer's RLPx connection; the two protocols are told apart by message code, and snap's codes start right after the last eth code.

<a id="f-myotis-wire-src-snap-messages-rs"></a>

### myotis-wire/src/snap/messages.rs

*library · 981 lines · Java twin · networking.snap.messages*

Pure snap codecs: account ranges, storage ranges (one account at a time), bytecodes, empty responses, and, new since the old tour, snap/2 (EIP-8189) and block access lists (EIP-7928): the per-block record of which accounts a block changed, and to what. A decoded “slim” account body is only the peer's *claim* and is never trusted. A single-account query asks for `[keccak(addr), 0xff…]` with a small byte budget, so the peer returns one account plus the boundary proof. Like `eth.rs`, the decoders now read in place and keep at most `MAX_RANGE_ENTRIES` entries and `MAX_PROOF_NODES` proof nodes.

`rust/myotis-wire/src/snap/messages.rs` · lines 49–74

```rust
impl SnapCodes {
    /// `base = 0x10 + eth_protocol_length`. eth/67-68 has length 17 (base
    /// 0x21); eth/69 adds BlockRangeUpdate → length 18 (base 0x22); eth/70
    /// changes no message count; eth/71 adds GetBlockAccessLists /
    /// BlockAccessLists → length 20 (base 0x24).
    pub fn negotiated(eth_version: u64, snap_version: u64) -> SnapCodes {
        let base = match eth_version {
            ..=68 => 0x21,
            69 | 70 => 0x22,
            _ => 0x24,
        };
        SnapCodes {
            snap_version,
            get_account_range: base,
            account_range: base + 1,
            get_storage_ranges: base + 2,
            storage_ranges: base + 3,
            get_byte_codes: base + 4,
            byte_codes: base + 5,
            get_trie_nodes: base + 6,
            trie_nodes: base + 7,
            get_block_access_lists: base + 8,
            block_access_lists: base + 9,
        }
    }
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* **Range patterns.** `..=68` matches every value up to 68, `69 | 70` either of two, and `_` the rest. Each eth version that adds messages pushes snap's base up: 0x21, then 0x22 (eth/69's BlockRangeUpdate), then 0x24 (eth/71's two access-list messages).
- *[Ownership & moves](01-primer.md#primer-ownership)* `SnapCodes` holds only `u64`s and derives `Copy`, so it is duplicated freely. `myotis-net`'s managed peer passes it around by value.

`rust/myotis-wire/src/snap/messages.rs` · lines 184–205

```rust
/// The fields of a slim account body, read in place.
struct SlimFields<'a> {
    nonce: u64,
    balance: &'a [u8],
    storage_root: [u8; 32],
    code_hash: [u8; 32],
}

impl<'a> SlimFields<'a> {
    /// The slim body is either a nested list `[nonce, balance, root?, codeHash?]`
    /// or a byte-string wrapping that list's RLP (go-ethereum's `[]byte` form).
    fn read(body: rlp::View<'a>) -> Result<SlimFields<'a>, CoreError> {
        let body = if body.is_list() { body } else { rlp::View::new(body.as_bytes()?)? };
        let mut fields = body.as_list()?;
        Ok(SlimFields {
            nonce: fields.next().map_or(Ok(0), |n| n.as_u64())?,
            balance: fields.next().map_or(Ok(&[][..]), |b| b.as_bytes())?,
            storage_root: slim_hash(fields.next(), &EMPTY_TRIE_ROOT)?,
            code_hash: slim_hash(fields.next(), &EMPTY_CODE_HASH)?,
        })
    }
}
```

*[Lifetimes](01-primer.md#primer-lifetimes) · [Borrowing & slices](01-primer.md#primer-borrowing)* **A struct that borrows from the message.** `SlimFields<'a>` holds `balance: &'a [u8]`, a slice of the peer's message, not a copy. The slim body comes in two forms (a nested list, or a byte string wrapping that list's RLP), and `let body = if body.is_list() { body } else { rlp::View::new(body.as_bytes()?)? };` unifies them by *shadowing*: the new `body` is a view of the inner bytes. That compiles because `View::as_bytes` returns `&'a [u8]`, tied to the original input, not to the temporary view. The old version of this decoder built an owned tree and had to declare a holder variable before the `match` so the borrow would live long enough; with views there is nothing to own. `decode_account_range` copies the balance (`to_vec()`) only for the entries it keeps.

`rust/myotis-wire/src/snap/messages.rs` · lines 474–495

```rust
pub fn bal_account_changes(raw: &[u8]) -> Result<Vec<BalAccountChange>, CoreError> {
    let mut out = Vec::new();
    let mut previous: Option<[u8; 20]> = None;
    for account in rlp::View::new(raw)?.as_list()? {
        let mut fields = account.as_list()?;
        let mut field = |name: &str| fields.next().ok_or_else(|| CoreError(format!("BAL: an account without {name}")));
        let mut address = [0u8; 20];
        address.copy_from_slice(field("an address")?.as_fixed_bytes(20)?);
        // Ascending and unique, as the spec orders them: a repeated account
        // would leave which of its entries holds open.
        if previous.is_some_and(|p| p >= address) {
            return Err(CoreError("BAL: accounts out of address order".into()));
        }
        previous = Some(address);
        let storage_changes = field("storage_changes")?;
        let storage_reads = field("storage_reads")?;
        let balance_changes = field("balance_changes")?;
        let nonce_changes = field("nonce_changes")?;
        let code_changes = field("code_changes")?;
        if fields.next().is_some() {
            return Err(CoreError("BAL: an account with more than six fields".into()));
        }
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Borrowing & slices](01-primer.md#primer-borrowing)* **A closure that borrows mutably.** `let mut field = |name: &str| fields.next()…` captures the iterator `fields` by mutable reference, so `field` is an `FnMut` and must itself be `mut`. While the closure is still going to be used, nothing else may touch `fields`. After its last call (line 492), the borrow ends, which is why line 493 may call `fields.next()` directly. The compiler works this out from where the closure is last used (“non-lexical lifetimes”).
- *[Protocol & domain](01-primer.md#primer-domain) · [Result, ? and panics](01-primer.md#primer-error-handling)* `previous.is_some_and(|p| p >= address)` compares two `[u8; 20]` arrays lexicographically, which is the address order the BAL spec requires. Out-of-order accounts are an error, never a partial answer, because these values are applied to proven state. Further down, `.map(|v| v.as_u64()).transpose()?` turns an `Option<Result<u64, _>>` into a `Result<Option<u64>, _>` so `?` can apply.

`rust/myotis-wire/src/snap/messages.rs` · lines 584–594

```rust
/// The byte-string nodes of a proof list (list elements are skipped).
fn decode_proof(item: Option<rlp::View<'_>>) -> Result<Vec<Vec<u8>>, CoreError> {
    let Some(nodes) = item.filter(rlp::View::is_list) else {
        return Ok(Vec::new());
    };
    let mut nodes = nodes.as_list()?;
    if nodes.clone().nth(MAX_PROOF_NODES).is_some() {
        return Err(CoreError(format!("proof has more than {MAX_PROOF_NODES} nodes")));
    }
    Ok(nodes.by_ref().filter_map(|n| n.as_bytes().ok().map(<[u8]>::to_vec)).collect())
}
```

*[Iterators & closures](01-primer.md#primer-iterators-closures)* `nodes.clone().nth(MAX_PROOF_NODES)` looks ahead on a *copy* of the iterator: a view iterator is a few words of position state, so cloning it is cheap and leaves `nodes` at the start. If a 1025th node exists, the proof is refused before any node is copied or hashed. `<[u8]>::to_vec` is a method named as a function and passed where a closure would otherwise go.

> [!WARNING]
> **Stale or inaccurate comments**Line 24 says `OUR_SNAP_VERSIONS` must match the capabilities in `rlpx::transport::encode_hello`, “pinned by its round-trip test”. `encode_hello` now lives in `rlpx::hello` (re-exported by `transport`), and the round-trip test in `transport.rs` checks the snap capabilities against literals, not against this constant. The section comment at lines 550–555 says wiring the empty responders into an inbound read loop is future work (“EL-A7”); `myotis-net/src/el/peer.rs` already answers inbound snap requests with `encode_empty_range` and `encode_empty_codes`.

<a id="f-myotis-wire-src-snap-fetch-rs"></a>

### myotis-wire/src/snap/fetch.rs

*library · 360 lines*

Security-critical verification. An account's fields come from the *proof leaf*, never from the slim body, since a peer could keep nonce and balance honest while forging storageRoot or codeHash. Storage is proven against the account's own storage root, and bytecode is accepted only if `keccak(code) == codeHash`. The file also defines the markers the reader uses to tell “the peer couldn't prove this root” apart from transport failures, and, new since the old tour, the `*_proof` variants that also return the proof path in `eth_getProof` form.

`rust/myotis-wire/src/snap/fetch.rs` · lines 40–72

```rust
/// Marker shared by every proof-verification failure message. LOAD-BEARING:
/// `reader::snap_account_at_best_root` classifies anchor-root failures by this
/// substring — "the peer answered but could not prove at that root" (pruned /
/// trailing / malformed proof) takes the handshake-head fallback, while
/// transport-shaped errors propagate immediately. Keep the format strings
/// below built from this constant, and keep
/// [`is_unservable_root_error`] + its tests in sync.
pub const PROOF_INVALID_MARKER: &str = "proof invalid";

/// Does this fetch error mean "the peer responded, but the proof did not
/// verify against the requested root"? True for a pruned/unknown root (empty
/// proof), a trailing peer, or a malformed/hostile proof — all cases where a
/// retry against a DIFFERENT root can still succeed. False for
/// transport-shaped failures (timeout/disconnect), where a second query
/// against the same peer would just pay the same timeout again.
pub fn is_unservable_root_error(error: &str) -> bool {
    error.contains(PROOF_INVALID_MARKER)
}

/// The reason `myotis_core::trie::verify_proof` gives when a peer answers a
/// range query with NO proof nodes for a non-empty root — the shape of "I do
/// not hold that root": pruned, or never had (a trailing peer). Kept in sync
/// with `trie.rs`; [`is_unknown_root_error`] is the only reader.
pub const UNKNOWN_ROOT_REASON: &str = "empty proof for non-empty root";

/// Does this fetch error mean "the peer does not hold the requested root" —
/// the empty-proof answer, as opposed to a malformed or hostile proof? The one
/// miss a read at a root the peer is not obliged to hold (the finalized root,
/// which execution clients keep for a bounded window) excuses: evidence about
/// the ask, not the peer. A garbage proof stays a strike.
pub fn is_unknown_root_error(error: &str) -> bool {
    is_unservable_root_error(error) && error.contains(UNKNOWN_ROOT_REASON)
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Protocol & domain](01-primer.md#primer-domain)* **Errors classified by substring.** These errors are `CoreError(String)`, not an enum, so the reader in `myotis-net` ([stop 14](14-el-reader.md)) classifies them by text. `is_unservable_root_error` means “the peer answered, but not with a valid proof at that root”: try a different root. `is_unknown_root_error` narrows it to the empty-proof case, the one a read at the finalized root forgives, because execution clients keep old roots only for a while. A garbage proof stays a strike against the peer. `UNKNOWN_ROOT_REASON` must equal the string in `myotis-core/src/trie.rs` line 92, which it does; a test pins the shapes.

`rust/myotis-wire/src/snap/fetch.rs` · lines 97–120

```rust
fn account_outcome(result: ProofResult) -> Result<AccountOutcome, CoreError> {
    match result {
        ProofResult::Found(leaf) => Ok(AccountOutcome::Present(decode_account_leaf(&leaf)?)),
        ProofResult::Absent => Ok(AccountOutcome::Absent),
        ProofResult::Invalid(reason) => {
            Err(CoreError(format!("account {PROOF_INVALID_MARKER}: {reason}")))
        }
    }
}

/// The verified outcome of a storage lookup: the minimal big-endian slot value
/// (empty = zero).
pub fn verify_storage(
    account: &AccountLeaf,
    slot: &[u8; 32],
    response: &StorageRanges,
) -> Result<Vec<u8>, CoreError> {
    // An empty storage trie: the value is zero with no proof needed.
    if account.storage_root == EMPTY_TRIE_ROOT {
        return Ok(Vec::new());
    }
    // Storage anchors at the account's PROVEN storageRoot, not the state root.
    storage_value(verify_proof(&account.storage_root, &keccak256(slot), &response.proof))
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* An exhaustive `match` on `ProofResult`. Each arm moves its payload (`leaf`, `reason`) out, and the `?` in the `Found` arm converts a leaf-decode failure into the function's error. A new `ProofResult` variant would break compilation here until it is handled.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `format!("account {PROOF_INVALID_MARKER}: {reason}")` inlines a constant by name; inline format arguments work with any identifier in scope. The marker is load-bearing for the classification above.
- *[Protocol & domain](01-primer.md#primer-domain)* `verify_storage` anchors at `account.storage_root`, which comes from an account leaf that was itself proven. An empty storage trie short-circuits to zero with no proof needed.

*[Ownership & moves](01-primer.md#primer-ownership)* `verify_bytecode(code_hash, returned: &[Vec<u8>])` borrows the peer's codes, so the matching one is returned as `code.clone()`, an owned copy.

> [!WARNING]
> **Stale or inaccurate comments**The module doc (lines 13–18) lists as “Deferred to EL-A7” peer rotation, root-unavailable marking and “answering inbound snap `Get*` with empty responses”. The managed peer it waited for now exists in `myotis-net`, and at least the last item is done: `el/peer.rs` answers inbound snap requests with the empty responders from `messages.rs`. The other two items were not checked for this stop.

## The shims left behind in myotis-net

Nine files in `myotis-net` are now four lines long. Each says where its code went and re-exports it. Here is one; the other eight differ only in the path.

`rust/myotis-net/src/codec.rs` · lines 1–4

```rust
//! Moved to `myotis-wire` (myotis#505) so hosts without tokio can use it;
//! re-exported here at its old path.

pub use myotis_wire::eth2::codec::*;
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **A glob re-export.** `pub use myotis_wire::eth2::codec::*;` makes every `pub` item of that module visible as if it were declared in `myotis_net::codec`. Nothing is copied: `myotis_net::codec::CodecError` and `myotis_wire::eth2::codec::CodecError` are the same type, so values pass freely between code that uses either path. Items that are `pub(crate)` (such as `eth::kept`) or exist only under `#[cfg(test)]` are not carried.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Why keep them.** Many users still name the old paths: `roost` (`myotis_net::codec`, `myotis_net::status`), `tor-poc` (`el::snap::fetch`), `myotis-net`'s own examples and conformance tests, and modules inside `myotis-net` itself (`crate::codec` in `reqresp.rs` and `sync.rs`). `roost` and `tor-poc` are separate Cargo workspaces, so a path change there is easy to miss. The shims let the move land with no change to any of them.

<a id="f-myotis-net-src-codec-rs"></a>

### myotis-net/src/codec.rs

*re-export shim · 4 lines*

Re-exports [myotis-wire's eth2/codec.rs](#f-myotis-wire-src-eth2-codec-rs) as `myotis_net::codec`. Kept for `roost` (its `framing.rs`, `store.rs` and `main.rs`), the CL examples, `tests/live_pins_alive.rs`, and `reqresp.rs` and `sync.rs` inside `myotis-net`.

<a id="f-myotis-net-src-status-rs"></a>

### myotis-net/src/status.rs

*re-export shim · 4 lines*

Re-exports [eth2/status.rs](#f-myotis-wire-src-eth2-status-rs) as `myotis_net::status`. `roost`'s `serve.rs` and `forks.rs` use the old path, as do `reqresp.rs`, `sync.rs` and `cl_fork_watch.rs` inside `myotis-net`.

<a id="f-myotis-net-src-protocols-rs"></a>

### myotis-net/src/protocols.rs

*re-export shim · 4 lines*

Re-exports [eth2/protocols.rs](#f-myotis-wire-src-eth2-protocols-rs) as `myotis_net::protocols`, for `reqresp.rs`, `sync.rs` and the CL examples (`lc_crawl`, `period_census`, `probe_updates`).

<a id="f-myotis-net-src-el-rlpx-ecies-rs"></a>

### myotis-net/src/el/rlpx/ecies.rs

*re-export shim · 4 lines*

Re-exports [rlpx/ecies.rs](#f-myotis-wire-src-rlpx-ecies-rs) at `myotis_net::el::rlpx::ecies`. The cross-language RLPx corpus test `tests/el_rlpx_conformance.rs` still imports it from here.

<a id="f-myotis-net-src-el-rlpx-frame-rs"></a>

### myotis-net/src/el/rlpx/frame.rs

*re-export shim · 4 lines*

Re-exports [rlpx/frame.rs](#f-myotis-wire-src-rlpx-frame-rs) at `el::rlpx::frame`. `transport.rs` next to it imports `FrameCodec` and its halves through `super::frame`, and `eth/session.rs`, `reader.rs` and the conformance test use the path too.

<a id="f-myotis-net-src-el-rlpx-handshake-rs"></a>

### myotis-net/src/el/rlpx/handshake.rs

*re-export shim · 4 lines*

Re-exports [rlpx/handshake.rs](#f-myotis-wire-src-rlpx-handshake-rs) at `el::rlpx::handshake`, for `transport.rs` (`super::handshake::Initiator`), `eth/session.rs` and the conformance test. Note that `myotis-net/src/el/rlpx/mod.rs` still declares these three modules and `transport`; `hello` has no shim of its own, because `transport.rs` re-exports its items by name.

<a id="f-myotis-net-src-el-eth-messages-rs"></a>

### myotis-net/src/el/eth/messages.rs

*re-export shim · 4 lines*

Re-exports the whole of [eth.rs](#f-myotis-wire-src-eth-rs) as `el::eth::messages`. The new crate flattened the path (`myotis_wire::eth`, not `eth::messages`), so this shim is where the two names meet. It is the most used of the nine: `peer.rs`, `pool.rs`, `reader.rs`, `anchor.rs`, `sync.rs`, three integration tests (`el_eth_conformance`, `el_verify_conformance`, `el_hostile_frames`) and the `snap_probe` example.

<a id="f-myotis-net-src-el-snap-fetch-rs"></a>

### myotis-net/src/el/snap/fetch.rs

*re-export shim · 4 lines*

Re-exports [snap/fetch.rs](#f-myotis-wire-src-snap-fetch-rs) at `el::snap::fetch`. Users include `tor-poc` (a separate workspace), `reader.rs`, `evm.rs`, `peer.rs`, the session, and the snap live tests.

<a id="f-myotis-net-src-el-snap-messages-rs"></a>

### myotis-net/src/el/snap/messages.rs

*re-export shim · 4 lines*

Re-exports [snap/messages.rs](#f-myotis-wire-src-snap-messages-rs) at `el::snap::messages`, for `peer.rs`, `reader.rs`, `activity.rs` (which uses `BalAccountChange`), the session, the conformance and hostile-frame tests, and `snap_probe`.

## Checkpoint

13 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-wire-q1"></a>

**Q1** · Multiple choice

Every source file in `myotis-wire` starts with `#[allow(unused_imports)] use alloc::{borrow::ToOwned, format, string::{String, ToString}, vec, vec::Vec};`. Why is this import there, and why the `allow`?

- **A.** In a `no_std` build the prelude is `core`'s and has no heap types, so they must be imported from `alloc`; every file copies the same list and not every file uses every name, so unused ones would warn
- **B.** `alloc::vec::Vec` is a different, faster type than `std::vec::Vec`
- **C.** The import is required by the `snap` crate
- **D.** It turns off the standard library for that file only

[Answer →](answers.md#a-wire-q1)

<a id="q-wire-q2"></a>

**Q2** · Multiple choice

What does an execution-layer-only host avoid by building `myotis-wire` without the `eth2` feature?

- **A.** The tokio runtime
- **B.** The `snap` crate
- **C.** `myotis-consensus` and, through it, `myotis-bls` and the blst C library, which would otherwise have to be cross-compiled for its target
- **D.** The RLPx frame codec

[Answer →](answers.md#a-wire-q2)

<a id="q-wire-q3"></a>

**Q3** · Multiple choice

In the built-in Snappy decoder, a copy element repeats `l` bytes from `off` bytes back. Why does it push one byte at a time instead of `out.extend_from_slice(&out[start..start + l])`?

- **A.** Byte loops are faster than `extend_from_slice`
- **B.** `extend_from_slice` is not available without `std`
- **C.** That line borrows `out` immutably and mutably at once, which does not compile, and a copy may overlap its own output (`l > off`), so the source bytes do not all exist yet when the copy starts
- **D.** To avoid integer overflow

[Answer →](answers.md#a-wire-q3)

<a id="q-wire-q4"></a>

**Q4** · Written answer

Explain `FrameCodec::split(self) -> (FrameEncoder, FrameDecoder)`: what happens to ownership, why the compiler allows it, and why the encoder's and decoder's methods take `&mut self`.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-wire-q4)

<a id="q-wire-q5"></a>

**Q5** · Multiple choice

In `SlimFields::read(body: rlp::View<'a>)`, the line `let body = if body.is_list() { body } else { rlp::View::new(body.as_bytes()?)? };` builds a view of the inner bytes, and the result is stored in a `SlimFields<'a>`. Why does this compile?

- **A.** Because `View::new` copies the bytes into a new buffer
- **B.** Because `View` implements `Drop`
- **C.** Because the compiler extends the life of temporaries automatically
- **D.** Because `View::as_bytes` returns `&'a [u8]`, tied to the original input rather than to the view value, so the new view also borrows the caller's buffer for `'a`

[Answer →](answers.md#a-wire-q5)

<a id="q-wire-q6"></a>

**Q6** · Multiple choice

`BlockReceipts::canonical` returns `Cow<'_, RawList>`. What does a caller get for an eth/68 response?

- **A.** `Cow::Borrowed` pointing at the stored list, with nothing copied, because eth/66-68 receipts are already receipts-trie values
- **B.** `Cow::Owned` with a copy of the list
- **C.** An error, because only eth/69 is supported
- **D.** A `Box<RawList>`

[Answer →](answers.md#a-wire-q6)

<a id="q-wire-q7"></a>

**Q7** · Multiple choice

Why does `encode_frame` write the header data as `0xc2 0x80 0x80` instead of an empty RLP list `0xc0`?

- **A.** It is shorter
- **B.** geth requires it for compression
- **C.** Nethermind's frame-header reader decodes an integer from the first list item and throws on `0xc0`, disconnecting on the first frame, which is fatal on gnosis, where most nodes run Nethermind
- **D.** It carries the message code

[Answer →](answers.md#a-wire-q7)

<a id="q-wire-q8"></a>

**Q8** · Multiple choice

In `discv4::decode_neighbors`, what happens to an entry whose fields are well-formed RLP but whose IP is 5 bytes long?

- **A.** The whole packet is rejected with an error
- **B.** The walk stops and keeps the nodes decoded so far
- **C.** That entry is skipped with `continue` and the walk goes on, matching where Java's `InetAddress` construction throws
- **D.** The IP is truncated to 4 bytes

[Answer →](answers.md#a-wire-q8)

<a id="q-wire-q9"></a>

**Q9** · Multiple choice

In `bal_account_changes`, `let mut field = |name: &str| fields.next()…` captures `fields`. Why may line 493 call `fields.next()` directly?

- **A.** The closure's mutable borrow of `fields` ends after its last use on line 492, so `fields` is free again
- **B.** Closures copy the iterator they capture
- **C.** `fields` is a `RefCell`
- **D.** Line 493 runs before the closure is created

[Answer →](answers.md#a-wire-q9)

<a id="q-wire-q10"></a>

**Q10** · Multiple choice

`parse_request_ssz_expecting` compares `uncompressed_len != expected as u64` before it ever writes `uncompressed_len as usize`. What would go wrong if it cast first?

- **A.** Nothing; the order does not matter
- **B.** The varint would be decoded twice
- **C.** It would allocate 10 MiB
- **D.** On a 32-bit target such as armv7 Android, `as usize` truncates silently, so a declared 2^32 + 32 would pass as 32

[Answer →](answers.md#a-wire-q10)

<a id="q-wire-q11"></a>

**Q11** · Written answer

`myotis-net/src/codec.rs` is now `pub use myotis_wire::eth2::codec::*;`. What does this line do to types and visibility, and why was it worth keeping nine such files?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-wire-q11)

<a id="q-wire-q12"></a>

**Q12** · Written answer

Both the RLPx frame decoder and the eth2 codec defend against Snappy “bombs”. Describe how each one does it and why their strategies differ.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-wire-q12)

<a id="q-wire-q13"></a>

**Q13** · Written answer

`Initiator<'a>` holds `local_key: &'a NodeKey`, `build_auth` takes `&mut self`, and `process_ack` takes `&self`. What does each of these choices express, and what copies does `process_ack` make to build its result?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-wire-q13)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
