//! EIP-1459 DNS node lists ("ENR trees") for the EL pool (#539, part 3) —
//! twin of the Java `networking.dns.DnsEnrResolver` and the DNS pool in
//! `ChainStack`, trimmed to what this pool needs.
//!
//! A network's node list is published as a Merkle tree of DNS TXT records.
//! The root sits at the tree's domain:
//! `enrtree-root:v1 e=<enr-root> l=<link-root> seq=<n> sig=<base64url>`,
//! signed by the key in the list's URL, `enrtree://<base32 key>@<domain>`.
//! Every other record lives at `<label>.<domain>`, the label being the base32
//! of the first 16 bytes of the keccak256 of the record's text:
//! `enrtree-branch:<label>,…` for an inner node, `enr:<record>` for a leaf,
//! `enrtree://…` for a link to another list (under `l=`, which this walk does
//! not follow, like the Java twin).
//!
//! Trust. The root signature puts the whole tree under the URL's key, and a
//! record that does not hash to its label is dropped — so a resolver or a
//! middlebox can withhold records but not add any. Each leaf is a signed node
//! record that the `enr` crate verifies on decode (the Java twin checks only
//! the root). None of it is a trust input for chain data: a leaf is a dial
//! candidate, judged by its `eth` entry first (`enrfilter.rs`, so a node on
//! another chain never costs a dial — the point of #539), and the eth Status
//! check at the handshake stays the authority.
//!
//! Where it runs. Only on hosts that allow DNS ([`set_enabled`]: the JVM
//! desktop and daemon, which resolve through the system resolver; a mobile
//! host supplies its own DNS servers and the engine has no port for those yet,
//! so it stays off there) and never under Tor (`el::tor`): a system-resolver
//! query for `all.mainnet.ethdisco.net` tells the local resolver which network
//! this node is on, which is what Tor is switched on to hide. The walk is
//! bounded (lookups, depth, deadline) and its order random, so a tree larger
//! than one walk's budget is seen in a different part each time. Its result is
//! a pool of candidates the peer pool dials from in small batches while below
//! target, and the walk is repeated every few minutes while the pool stays
//! short.

use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use discv5::enr::{CombinedKey, Enr, EnrPublicKey};
use myotis_core::enr::base64url_decode;
use myotis_core::keccak::keccak256;
use myotis_core::nodekey::{decompress_public_key, recover_public_key};

use crate::el::enrfilter::{ForkFilter, Verdict};
use crate::el::pool::Enode;

// ---------------------------------------------------------------------------
// Policy: a host switch, and never under Tor.
// ---------------------------------------------------------------------------

/// Process-wide: whether the host allows DNS discovery (default off; the
/// hosts that resolve through the system resolver switch it on —
/// `myotis_set_dns_discovery`).
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Allow or forbid DNS discovery for every network this process runs.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::SeqCst);
    if on {
        tracing::info!("dns discovery: ENABLED (EIP-1459 trees over the system resolver)");
    } else {
        tracing::info!("dns discovery: disabled");
    }
}

/// Whether a host allowed DNS discovery.
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::SeqCst)
}

/// Whether a walk may run now: a host allowed DNS, and Tor is not on. Read at
/// every walk, not once: both switches are live.
pub fn allowed() -> bool {
    is_enabled() && !tor_enabled()
}

fn tor_enabled() -> bool {
    #[cfg(feature = "tor")]
    {
        crate::el::tor::is_enabled()
    }
    #[cfg(not(feature = "tor"))]
    {
        false
    }
}

// ---------------------------------------------------------------------------
// The records (pure).
// ---------------------------------------------------------------------------

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32, unpadded — how EIP-1459 writes keys and labels.
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(BASE32_ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// RFC 4648 base32 decode: case-insensitive, trailing `=` padding tolerated,
/// leftover bits dropped (the Java twin's leniency).
pub fn base32_decode(s: &str) -> Result<Vec<u8>, String> {
    let body = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(body.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for c in body.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return Err(format!("base32: invalid character {:?}", c as char)),
        };
        buffer = (buffer << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
        buffer &= (1 << bits) - 1;
    }
    Ok(out)
}

/// The DNS label a record lives under: base32 of the first 16 bytes of the
/// keccak256 of its text.
pub fn label_of(content: &str) -> String {
    base32_encode(&keccak256(content.as_bytes())[..16])
}

/// An `enrtree://<key>@<domain>` list URL: the domain and the key, uncompressed,
/// that its root record must recover to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrTreeUrl {
    pub domain: String,
    pub pubkey: [u8; 64],
}

impl EnrTreeUrl {
    pub fn parse(url: &str) -> Result<EnrTreeUrl, String> {
        let rest = url
            .strip_prefix("enrtree://")
            .ok_or_else(|| format!("not an enrtree:// URL: {url}"))?;
        let (key, domain) = rest
            .split_once('@')
            .ok_or_else(|| format!("enrtree URL without a key: {url}"))?;
        if key.is_empty() || domain.is_empty() {
            return Err(format!("enrtree URL with an empty key or domain: {url}"));
        }
        if domain
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
        {
            return Err(format!("enrtree URL with an unusable domain: {url}"));
        }
        let compressed = base32_decode(key)?;
        if compressed.len() != 33 {
            return Err(format!(
                "enrtree key is {} bytes, not a 33-byte compressed point",
                compressed.len()
            ));
        }
        let pubkey = decompress_public_key(&compressed).map_err(|e| format!("enrtree key: {}", e.0))?;
        Ok(EnrTreeUrl {
            domain: domain.to_string(),
            pubkey,
        })
    }
}

const ROOT_PREFIX: &str = "enrtree-root:v1 ";
const BRANCH_PREFIX: &str = "enrtree-branch:";
const LEAF_PREFIX: &str = "enr:";
const LINK_PREFIX: &str = "enrtree://";

/// A verified root record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    pub enr_root: String,
    pub link_root: String,
    pub seq: u64,
}

/// Parse a root record and verify its signature against the tree's key: the
/// 65-byte `r‖s‖v` signature (base64url, padding optional) is over the
/// keccak256 of the text before ` sig=`, and must recover to `pubkey`.
pub fn parse_root(txt: &str, pubkey: &[u8; 64]) -> Result<Root, String> {
    let txt = txt.trim();
    if !txt.starts_with(ROOT_PREFIX) {
        return Err(format!("not an enrtree-root:v1 record: {}", truncate(txt, 60)));
    }
    let (signed, sig) = txt
        .rsplit_once(" sig=")
        .ok_or_else(|| "root record without a sig= field".to_string())?;
    let (mut enr_root, mut link_root, mut seq) = (None, None, None);
    for token in signed[ROOT_PREFIX.len()..].split(' ') {
        match token.split_once('=') {
            Some(("e", v)) => enr_root = Some(v.to_string()),
            Some(("l", v)) => link_root = Some(v.to_string()),
            Some(("seq", v)) => {
                seq = Some(v.parse::<u64>().map_err(|_| format!("root seq is not a number: {v}"))?)
            }
            _ => {} // unknown fields are ignored, as geth does
        }
    }
    let (Some(enr_root), Some(link_root), Some(seq)) = (enr_root, link_root, seq) else {
        return Err(format!("root record missing e=, l= or seq=: {}", truncate(signed, 80)));
    };
    let sig = base64url_decode(sig.trim()).map_err(|e| format!("root sig: {}", e.0))?;
    let sig65: [u8; 65] = sig
        .try_into()
        .map_err(|v: Vec<u8>| format!("root sig is {} bytes, not 65", v.len()))?;
    let recovered = recover_public_key(&keccak256(signed.as_bytes()), &sig65)
        .map_err(|e| format!("root sig: {}", e.0))?;
    if recovered != *pubkey {
        return Err("root signature does not recover to the tree's key".to_string());
    }
    Ok(Root {
        enr_root,
        link_root,
        seq,
    })
}

/// A record below the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// `enrtree-branch:` — the labels of its children.
    Branch(Vec<String>),
    /// `enr:` — a node record, as text.
    Node(String),
    /// `enrtree://` — a link to another list (not followed).
    Link(String),
}

pub fn parse_entry(txt: &str) -> Result<Entry, String> {
    let txt = txt.trim();
    if let Some(rest) = txt.strip_prefix(BRANCH_PREFIX) {
        return Ok(Entry::Branch(
            rest.split(',')
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect(),
        ));
    }
    if txt.starts_with(LEAF_PREFIX) {
        return Ok(Entry::Node(txt.to_string()));
    }
    if txt.starts_with(LINK_PREFIX) {
        return Ok(Entry::Link(txt.to_string()));
    }
    Err(format!("unknown tree entry: {}", truncate(txt, 40)))
}

/// A node record from the tree: what the pool needs to dial it and what the
/// filter needs to judge it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsNode {
    /// The record's secp256k1 identity, uncompressed (the RLPx dial key).
    pub pubkey: [u8; 64],
    pub ip: IpAddr,
    /// `None`: the record names no TCP port — a discovery-only node, never
    /// dialed (geth refuses such a node too, `errNoPort`).
    pub tcp: Option<u16>,
    pub udp: Option<u16>,
    /// The raw RLP of the `eth` entry (EIP-2124 fork id), if any.
    pub eth: Option<Vec<u8>>,
    pub seq: u64,
}

impl DnsNode {
    /// The address to dial, when the record names a TCP port.
    pub fn dial_addr(&self) -> Option<SocketAddr> {
        self.tcp.map(|p| SocketAddr::new(self.ip, p))
    }

    /// The discv4 endpoint, when the record names a UDP port.
    pub fn udp_addr(&self) -> Option<SocketAddr> {
        self.udp.map(|p| SocketAddr::new(self.ip, p))
    }
}

/// Decode a leaf: the `enr` crate verifies the record's signature; the
/// identity must be secp256k1 (an ed25519 node cannot be dialed over RLPx)
/// and the record must name an address (`ip`, else `ip6`, with that family's
/// ports — a record without one is nobody's dial candidate).
pub fn parse_leaf(txt: &str) -> Result<DnsNode, String> {
    let enr: Enr<CombinedKey> = txt.parse().map_err(|e| format!("leaf: {e}"))?;
    let pubkey = decompress_public_key(&enr.public_key().encode())
        .map_err(|_| "leaf: not a secp256k1 node".to_string())?;
    let (ip, tcp, udp) = if let Some(ip4) = enr.ip4() {
        (IpAddr::V4(ip4), enr.tcp4(), enr.udp4())
    } else if let Some(ip6) = enr.ip6() {
        (IpAddr::V6(ip6), enr.tcp6().or(enr.tcp4()), enr.udp6().or(enr.udp4()))
    } else {
        return Err("leaf: no address".to_string());
    };
    Ok(DnsNode {
        pubkey,
        ip,
        tcp: tcp.filter(|p| *p != 0),
        udp: udp.filter(|p| *p != 0),
        eth: enr.get_raw_rlp("eth").map(<[u8]>::to_vec),
        seq: enr.seq(),
    })
}

fn truncate(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

// ---------------------------------------------------------------------------
// The walk.
// ---------------------------------------------------------------------------

/// The TXT lookups a walk makes: one name → the record's text, `None` when the
/// name has no TXT record. Production: [`SystemResolver`]; tests: a map.
pub trait TxtLookup: Send + Sync {
    fn txt<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<String>, String>> + Send + 'a>>;
}

/// How a walk is bounded: TXT lookups below the root, tree depth, wall time.
/// The Java twin's 512 / 16, and a deadline a shade over its 10 s + grace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkLimits {
    pub max_lookups: usize,
    pub max_depth: usize,
    pub deadline: Duration,
}

impl Default for WalkLimits {
    fn default() -> Self {
        WalkLimits {
            max_lookups: 512,
            max_depth: 16,
            deadline: Duration::from_secs(15),
        }
    }
}

/// What one walk found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalkReport {
    /// The root's sequence number.
    pub seq: u64,
    /// TXT lookups made below the root (failed ones included).
    pub lookups: usize,
    /// `enr:` leaves met.
    pub leaves: usize,
    /// Leaves on our chain (or not placed on another) that name a TCP port.
    pub candidates: Vec<DnsNode>,
    /// Compatible leaves that name a UDP port but no TCP port: discv4 seeds,
    /// never dial candidates.
    pub discovery_only: Vec<SocketAddr>,
    /// Leaves the fork filter placed on another chain.
    pub foreign: usize,
    /// Leaves that did not decode (bad signature, no secp256k1 key, no address).
    pub unusable: usize,
    /// Records whose text did not hash to their label.
    pub mismatched: usize,
    /// Links met in the `e=` subtree (ignored).
    pub links: usize,
    /// The deadline cut the walk short.
    pub timed_out: bool,
}

/// Walk `url`'s `e=` subtree depth-first in random order within `limits`,
/// judging each leaf's `eth` entry with `filter` at `now_secs`. Fails only
/// when the root is missing or does not verify — a tree with no verified root
/// is no tree; everything below is best-effort and counted.
pub async fn walk(
    resolver: &dyn TxtLookup,
    url: &EnrTreeUrl,
    limits: WalkLimits,
    filter: &ForkFilter,
    now_secs: u64,
) -> Result<WalkReport, String> {
    let started = tokio::time::Instant::now();
    let root_txt = resolver
        .txt(&url.domain)
        .await
        .map_err(|e| format!("{}: root lookup failed: {e}", url.domain))?
        .ok_or_else(|| format!("{}: no root TXT record", url.domain))?;
    let root = parse_root(&root_txt, &url.pubkey).map_err(|e| format!("{}: {e}", url.domain))?;
    let mut report = WalkReport {
        seq: root.seq,
        ..WalkReport::default()
    };
    let mut stack: Vec<(String, usize)> = vec![(root.enr_root, 0)];
    let mut visited: HashSet<String> = HashSet::new();
    while let Some((label, depth)) = stack.pop() {
        if started.elapsed() >= limits.deadline {
            report.timed_out = true;
            break;
        }
        if report.lookups >= limits.max_lookups {
            break;
        }
        // Loop protection first: a label met twice is never fetched twice.
        if !visited.insert(label.to_ascii_uppercase()) {
            continue;
        }
        if depth > limits.max_depth {
            continue;
        }
        report.lookups += 1;
        let name = format!("{label}.{}", url.domain);
        let txt = match resolver.txt(&name).await {
            Ok(Some(t)) => t,
            Ok(None) => {
                tracing::debug!(%name, "dns tree: no record");
                continue;
            }
            Err(e) => {
                tracing::debug!(%name, "dns tree: lookup failed: {e}");
                continue;
            }
        };
        let txt = txt.trim();
        // The label is the record's hash: a record that does not hash to it
        // was not published under this root.
        if !label_of(txt).eq_ignore_ascii_case(&label) {
            report.mismatched += 1;
            tracing::debug!(%name, "dns tree: record does not hash to its label");
            continue;
        }
        match parse_entry(txt) {
            Ok(Entry::Branch(mut children)) => {
                shuffle(&mut children);
                for child in children {
                    stack.push((child, depth + 1));
                }
            }
            Ok(Entry::Node(text)) => {
                report.leaves += 1;
                match parse_leaf(&text) {
                    Ok(node) => judge(node, filter, now_secs, &mut report),
                    Err(e) => {
                        report.unusable += 1;
                        tracing::debug!(%name, "dns tree: {e}");
                    }
                }
            }
            Ok(Entry::Link(_)) => report.links += 1,
            Err(e) => tracing::debug!(%name, "dns tree: {e}"),
        }
    }
    Ok(report)
}

/// Sort a decoded leaf into the report: foreign nodes are counted and dropped,
/// the rest are dial candidates or, without a TCP port, discv4 seeds.
fn judge(node: DnsNode, filter: &ForkFilter, now_secs: u64, report: &mut WalkReport) {
    if filter.verdict(node.eth.as_deref(), now_secs) == Verdict::Foreign {
        report.foreign += 1;
        return;
    }
    if node.tcp.is_some() {
        report.candidates.push(node);
    } else if let Some(udp) = node.udp_addr() {
        report.discovery_only.push(udp);
    } else {
        report.unusable += 1;
    }
}

/// Fisher–Yates with the OS's randomness (the same source discv4's refresh
/// samples with); a tree larger than one walk's budget is seen in a different
/// part each walk, as EIP-1459 asks.
fn shuffle<T>(items: &mut [T]) {
    let mut rnd = [0u8; 8];
    for i in (1..items.len()).rev() {
        let _ = getrandom::getrandom(&mut rnd);
        let j = (u64::from_le_bytes(rnd) % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
}

// ---------------------------------------------------------------------------
// The system resolver.
// ---------------------------------------------------------------------------

/// Per-lookup timeout (the Java twin's).
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// The platform's resolver configuration (`/etc/resolv.conf` on unix, the
/// registry on Windows), one TXT query at a time. hickory is already compiled
/// in through libp2p's DNS transport, so this adds no dependency.
pub struct SystemResolver {
    inner: hickory_resolver::TokioResolver,
}

impl SystemResolver {
    /// `Err` where the platform offers no resolver configuration — Android has
    /// had no `/etc/resolv.conf` since Oreo (see `reqresp.rs`) — in which case
    /// DNS discovery is simply unavailable, and says so once.
    pub fn new() -> Result<SystemResolver, String> {
        let mut builder = hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|e| format!("system resolver: {e}"))?;
        let opts = builder.options_mut();
        opts.timeout = LOOKUP_TIMEOUT;
        opts.attempts = 1;
        Ok(SystemResolver {
            inner: builder.build(),
        })
    }
}

impl TxtLookup for SystemResolver {
    fn txt<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<String>, String>> + Send + 'a>> {
        Box::pin(async move {
            // Fully qualified: no search-list suffixing, one query.
            let fqdn = format!("{name}.");
            match self.inner.txt_lookup(fqdn).await {
                // One record per name in a tree; its segments concatenate
                // (TXT strings are at most 255 bytes, a long ENR is split).
                Ok(lookup) => Ok(lookup.iter().next().map(|txt| {
                    txt.txt_data()
                        .iter()
                        .map(|seg| String::from_utf8_lossy(seg))
                        .collect::<String>()
                })),
                Err(e) if e.is_no_records_found() || e.is_nx_domain() => Ok(None),
                Err(e) => Err(e.to_string()),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// The seeder: walks on a schedule, holds the candidates, hands out batches.
// ---------------------------------------------------------------------------

/// How long a pool that stays below target waits before walking the tree
/// again (Java `DNS_REFRESH_INTERVAL_MS`).
pub const DNS_REFRESH_INTERVAL: Duration = Duration::from_secs(4 * 60);
/// Candidates kept across walks (Java `DNS_POOL_MAX`).
pub const DNS_POOL_MAX: usize = 600;
/// Candidates offered to the dialer per maintainer tick (10 s): six ticks a
/// minute make the Java twin's 60 dials a minute.
pub const DNS_DIAL_BATCH: usize = 10;
/// UDP endpoints from one walk nudged into discv4 (`probe`), so a tree seeds
/// the DHT walk too — the discv4-independent source #414 and #422 lacked.
pub const DNS_PROBE_MAX: usize = 32;

/// Where a walk's TXT lookups go: the system resolver, built fresh per walk so
/// a changed network configuration is picked up, or a fixed one (tests).
pub enum ResolverSource {
    System,
    Fixed(Arc<dyn TxtLookup>),
}

#[derive(Debug, Default)]
struct SeedState {
    pool: Vec<Enode>,
    cursor: usize,
    last_walk: Option<tokio::time::Instant>,
    walking: bool,
    /// The system resolver was found unusable (no configuration): said once.
    resolver_unavailable: bool,
}

/// The network's trees, the filter that judges their leaves, and the
/// candidates the last walks produced.
pub struct DnsSeeder {
    urls: Vec<EnrTreeUrl>,
    filter: ForkFilter,
    source: ResolverSource,
    limits: WalkLimits,
    state: Mutex<SeedState>,
}

impl DnsSeeder {
    /// `None` when no URL parses (a network without a tree passes none).
    pub fn new(urls: &[String], filter: ForkFilter) -> Option<DnsSeeder> {
        Self::with_source(urls, filter, ResolverSource::System, WalkLimits::default())
    }

    pub fn with_source(
        urls: &[String],
        filter: ForkFilter,
        source: ResolverSource,
        limits: WalkLimits,
    ) -> Option<DnsSeeder> {
        let parsed: Vec<EnrTreeUrl> = urls
            .iter()
            .filter_map(|u| match EnrTreeUrl::parse(u) {
                Ok(url) => Some(url),
                Err(e) => {
                    tracing::warn!("dns tree URL skipped: {e}");
                    None
                }
            })
            .collect();
        if parsed.is_empty() {
            return None;
        }
        Some(DnsSeeder {
            urls: parsed,
            filter,
            source,
            limits,
            state: Mutex::new(SeedState::default()),
        })
    }

    /// Claim the next walk if one is due: never two at once, never while the
    /// policy forbids it, the first at once, later ones only while the pool
    /// is below target and [`DNS_REFRESH_INTERVAL`] has passed. The caller
    /// that gets `true` must run [`walk_once`](Self::walk_once).
    pub fn begin_walk_if_due(
        &self,
        now: tokio::time::Instant,
        below_target: bool,
        allowed: bool,
    ) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.walking || !allowed {
            return false;
        }
        let due = match st.last_walk {
            None => true,
            Some(last) => below_target && now.duration_since(last) >= DNS_REFRESH_INTERVAL,
        };
        if due {
            st.walking = true;
        }
        due
    }

    /// Walk every tree once, merge the candidates into the pool (newest first,
    /// deduplicated by address, at most [`DNS_POOL_MAX`]), and offer up to
    /// [`DNS_PROBE_MAX`] UDP endpoints to discv4 through `probe`. Returns the
    /// candidates added. Clears the claim [`begin_walk_if_due`](Self::begin_walk_if_due) took.
    pub async fn walk_once(&self, probe: Option<&tokio::sync::mpsc::Sender<SocketAddr>>) -> usize {
        let added = self.walk_all(probe).await;
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.walking = false;
        st.last_walk = Some(tokio::time::Instant::now());
        added
    }

    async fn walk_all(&self, probe: Option<&tokio::sync::mpsc::Sender<SocketAddr>>) -> usize {
        let system;
        let resolver: &dyn TxtLookup = match &self.source {
            ResolverSource::Fixed(r) => r.as_ref(),
            ResolverSource::System => match SystemResolver::new() {
                Ok(r) => {
                    system = r;
                    &system
                }
                Err(e) => {
                    let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                    if !st.resolver_unavailable {
                        st.resolver_unavailable = true;
                        tracing::warn!("dns discovery unavailable on this host: {e}");
                    }
                    return 0;
                }
            },
        };
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut added = 0usize;
        let mut endpoints: Vec<SocketAddr> = Vec::new();
        for url in &self.urls {
            let report = match walk(resolver, url, self.limits, &self.filter, now_secs).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("dns tree: {e}");
                    continue;
                }
            };
            let fresh: Vec<Enode> = report
                .candidates
                .iter()
                .filter_map(|n| n.dial_addr().map(|a| (a, n.pubkey)))
                .collect();
            endpoints.extend(report.candidates.iter().filter_map(DnsNode::udp_addr));
            endpoints.extend(report.discovery_only.iter().copied());
            let (pool_len, new) = self.merge(&fresh);
            added += new;
            tracing::info!(
                domain = %url.domain,
                seq = report.seq,
                lookups = report.lookups,
                leaves = report.leaves,
                candidates = fresh.len(),
                new,
                foreign = report.foreign,
                discovery_only = report.discovery_only.len(),
                unusable = report.unusable,
                mismatched = report.mismatched,
                timed_out = report.timed_out,
                pool = pool_len,
                "dns tree walked (EIP-1459)"
            );
        }
        if let Some(probe) = probe {
            shuffle(&mut endpoints);
            for addr in endpoints.into_iter().take(DNS_PROBE_MAX) {
                if probe.send(addr).await.is_err() {
                    break; // discovery is gone
                }
            }
        }
        added
    }

    /// Merge fresh candidates in front of the held ones, deduplicated by
    /// address and capped; returns (pool size, candidates not held before).
    /// Crate-visible so the pool's tests can seed a pool without a walk.
    pub(crate) fn merge(&self, fresh: &[Enode]) -> (usize, usize) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let (pool, new) = merge_candidates(std::mem::take(&mut st.pool), fresh);
        st.pool = pool;
        st.cursor = 0;
        (st.pool.len(), new)
    }

    /// Up to `n` candidates, round-robin from where the last batch stopped.
    pub fn take_batch(&self, n: usize) -> Vec<Enode> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.pool.is_empty() || n == 0 {
            return Vec::new();
        }
        let len = st.pool.len();
        let start = st.cursor % len;
        let take = n.min(len);
        let batch: Vec<Enode> = (0..take).map(|i| st.pool[(start + i) % len]).collect();
        st.cursor = (start + take) % len;
        batch
    }

    /// Candidates held.
    pub fn pool_len(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).pool.len()
    }
}

/// Pure: `fresh` first, then the held candidates not among them, deduplicated
/// by address and cut to [`DNS_POOL_MAX`]; the count is of fresh candidates
/// that were not held.
pub fn merge_candidates(held: Vec<Enode>, fresh: &[Enode]) -> (Vec<Enode>, usize) {
    let mut seen: HashSet<SocketAddr> = HashSet::new();
    let mut out: Vec<Enode> = Vec::with_capacity(held.len() + fresh.len());
    for &(addr, key) in fresh {
        if seen.insert(addr) {
            out.push((addr, key));
        }
    }
    let fresh_count = out.len();
    let mut new = fresh_count;
    for (addr, key) in held {
        if seen.insert(addr) {
            out.push((addr, key));
        } else if out[..fresh_count].iter().any(|(a, _)| *a == addr) {
            new -= 1; // a fresh candidate we already held
        }
    }
    out.truncate(DNS_POOL_MAX);
    (out, new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use myotis_core::nodekey::NodeKey;
    use std::collections::HashMap;

    fn key(n: u8) -> NodeKey {
        let mut secret = [0u8; 32];
        secret[31] = n;
        NodeKey::from_secret_bytes(&secret).unwrap()
    }

    /// The EIP-1459 example URL, and the example zone (signed by another key:
    /// the one go-ethereum's `dnsdisc` test data uses, which the EIP's zone
    /// file was taken from — recovered from the root's signature).
    const SPEC_URL: &str = "enrtree://AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@nodes.example.org";
    const SPEC_ZONE_URL: &str = "enrtree://AKPYQIUQIL7PSIACI32J7FGZW56E5FKHEFCCOFHILBIMW3M6LWXS2@nodes.example.org";
    const SPEC_ROOT: &str = "enrtree-root:v1 e=JWXYDBPXYWG6FX3GMDIBFA6CJ4 l=C7HRFPF3BLGF3YR4DY5KX3SMBE seq=1 sig=o908WmNp7LibOfPsr4btQwatZJ5URBr2ZAuxvK4UWHlsB9sUOTJQaGAlLPVAhM__XJesCHxLISo94z5Z2a463gA";
    const SPEC_LINK: &str =
        "enrtree://AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@morenodes.example.org";
    const SPEC_BRANCH: &str = "enrtree-branch:2XS2367YHAXJFGLZHVAWLQD4ZY,H4FHT4B454P6UXFD7JCYQ5PWDY,MHTDO6TMUBRIA2XWG5LUDACK24";
    const SPEC_LEAVES: [&str; 3] = [
        "enr:-HW4QOFzoVLaFJnNhbgMoDXPnOvcdVuj7pDpqRvh6BRDO68aVi5ZcjB3vzQRZH2IcLBGHzo8uUN3snqmgTiE56CH3AMBgmlkgnY0iXNlY3AyNTZrMaECC2_24YYkYHEgdzxlSNKQEnHhuNAbNlMlWJxrJxbAFvA",
        "enr:-HW4QAggRauloj2SDLtIHN1XBkvhFZ1vtf1raYQp9TBW2RD5EEawDzbtSmlXUfnaHcvwOizhVYLtr7e6vw7NAf6mTuoCgmlkgnY0iXNlY3AyNTZrMaECjrXI8TLNXU0f8cthpAMxEshUyQlK-AM0PW2wfrnacNI",
        "enr:-HW4QLAYqmrwllBEnzWWs7I5Ev2IAs7x_dZlbYdRdMUx5EyKHDXp7AV5CkuPGUPdvbv1_Ms1CPfhcGCvSElSosZmyoqAgmlkgnY0iXNlY3AyNTZrMaECriawHKWdDRk2xeZkrOXBQ0dfMFLHY4eENZwdufn1S1o",
    ];

    #[test]
    fn base32_round_trips_the_rfc_4648_vectors() {
        let vectors: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "MY"),
            (b"fo", "MZXQ"),
            (b"foo", "MZXW6"),
            (b"foob", "MZXW6YQ"),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI"),
        ];
        for (bytes, text) in vectors {
            assert_eq!(base32_encode(bytes), text);
            assert_eq!(base32_decode(text).unwrap(), bytes);
            // Padded and lower-case input decode too.
            let padded = format!("{text}{}", "=".repeat((8 - text.len() % 8) % 8));
            assert_eq!(base32_decode(&padded).unwrap(), bytes);
            assert_eq!(base32_decode(&text.to_ascii_lowercase()).unwrap(), bytes);
        }
        assert!(base32_decode("MZ1W").is_err()); // '1' is not in the alphabet
    }

    #[test]
    fn the_spec_url_parses_to_its_key() {
        let url = EnrTreeUrl::parse(SPEC_URL).unwrap();
        assert_eq!(url.domain, "nodes.example.org");
        // The key is the 33-byte compressed point `03 3a 51 41 76 …` (the EIP's
        // prose quotes an uncompressed key that is not this one; the URL is
        // what clients decode): decompressed here, it compresses back to the
        // URL's base32.
        assert_eq!(&url.pubkey[..4], &[0x3a, 0x51, 0x41, 0x76]);
        let compressed = myotis_core::nodekey::compress_public_key(&url.pubkey).unwrap();
        assert_eq!(compressed[0], 0x03);
        assert_eq!(base32_encode(&compressed), "AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2");
        for bad in [
            "enrtree://nodes.example.org",
            "enrtree://@nodes.example.org",
            "enrtree://AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@",
            "enrtree://AAAAAA@example.com",
            "enr://AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@nodes.example.org",
            "enrtree://AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@nodes.example.org/x",
        ] {
            assert!(EnrTreeUrl::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn labels_are_the_base32_of_the_abbreviated_keccak_of_the_record() {
        // The EIP example: every record hashes to the label it is served under.
        assert_eq!(label_of(SPEC_BRANCH), "JWXYDBPXYWG6FX3GMDIBFA6CJ4");
        assert_eq!(label_of(SPEC_LINK), "C7HRFPF3BLGF3YR4DY5KX3SMBE");
        assert_eq!(label_of(SPEC_LEAVES[0]), "2XS2367YHAXJFGLZHVAWLQD4ZY");
        assert_eq!(label_of(SPEC_LEAVES[1]), "H4FHT4B454P6UXFD7JCYQ5PWDY");
        assert_eq!(label_of(SPEC_LEAVES[2]), "MHTDO6TMUBRIA2XWG5LUDACK24");
    }

    #[test]
    fn the_spec_root_verifies_under_the_spec_key_only() {
        let url = EnrTreeUrl::parse(SPEC_ZONE_URL).unwrap();
        let root = parse_root(SPEC_ROOT, &url.pubkey).unwrap();
        assert_eq!(
            root,
            Root {
                enr_root: "JWXYDBPXYWG6FX3GMDIBFA6CJ4".into(),
                link_root: "C7HRFPF3BLGF3YR4DY5KX3SMBE".into(),
                seq: 1,
            }
        );
        // Another key — the one in the EIP's URL example, or any other: refused.
        assert!(parse_root(SPEC_ROOT, &EnrTreeUrl::parse(SPEC_URL).unwrap().pubkey).is_err());
        assert!(parse_root(SPEC_ROOT, &key(1).public_key_bytes()).is_err());
        // A changed byte in the signed text: refused.
        assert!(parse_root(&SPEC_ROOT.replace("seq=1", "seq=2"), &url.pubkey).is_err());
        // Shapes that are not a root.
        assert!(parse_root("enrtree-branch:AAAA", &url.pubkey).is_err());
        assert!(parse_root("enrtree-root:v1 e=A l=B seq=1", &url.pubkey).is_err()); // no sig
        assert!(parse_root(
            "enrtree-root:v1 e=A seq=1 sig=o908WmNp7LibOfPsr4btQwatZJ5URBr2ZAuxvK4UWHlsB9sUOTJQaGAlLPVAhM__XJesCHxLISo94z5Z2a463gA",
            &url.pubkey
        )
        .is_err()); // no l=
        assert!(parse_root("enrtree-root:v1 e=A l=B seq=x sig=AAAA", &url.pubkey).is_err());
    }

    fn base64url_nopad(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut buf = [0u8; 3];
            buf[..chunk.len()].copy_from_slice(chunk);
            let n = (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2]);
            let chars = [n >> 18, (n >> 12) & 63, (n >> 6) & 63, n & 63];
            for (i, c) in chars.iter().enumerate() {
                if i <= chunk.len() {
                    out.push(ALPHABET[*c as usize] as char);
                }
            }
        }
        out
    }

    /// Sign a root whose fields are `body` for `signer`.
    fn sign_root_text(signer: &NodeKey, body: &str) -> String {
        let signed = format!("{ROOT_PREFIX}{body}");
        let sig = signer.sign_hash(&keccak256(signed.as_bytes())).unwrap();
        format!("{signed} sig={}", base64url_nopad(&sig))
    }

    /// Sign a root for `signer`.
    fn signed_root(signer: &NodeKey, enr_root: &str, link_root: &str, seq: u64) -> String {
        sign_root_text(signer, &format!("e={enr_root} l={link_root} seq={seq}"))
    }

    #[test]
    fn our_own_root_verifies_padded_or_not() {
        let signer = key(7);
        let root = signed_root(&signer, "AAAA", "BBBB", 42);
        let parsed = parse_root(&root, &signer.public_key_bytes()).unwrap();
        assert_eq!((parsed.enr_root.as_str(), parsed.link_root.as_str(), parsed.seq), ("AAAA", "BBBB", 42));
        // Padded base64 (what some zone tools write) is accepted too.
        let padded = format!("{root}=");
        assert!(parse_root(&padded, &signer.public_key_bytes()).is_ok());
        // Unknown fields are ignored and field order is free — within what the
        // signature covers.
        let odd = sign_root_text(&signer, "seq=42 x=1 l=BBBB e=AAAA");
        let parsed = parse_root(&odd, &signer.public_key_bytes()).unwrap();
        assert_eq!((parsed.enr_root.as_str(), parsed.link_root.as_str(), parsed.seq), ("AAAA", "BBBB", 42));
        // The signed text altered after signing: refused.
        let altered = root.replace("l=BBBB", "l=CCCC");
        assert!(parse_root(&altered, &signer.public_key_bytes()).is_err());
    }

    #[test]
    fn entries_parse_by_prefix() {
        assert_eq!(
            parse_entry("enrtree-branch:AAAA, BBBB,,CCCC").unwrap(),
            Entry::Branch(vec!["AAAA".into(), "BBBB".into(), "CCCC".into()])
        );
        assert_eq!(parse_entry(SPEC_LEAVES[0]).unwrap(), Entry::Node(SPEC_LEAVES[0].into()));
        assert_eq!(parse_entry(SPEC_LINK).unwrap(), Entry::Link(SPEC_LINK.into()));
        assert!(parse_entry("v=spf1 -all").is_err());
    }

    #[test]
    fn the_spec_leaves_decode_but_name_no_address() {
        // The example records carry an identity only: verified, decoded, and
        // nobody's dial candidate.
        for leaf in SPEC_LEAVES {
            let e = parse_leaf(leaf).unwrap_err();
            assert!(e.contains("no address"), "{e}");
        }
        // A tampered record fails its signature check.
        let mut tampered = SPEC_LEAVES[0].to_string();
        tampered.replace_range(tampered.len() - 2.., "AA");
        assert!(parse_leaf(&tampered).unwrap_err().contains("leaf:"));
        assert!(parse_leaf("enr:").is_err());
    }

    /// A node record for tests: `signer`'s identity at `ip`, with the ports
    /// and `eth` entry given (`None` leaves the key out).
    fn record(signer: &NodeKey, ip: IpAddr, tcp: Option<u16>, udp: Option<u16>, eth: Option<Vec<u8>>) -> String {
        let mut secret = signer.secret_bytes();
        let signing = CombinedKey::secp256k1_from_bytes(&mut secret).unwrap();
        let mut b = Enr::<CombinedKey>::builder();
        b.seq(3).ip(ip);
        match ip {
            IpAddr::V4(_) => {
                if let Some(p) = tcp {
                    b.tcp4(p);
                }
                if let Some(p) = udp {
                    b.udp4(p);
                }
            }
            IpAddr::V6(_) => {
                if let Some(p) = tcp {
                    b.tcp6(p);
                }
                if let Some(p) = udp {
                    b.udp6(p);
                }
            }
        }
        if let Some(eth) = eth {
            b.add_value_rlp("eth", alloy_rlp::Bytes::from(eth));
        }
        b.build(&signing).unwrap().to_base64()
    }

    #[test]
    fn a_leaf_yields_the_dial_key_address_ports_and_fork_id() {
        use crate::el::enrfilter::eth_entry_rlp;
        let eth = eth_entry_rlp([1, 2, 3, 4], 0);
        let v4 = record(&key(2), "10.0.0.2".parse().unwrap(), Some(30303), Some(30301), Some(eth.clone()));
        let node = parse_leaf(&v4).unwrap();
        assert_eq!(node.pubkey, key(2).public_key_bytes());
        assert_eq!(node.dial_addr(), Some("10.0.0.2:30303".parse().unwrap()));
        assert_eq!(node.udp_addr(), Some("10.0.0.2:30301".parse().unwrap()));
        assert_eq!(node.eth.as_deref(), Some(&eth[..]));
        assert_eq!(node.seq, 3);
        // v6 with its own ports; no eth entry.
        let v6 = record(&key(3), "2001:db8::7".parse().unwrap(), Some(30306), None, None);
        let node = parse_leaf(&v6).unwrap();
        assert_eq!(node.dial_addr(), Some("[2001:db8::7]:30306".parse().unwrap()));
        assert_eq!(node.udp_addr(), None);
        assert!(node.eth.is_none());
        // No TCP port: a discovery-only node.
        let udp_only = record(&key(4), "10.0.0.4".parse().unwrap(), None, Some(30303), None);
        let node = parse_leaf(&udp_only).unwrap();
        assert_eq!(node.dial_addr(), None);
        assert_eq!(node.udp_addr(), Some("10.0.0.4:30303".parse().unwrap()));
        // Port 0 is no port.
        let zero = record(&key(5), "10.0.0.5".parse().unwrap(), Some(0), Some(0), None);
        let node = parse_leaf(&zero).unwrap();
        assert_eq!((node.tcp, node.udp), (None, None));
    }

    /// An in-memory zone: name → TXT.
    struct Zone(HashMap<String, String>);

    impl TxtLookup for Zone {
        fn txt<'a>(
            &'a self,
            name: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<String>, String>> + Send + 'a>> {
            Box::pin(async move {
                if name.starts_with("LOOKUPFAILS") {
                    return Err("servfail".to_string());
                }
                Ok(self.0.get(name).cloned())
            })
        }
    }

    /// A zone for `domain` from `records` (their labels computed), signed by
    /// `signer`, with the given extra root-level entries.
    fn make_zone(signer: &NodeKey, domain: &str, enr_root: &str, records: &[&str]) -> (Zone, EnrTreeUrl) {
        let mut map = HashMap::new();
        for r in records {
            map.insert(format!("{}.{domain}", label_of(r)), r.to_string());
        }
        map.insert(domain.to_string(), signed_root(signer, enr_root, "LINKS", 9));
        let compressed = myotis_core::nodekey::compress_public_key(&signer.public_key_bytes()).unwrap();
        let url = EnrTreeUrl::parse(&format!("enrtree://{}@{domain}", base32_encode(&compressed))).unwrap();
        (Zone(map), url)
    }

    fn filter() -> ForkFilter {
        ForkFilter::for_chain([1, 2, 3, 4], 0)
    }

    #[tokio::test]
    async fn the_walk_judges_leaves_and_counts_the_rest() {
        use crate::el::enrfilter::eth_entry_rlp;
        let signer = key(9);
        let ours = eth_entry_rlp([1, 2, 3, 4], 0);
        let theirs = eth_entry_rlp([9, 9, 9, 9], 0);
        let compatible = record(&key(11), "10.0.0.11".parse().unwrap(), Some(30303), Some(30303), Some(ours.clone()));
        let unknown = record(&key(12), "10.0.0.12".parse().unwrap(), Some(30303), None, None);
        let foreign = record(&key(13), "10.0.0.13".parse().unwrap(), Some(30303), None, Some(theirs));
        let discovery_only = record(&key(14), "10.0.0.14".parse().unwrap(), None, Some(30301), Some(ours));
        let leaves = [compatible.as_str(), unknown.as_str(), foreign.as_str(), discovery_only.as_str()];
        let lower = format!("enrtree-branch:{},{}", label_of(leaves[2]), label_of(leaves[3]));
        let upper = format!(
            "enrtree-branch:{},{},{},{}",
            label_of(leaves[0]),
            label_of(leaves[1]),
            label_of(&lower),
            label_of(SPEC_LINK) // a link in the e= subtree: ignored, counted
        );
        let records = [leaves[0], leaves[1], leaves[2], leaves[3], lower.as_str(), upper.as_str(), SPEC_LINK];
        let (zone, url) = make_zone(&signer, "tree.test", &label_of(&upper), &records);
        let report = walk(&zone, &url, WalkLimits::default(), &filter(), 1_700_000_000).await.unwrap();
        assert_eq!(report.seq, 9);
        assert_eq!(report.lookups, 7, "every record fetched once: {report:?}");
        assert_eq!(report.leaves, 4);
        let mut got: Vec<SocketAddr> = report.candidates.iter().filter_map(DnsNode::dial_addr).collect();
        got.sort();
        assert_eq!(got, vec!["10.0.0.11:30303".parse().unwrap(), "10.0.0.12:30303".parse().unwrap()]);
        assert_eq!(report.foreign, 1);
        assert_eq!(report.discovery_only, vec!["10.0.0.14:30301".parse().unwrap()]);
        assert_eq!(report.links, 1);
        assert_eq!((report.unusable, report.mismatched), (0, 0));
        assert!(!report.timed_out);
    }

    #[tokio::test]
    async fn the_walk_drops_what_does_not_hash_to_its_label_and_survives_gaps() {
        let signer = key(9);
        let good = record(&key(21), "10.0.0.21".parse().unwrap(), Some(30303), None, None);
        let forged = record(&key(22), "10.0.0.22".parse().unwrap(), Some(30303), None, None);
        // A sub-branch that also names the good leaf: referenced twice,
        // fetched once.
        let sub = format!("enrtree-branch:{}", label_of(&good));
        // The top branch names the good leaf, the sub-branch, a label the
        // forged record does not hash to, a label nobody serves, and a label
        // whose lookup fails.
        let top = format!(
            "enrtree-branch:{},{},FORGEDLABEL00000000000000,MISSINGLABEL0000000000000,LOOKUPFAILS00000000000000",
            label_of(&good),
            label_of(&sub),
        );
        let (mut zone, url) = make_zone(&signer, "tree.test", &label_of(&top), &[good.as_str(), sub.as_str(), top.as_str()]);
        zone.0.insert("FORGEDLABEL00000000000000.tree.test".into(), forged);
        let report = walk(&zone, &url, WalkLimits::default(), &filter(), 1_700_000_000).await.unwrap();
        assert_eq!(report.candidates.len(), 1, "{report:?}");
        assert_eq!(report.mismatched, 1, "the forged record is dropped");
        // top + good + sub + forged + missing + failing: six lookups, the leaf
        // once although two branches name it.
        assert_eq!(report.lookups, 6);
        assert_eq!(report.leaves, 1);
    }

    #[tokio::test]
    async fn the_walk_is_bounded_by_lookups_depth_and_the_root() {
        let signer = key(9);
        // A chain of ten branches ending in a leaf at depth 10 — within the
        // default depth cap, below a cap of 5.
        let leaf = record(&key(31), "10.0.0.31".parse().unwrap(), Some(30303), None, None);
        let mut records = vec![leaf.clone()];
        let mut child = label_of(&leaf);
        for _ in 0..10 {
            let branch = format!("enrtree-branch:{child}");
            child = label_of(&branch);
            records.push(branch);
        }
        let refs: Vec<&str> = records.iter().map(String::as_str).collect();
        let (zone, url) = make_zone(&signer, "deep.test", &child, &refs);
        let shallow = WalkLimits { max_depth: 5, ..WalkLimits::default() };
        let report = walk(&zone, &url, shallow, &filter(), 1_700_000_000).await.unwrap();
        assert_eq!(report.candidates.len(), 0, "the leaf sits below the depth cap");
        assert_eq!(report.lookups, 6, "depths 0..=5 are fetched");
        let few = WalkLimits { max_lookups: 3, ..WalkLimits::default() };
        let report = walk(&zone, &url, few, &filter(), 1_700_000_000).await.unwrap();
        assert_eq!(report.lookups, 3);
        let report = walk(&zone, &url, WalkLimits::default(), &filter(), 1_700_000_000).await.unwrap();
        assert_eq!(report.candidates.len(), 1);
        // No root, or a root under another key: no walk at all.
        let (zone, _) = make_zone(&signer, "other.test", &child, &refs);
        let wrong = EnrTreeUrl { domain: "other.test".into(), pubkey: key(1).public_key_bytes() };
        assert!(walk(&zone, &wrong, WalkLimits::default(), &filter(), 0).await.is_err());
        let missing = EnrTreeUrl { domain: "nowhere.test".into(), pubkey: url.pubkey };
        assert!(walk(&zone, &missing, WalkLimits::default(), &filter(), 0).await.is_err());
    }

    #[test]
    fn candidates_merge_newest_first_deduplicated_and_capped() {
        let e = |n: u16| -> Enode { (SocketAddr::from(([10, 0, 0, 1], n)), [n as u8; 64]) };
        let (pool, new) = merge_candidates(vec![e(1), e(2)], &[e(2), e(3), e(3)]);
        assert_eq!(pool, vec![e(2), e(3), e(1)]);
        assert_eq!(new, 1, "only 3 was not held");
        let many: Vec<Enode> = (1..=700).map(e).collect();
        let (pool, new) = merge_candidates(Vec::new(), &many);
        assert_eq!(pool.len(), DNS_POOL_MAX);
        assert_eq!(new, 700);
    }

    #[test]
    fn the_seeder_schedules_walks_and_hands_out_batches_round_robin() {
        let seeder = DnsSeeder::with_source(
            &[SPEC_URL.to_string(), "garbage".to_string()],
            filter(),
            ResolverSource::Fixed(Arc::new(Zone(HashMap::new()))),
            WalkLimits::default(),
        )
        .unwrap();
        assert_eq!(seeder.urls.len(), 1, "an unparsable URL is skipped");
        let t0 = tokio::time::Instant::now();
        // Forbidden: never due. Allowed: the first walk is due at once, and
        // claimed exactly once.
        assert!(!seeder.begin_walk_if_due(t0, true, false));
        assert!(seeder.begin_walk_if_due(t0, false, true));
        assert!(!seeder.begin_walk_if_due(t0, true, true), "one walk at a time");
        {
            let mut st = seeder.state.lock().unwrap();
            st.walking = false;
            st.last_walk = Some(t0);
        }
        // Then only below target, and only after the interval.
        assert!(!seeder.begin_walk_if_due(t0 + DNS_REFRESH_INTERVAL, false, true));
        assert!(!seeder.begin_walk_if_due(t0 + DNS_REFRESH_INTERVAL / 2, true, true));
        assert!(seeder.begin_walk_if_due(t0 + DNS_REFRESH_INTERVAL, true, true));
        // Batches rotate through the pool and wrap.
        let e = |n: u16| -> Enode { (SocketAddr::from(([10, 0, 0, 2], n)), [n as u8; 64]) };
        seeder.merge(&[e(1), e(2), e(3)]);
        assert_eq!(seeder.take_batch(2), vec![e(1), e(2)]);
        assert_eq!(seeder.take_batch(2), vec![e(3), e(1)]);
        assert_eq!(seeder.take_batch(5), vec![e(2), e(3), e(1)]);
        assert_eq!(seeder.pool_len(), 3);
        assert!(DnsSeeder::new(&[], filter()).is_none());
        assert!(DnsSeeder::new(&["nonsense".to_string()], filter()).is_none());
    }

    #[tokio::test]
    async fn a_walk_fills_the_pool_and_probes_the_endpoints() {
        use crate::el::enrfilter::eth_entry_rlp;
        let signer = key(9);
        let ours = eth_entry_rlp([1, 2, 3, 4], 0);
        let a = record(&key(41), "10.0.0.41".parse().unwrap(), Some(30303), Some(30303), Some(ours.clone()));
        let b = record(&key(42), "10.0.0.42".parse().unwrap(), None, Some(30304), Some(ours));
        let branch = format!("enrtree-branch:{},{}", label_of(&a), label_of(&b));
        let (zone, url) = make_zone(&signer, "seed.test", &label_of(&branch), &[a.as_str(), b.as_str(), branch.as_str()]);
        let compressed = myotis_core::nodekey::compress_public_key(&signer.public_key_bytes()).unwrap();
        let url_text = format!("enrtree://{}@{}", base32_encode(&compressed), url.domain);
        let seeder = DnsSeeder::with_source(
            &[url_text],
            filter(),
            ResolverSource::Fixed(Arc::new(zone)),
            WalkLimits::default(),
        )
        .unwrap();
        let (probe_tx, mut probe_rx) = tokio::sync::mpsc::channel(8);
        assert!(seeder.begin_walk_if_due(tokio::time::Instant::now(), true, true));
        let added = seeder.walk_once(Some(&probe_tx)).await;
        assert_eq!(added, 1, "one node names a TCP port");
        assert_eq!(seeder.take_batch(5), vec![("10.0.0.41:30303".parse().unwrap(), key(41).public_key_bytes())]);
        let mut probed = Vec::new();
        while let Ok(addr) = probe_rx.try_recv() {
            probed.push(addr);
        }
        probed.sort();
        assert_eq!(probed, vec!["10.0.0.41:30303".parse().unwrap(), "10.0.0.42:30304".parse().unwrap()]);
        // The claim is released and the walk time set.
        let st = seeder.state.lock().unwrap();
        assert!(!st.walking);
        assert!(st.last_walk.is_some());
    }
}
