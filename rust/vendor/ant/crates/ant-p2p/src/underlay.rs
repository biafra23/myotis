//! Serialize / deserialize underlay multiaddrs (Bee `bzz.SerializeUnderlays`).
//!
//! Bee 2.8 caps the number and serialized size of advertised underlays
//! per peer (`maxUnderlaysPerPeer = 20`, `maxUnderlayBytes = 2048`) and
//! rejects out-of-bound payloads up-front — see
//! [pkg/bzz/transport.go](../bee/pkg/bzz/transport.go) and
//! [pkg/bzz/underlay.go](../bee/pkg/bzz/underlay.go). We mirror both
//! limits on send and receive so a misbehaving peer can't blow our
//! buffer and we don't get silently rejected once our own listen-set
//! grows beyond the cap.

use libp2p::core::multiaddr::Protocol;
use libp2p::multiaddr::{Error as MultiaddrError, Multiaddr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use unsigned_varint::decode::Error as VarintError;

const UNDERLAY_LIST_PREFIX: u8 = 0x99;

/// Maximum number of underlay addresses we will pack into a single
/// serialized record. Matches bee 2.8 `maxUnderlaysPerPeer`.
pub const MAX_UNDERLAYS_PER_PEER: usize = 20;

/// Maximum size of the serialized underlay payload. Matches bee 2.8
/// `maxUnderlayBytes` — chosen there as ~10× the typical multiaddr
/// budget so the cap rarely bites in practice.
pub const MAX_UNDERLAY_BYTES: usize = 2048;

#[derive(Debug, thiserror::Error)]
pub enum UnderlayError {
    #[error("empty underlay bytes")]
    Empty,
    #[error("invalid multiaddr: {0}")]
    Multiaddr(#[from] MultiaddrError),
    #[error("varint: {0}")]
    Varint(#[from] VarintError),
    #[error("underlay count {0} exceeds cap of {MAX_UNDERLAYS_PER_PEER}")]
    CountExceeded(usize),
    #[error("underlay bytes {0} exceed cap of {MAX_UNDERLAY_BYTES}")]
    ByteSizeExceeded(usize),
}

/// Sort + truncate `addrs` to fit inside bee 2.8's count and byte
/// caps, prioritising IPv4 public TCP > IPv4 public WS/WSS > private >
/// loopback / non-IPv4. Mirrors `bzz.SortUnderlaysByPriority` +
/// `bzz.TruncateUnderlays`. Returns the truncated list in priority
/// order; callers should pass this into [`serialize_underlays`].
#[must_use]
pub fn truncate_underlays(addrs: &[Multiaddr]) -> Vec<Multiaddr> {
    let mut sorted: Vec<Multiaddr> = addrs.to_vec();
    sorted.sort_by_key(underlay_score);

    let mut out: Vec<Multiaddr> = Vec::with_capacity(sorted.len().min(MAX_UNDERLAYS_PER_PEER));
    // Account for the 0x99 list-prefix byte that `serialize_underlays`
    // emits when there are 2+ entries. Single-entry records use the
    // backward-compat raw multiaddr encoding (no prefix); we
    // pre-charge the prefix here as an upper bound — slightly
    // conservative for the single-entry case, exactly right for
    // multi-entry records.
    let mut total = 1_usize;
    for addr in sorted {
        if out.len() >= MAX_UNDERLAYS_PER_PEER {
            break;
        }
        let b = addr.to_vec();
        let mut enc = unsigned_varint::encode::u64_buffer();
        let v = unsigned_varint::encode::u64(b.len() as u64, &mut enc);
        let size = v.len() + b.len();
        if total + size > MAX_UNDERLAY_BYTES {
            break;
        }
        total += size;
        out.push(addr);
    }
    out
}

/// Lower score = higher priority. Matches bee 2.8 `underlayScore`:
/// - non-IPv4 +100
/// - loopback +20, else private +10
/// - transport priority: TCP 0, WS 1, WSS 2, else 3
fn underlay_score(addr: &Multiaddr) -> i32 {
    let mut score = 0;
    let mut has_ip4 = false;
    let mut is_loopback = false;
    let mut is_private = false;
    for p in addr {
        match p {
            Protocol::Ip4(ip) => {
                has_ip4 = true;
                if ip.is_loopback() {
                    is_loopback = true;
                } else if is_private_ipv4(ip) {
                    is_private = true;
                }
            }
            Protocol::Ip6(ip) => {
                if ip.is_loopback() {
                    is_loopback = true;
                } else if is_private_ipv6(ip) {
                    is_private = true;
                }
            }
            _ => {}
        }
    }
    if !has_ip4 {
        score += 100;
    }
    if is_loopback {
        score += 20;
    } else if is_private {
        score += 10;
    }
    score += transport_priority(addr);
    score
}

fn transport_priority(addr: &Multiaddr) -> i32 {
    let mut tcp = false;
    let mut ws = false;
    let mut wss = false;
    for p in addr {
        match p {
            Protocol::Tcp(_) => tcp = true,
            Protocol::Ws(_) => ws = true,
            Protocol::Wss(_) => wss = true,
            _ => {}
        }
    }
    if wss {
        2
    } else if ws {
        1
    } else if tcp {
        0
    } else {
        3
    }
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local()
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    // RFC 4193 ULA (fc00::/7) — matches `manet.IsPrivateAddr`.
    let octets = ip.octets();
    (octets[0] & 0xfe) == 0xfc
}

/// Reachability class of an IP address, from the point of view of a node
/// somewhere else on the internet. Shared by the "is our observed address
/// worth advertising" check and the "may we dial this peer underlay"
/// filter, so both agree on what "unroutable" means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpScope {
    /// Publicly routable.
    Global,
    /// Belongs to *some* private network: RFC1918, IPv4 link-local
    /// (`169.254/16`), CGNAT (`100.64/10`), IPv6 ULA (`fc00::/7`),
    /// deprecated IPv6 site-local (`fec0::/10`) and the local-use NAT64
    /// prefix (`64:ff9b:1::/48`).
    /// Only reachable from a host attached to that same network.
    Private,
    /// Never meaningful as a remote peer's address: loopback, unspecified,
    /// `0/8`, `240/4` (reserved, incl. broadcast), multicast, documentation
    /// and benchmarking ranges (`198.18/15`, `2001:2::/48`), `192.0.0/24`,
    /// IPv6 discard-only `100::/64`, and IPv6 link-local (`fe80::/10` — undialable without the zone id, which
    /// multiaddrs don't carry).
    Local,
}

/// Classify `ip`. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is classified as the
/// embedded IPv4 address.
pub(crate) fn ip_scope(ip: IpAddr) -> IpScope {
    match ip {
        IpAddr::V4(v4) => ipv4_scope(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ipv4_scope(v4);
            }
            let seg = v6.segments();
            if v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fe80::/10 link-local
                || (seg[0] & 0xffc0) == 0xfe80
                // 2001:db8::/32 and 3fff::/20 documentation (RFC 3849, RFC 9637)
                || (seg[0] == 0x2001 && seg[1] == 0x0db8)
                || (seg[0] & 0xfff0) == 0x3ff0
                // 2001:2::/48 benchmarking (RFC 5180)
                || (seg[0] == 0x2001 && seg[1] == 0x0002 && seg[2] == 0)
                // 100::/64 discard-only (RFC 6666)
                || (seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0)
            {
                IpScope::Local
            } else if is_private_ipv6(v6)
                // fec0::/10 deprecated site-local (RFC 3879)
                || (seg[0] & 0xffc0) == 0xfec0
                // 64:ff9b:1::/48 local-use NAT64 prefix (RFC 8215)
                || (seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001)
            {
                IpScope::Private
            } else {
                IpScope::Global
            }
        }
    }
}

fn ipv4_scope(ip: Ipv4Addr) -> IpScope {
    let o = ip.octets();
    if ip.is_loopback()
        || ip.is_unspecified()
        // 0.0.0.0/8 "this network"
        || o[0] == 0
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        // 192.0.0.0/24 IETF protocol assignments (RFC 6890)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 198.18.0.0/15 benchmarking (RFC 2544) — also the "fake-IP" range
        // of transparent proxies, so never a real remote host
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        // 240.0.0.0/4 reserved (RFC 1112); includes broadcast
        || o[0] >= 240
    {
        IpScope::Local
    } else if is_private_ipv4(ip) || is_cgnat_ipv4(ip) {
        IpScope::Private
    } else {
        IpScope::Global
    }
}

/// `100.64.0.0/10` shared address space (RFC 6598, carrier-grade NAT).
fn is_cgnat_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

/// True when `ip` is reachable from anywhere on the internet.
pub(crate) fn is_globally_routable_ip(ip: IpAddr) -> bool {
    ip_scope(ip) == IpScope::Global
}

/// The IP subnets this host is directly attached to (interfaces that are
/// up, non-loopback and not a host-internal virtual bridge). A peer
/// underlay in [`IpScope::Private`] space is only worth dialing when it
/// falls inside one of these — e.g. phone on
/// `192.168.1.0/24` and a bee node on the same Wi-Fi advertising
/// `192.168.1.20`. Traffic to a directly-attached subnet never leaves the
/// local network, so it can't look like a scan to an upstream provider.
#[derive(Debug, Clone, Default)]
pub(crate) struct LocalSubnets {
    /// Subnets of interfaces that are up — what [`Self::contains`] matches.
    nets: Vec<(IpAddr, u8)>,
    /// Subnets of every candidate interface, up *or* down — what
    /// [`Self::same_networks`] compares. Kept separate so a transient
    /// carrier drop (Wi-Fi reassociation clearing `IFF_RUNNING` while the
    /// address stays configured) stops same-LAN dials for its duration
    /// without reading as a network move that purges the cached same-LAN
    /// underlays.
    attached: Vec<(IpAddr, u8)>,
}

impl LocalSubnets {
    /// Snapshot the host's interfaces. `None` when enumeration failed —
    /// deliberately distinct from an empty set ("no private networks"),
    /// because the swarm loop purges its cached same-LAN underlays when
    /// the snapshot changes and a failed read is not a network move.
    pub(crate) fn from_interfaces() -> Option<Self> {
        match if_addrs::get_if_addrs() {
            Ok(ifs) => Some(Self::from_interface_list(ifs.into_iter().map(|i| {
                let up = i.is_oper_up();
                let (ip, prefix) = match i.addr {
                    if_addrs::IfAddr::V4(a) => (IpAddr::V4(a.ip), a.prefixlen),
                    if_addrs::IfAddr::V6(a) => (IpAddr::V6(a.ip), a.prefixlen),
                };
                (i.name, up, ip, prefix)
            }))),
            Err(e) => {
                tracing::debug!(target: "ant_p2p", "enumerate local interfaces: {e}");
                None
            }
        }
    }

    /// Build from `(interface name, is up, address, prefix length)` rows,
    /// keeping only the interfaces that can put us on the same LAN as a
    /// peer: up, not loopback, and not a host-internal virtual bridge (see
    /// [`is_virtual_interface`]). A down `docker0` or a live `br-…` still
    /// carries a `172.17.0.1/16`-style address, but that subnet is this
    /// host's container network — a peer advertising `172.17.0.5` is in
    /// *its* container network, not ours (issue #92).
    ///
    /// A down (not `IFF_RUNNING`) interface's address is still remembered
    /// for change detection, though: see the `attached` field.
    pub(crate) fn from_interface_list(
        ifs: impl IntoIterator<Item = (String, bool, IpAddr, u8)>,
    ) -> Self {
        let mut nets = Vec::new();
        let mut attached = Vec::new();
        for (name, up, ip, prefix) in ifs {
            if ip.to_canonical().is_loopback() || is_virtual_interface(&name) {
                continue;
            }
            attached.push((ip, prefix));
            if up {
                nets.push((ip, prefix));
            }
        }
        Self::build(nets, attached)
    }

    /// Build from `(interface address, prefix length)` pairs, all up.
    #[cfg(test)]
    pub(crate) fn from_nets(nets: Vec<(IpAddr, u8)>) -> Self {
        Self::build(nets.clone(), nets)
    }

    fn build(mut nets: Vec<(IpAddr, u8)>, mut attached: Vec<(IpAddr, u8)>) -> Self {
        for v in [&mut nets, &mut attached] {
            v.sort_unstable();
            v.dedup();
        }
        Self { nets, attached }
    }

    /// Do two snapshots describe the same attached networks, as far as
    /// same-LAN dialing is concerned? This is the swarm loop's "we moved
    /// networks" signal, so it only looks at what can change a
    /// [`filter_dialable_underlays`] verdict — the [`IpScope::Private`]
    /// subnets — and ignores interface churn that isn't a move:
    ///
    /// * global / link-local addresses are dropped (they never decide
    ///   whether a private underlay is kept), so rotating an RFC 4941
    ///   temporary global IPv6 address is not a change;
    /// * private IPv6 subnets compare by network prefix, not host address,
    ///   so a temporary ULA address rotating inside the same `/64` isn't
    ///   either;
    /// * private IPv4 subnets compare by host address *and* prefix: a new
    ///   DHCP lease inside the same `192.168.1.0/24` is the best available
    ///   hint that this may be a different LAN reusing the numbering;
    /// * an interface's up/down state is ignored — a carrier flap that keeps
    ///   the address is not a move (a real move changes or drops the
    ///   address, which is still caught).
    pub(crate) fn same_networks(&self, other: &Self) -> bool {
        self.network_key() == other.network_key()
    }

    fn network_key(&self) -> Vec<(IpAddr, u8)> {
        let mut key: Vec<(IpAddr, u8)> = self
            .attached
            .iter()
            .filter(|&&(ip, _)| ip_scope(ip) == IpScope::Private)
            .map(|&(ip, prefix)| match ip.to_canonical() {
                IpAddr::V4(v4) => (IpAddr::V4(v4), prefix),
                IpAddr::V6(v6) => (IpAddr::V6(mask_v6(v6, prefix)), prefix),
            })
            .collect();
        key.sort_unstable();
        key.dedup();
        key
    }

    /// Is `ip` inside one of the attached subnets? IPv4-mapped IPv6
    /// (`::ffff:a.b.c.d`) is matched as its embedded IPv4 address, the same
    /// way [`ip_scope`] classifies it.
    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.nets.iter().any(|&(net, prefix)| match (net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => prefix_match(&n.octets(), &a.octets(), prefix),
            (IpAddr::V6(n), IpAddr::V6(a)) => prefix_match(&n.octets(), &a.octets(), prefix),
            _ => false,
        })
    }
}

/// Interface-name prefixes of host-internal virtual networks: container
/// bridges and veth pairs (Docker, Podman, k8s CNIs) and hypervisor
/// host-only / NAT networks (`virbr*`, `vboxnet*`, `vmnet*`). Their subnets
/// are routed to a local bridge, so they never make a remote peer's private
/// address reachable. Matched case-insensitively. VPN tunnels (`tun*`,
/// `utun*`, `wg*`, `tailscale*`) are deliberately *not* listed: those do
/// reach real remote private networks.
///
/// Two families are too broad to match by prefix and are handled in
/// [`is_virtual_interface`] instead: Docker user-defined networks
/// (`br-<12 hex>` — a bare `br-` would also catch `OpenWrt`'s real LAN bridge
/// `br-lan`) and Hyper-V/WSL (`vEthernet (…)` — a Hyper-V *External*
/// switch is also `vEthernet (<name>)` and carries the host's real LAN
/// address).
const VIRTUAL_INTERFACE_PREFIXES: &[&str] = &[
    "docker", "veth", "cni", "flannel", "cali", "cilium", "weave", "kube-", "virbr", "vboxnet",
    "vmnet", "podman", "lxcbr", "lxdbr",
];

/// Hyper-V adapters that are always host-internal: the built-in NAT
/// `Default Switch`, WSL 2's switch (`WSL`, `WSL (Hyper-V firewall)`) and
/// Docker Desktop's `nat` network. Other `vEthernet (…)` adapters are
/// user-named switches — possibly an External switch bridged onto the
/// real LAN — so they are left in.
const HYPERV_INTERNAL_PREFIXES: &[&str] = &[
    "vEthernet (Default Switch)",
    "vEthernet (WSL",
    "vEthernet (nat)",
];

/// Is `name` a host-internal virtual network? A naming heuristic — it
/// catches the common defaults on Linux, macOS and Windows; anything it
/// misses can be worked around with `allow_private_dials`.
pub(crate) fn is_virtual_interface(name: &str) -> bool {
    let has_prefix = |p: &str| {
        name.get(..p.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(p))
    };
    // Hyper-V names are decided by the allowlist alone: the generic `veth`
    // prefix would otherwise swallow every `vEthernet (…)`, External
    // switches included.
    if has_prefix("vEthernet") {
        return HYPERV_INTERNAL_PREFIXES.iter().any(|p| has_prefix(p));
    }
    VIRTUAL_INTERFACE_PREFIXES.iter().any(|p| has_prefix(p)) || is_docker_network_bridge(name)
}

/// Docker names a user-defined network's bridge `br-` followed by the
/// first 12 hex characters of the network id (`br-68148f6025cd`).
fn is_docker_network_bridge(name: &str) -> bool {
    name.strip_prefix("br-")
        .is_some_and(|id| id.len() == 12 && id.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// `ip` with every bit past the first `prefix` cleared.
fn mask_v6(ip: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let bits = u32::from(prefix.min(128));
    let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
    Ipv6Addr::from(u128::from(ip) & mask)
}

/// Compare the first `prefix` bits of two equal-length octet strings. A
/// zero prefix (a default-route-sized "subnet") never matches: it would
/// admit every private address.
fn prefix_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let prefix = usize::from(prefix);
    if prefix == 0 || prefix > a.len() * 8 {
        return false;
    }
    let full = prefix / 8;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/// Keep only the peer underlays that are worth dialing from this host.
///
/// A peer's private / loopback / link-local underlays describe *its own*
/// network: from anywhere else they are unreachable or, worse, hit an
/// unrelated host on ours. Dialing them en masse (bee nodes in
/// Docker/Kubernetes advertise their pod addresses) looks like a network
/// scan to a hosting provider (issue #88). So an address survives when every
/// IP component is globally routable, or is [`IpScope::Private`] and inside
/// one of `local`'s subnets (same-LAN peer). Addresses without an IP
/// component (`/dns4/…`) pass through. `allow_private` disables the filter
/// entirely, for dev/test networks that live on one private network or
/// loopback.
pub(crate) fn filter_dialable_underlays(
    addrs: &[Multiaddr],
    local: &LocalSubnets,
    allow_private: bool,
) -> Vec<Multiaddr> {
    if allow_private {
        return addrs.to_vec();
    }
    addrs
        .iter()
        .filter(|addr| {
            addr.iter().all(|p| {
                let ip = match p {
                    Protocol::Ip4(ip) => IpAddr::V4(ip),
                    Protocol::Ip6(ip) => IpAddr::V6(ip),
                    _ => return true,
                };
                match ip_scope(ip) {
                    IpScope::Global => true,
                    IpScope::Private => local.contains(ip),
                    IpScope::Local => false,
                }
            })
        })
        .cloned()
        .collect()
}

/// Does `addr` carry an IP component in [`IpScope::Private`] space? Such an
/// address was only admitted by [`filter_dialable_underlays`] because it
/// matched the host's subnets *at the time*; it has to be re-checked (or
/// dropped) once the host's networks change.
pub(crate) fn has_private_ip(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => ip_scope(IpAddr::V4(ip)) == IpScope::Private,
        Protocol::Ip6(ip) => ip_scope(IpAddr::V6(ip)) == IpScope::Private,
        _ => false,
    })
}

/// Single-address backward-compatible encoding uses raw multiaddr bytes.
///
/// Returns the serialized form unconditionally; the cap checks live in
/// [`serialize_underlays_checked`]. Existing callers that rely on the
/// infallible signature don't change behaviour because we already feed
/// them small, hand-curated address sets.
pub fn serialize_underlays(addrs: &[Multiaddr]) -> Vec<u8> {
    if addrs.len() == 1 {
        return addrs[0].to_vec();
    }
    let mut buf = Vec::new();
    buf.push(UNDERLAY_LIST_PREFIX);
    for addr in addrs {
        let b = addr.to_vec();
        let mut enc = unsigned_varint::encode::u64_buffer();
        let v = unsigned_varint::encode::u64(b.len() as u64, &mut enc);
        buf.extend_from_slice(v);
        buf.extend_from_slice(&b);
    }
    buf
}

/// Like [`serialize_underlays`] but returns an explicit error when the
/// count / byte caps would be exceeded. Prefer this on the handshake
/// hot path so we surface the cap locally instead of letting bee 2.8
/// reject the payload mid-handshake with `ErrUnderlayCountExceeded` /
/// `ErrUnderlayByteSizeExceeded`.
pub fn serialize_underlays_checked(addrs: &[Multiaddr]) -> Result<Vec<u8>, UnderlayError> {
    if addrs.len() > MAX_UNDERLAYS_PER_PEER {
        return Err(UnderlayError::CountExceeded(addrs.len()));
    }
    let out = serialize_underlays(addrs);
    if out.len() > MAX_UNDERLAY_BYTES {
        return Err(UnderlayError::ByteSizeExceeded(out.len()));
    }
    Ok(out)
}

pub fn deserialize_underlays(data: &[u8]) -> Result<Vec<Multiaddr>, UnderlayError> {
    if data.is_empty() {
        return Err(UnderlayError::Empty);
    }
    if data.len() > MAX_UNDERLAY_BYTES {
        return Err(UnderlayError::ByteSizeExceeded(data.len()));
    }
    if data[0] == UNDERLAY_LIST_PREFIX {
        return deserialize_list(&data[1..]);
    }
    Ok(vec![Multiaddr::try_from(data.to_vec())?])
}

fn deserialize_list(data: &[u8]) -> Result<Vec<Multiaddr>, UnderlayError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        if out.len() >= MAX_UNDERLAYS_PER_PEER {
            return Err(UnderlayError::CountExceeded(out.len() + 1));
        }
        let slice = &data[i..];
        let (len, rest) = unsigned_varint::decode::u64(slice)?;
        let used = slice.len() - rest.len();
        i += used;
        let len = len as usize;
        if data.len() < i + len {
            return Err(UnderlayError::Empty);
        }
        out.push(Multiaddr::try_from(data[i..i + len].to_vec())?);
        i += len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn priority_orders_ipv4_public_tcp_first() {
        let public = ma("/ip4/1.2.3.4/tcp/1634");
        let private = ma("/ip4/10.0.0.1/tcp/1634");
        let loopback = ma("/ip4/127.0.0.1/tcp/1634");
        let ipv6 = ma("/ip6/2001:db8::1/tcp/1634");
        let wss = ma("/ip4/1.2.3.4/tcp/1634/wss");
        assert!(underlay_score(&public) < underlay_score(&private));
        assert!(underlay_score(&private) < underlay_score(&loopback));
        assert!(underlay_score(&public) < underlay_score(&ipv6));
        assert!(underlay_score(&public) < underlay_score(&wss));
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ip_scope_classifies_unroutable_ranges() {
        for g in ["1.2.3.4", "8.8.8.8", "2a01:4f8::1", "::ffff:1.2.3.4"] {
            assert_eq!(ip_scope(ip(g)), IpScope::Global, "{g}");
        }
        for p in [
            "10.233.1.2",
            "172.17.0.3",
            "192.168.1.20",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "fd00::1",
            "fc00::1",
            "::ffff:10.0.0.1",
            "fec0::1",
            "feff::1",
            "64:ff9b:1::1",
            "64:ff9b:1:ffff::1",
        ] {
            assert_eq!(ip_scope(ip(p)), IpScope::Private, "{p}");
        }
        for l in [
            "127.0.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "255.255.255.255",
            "224.0.0.1",
            "192.0.2.1",
            "::1",
            "::",
            "fe80::1",
            "febf::1",
            "ff02::1",
            "2001:db8::1",
            "3fff::1",
            "3fff:fff::1",
            "198.18.0.1",
            "198.19.255.254",
            "::ffff:198.18.5.5",
            "240.0.0.1",
            "254.1.2.3",
            "192.0.0.8",
            "2001:2::1",
            "100::1",
            "100::ffff:ffff:ffff:ffff",
        ] {
            assert_eq!(ip_scope(ip(l)), IpScope::Local, "{l}");
        }
        // Just outside CGNAT / link-local on either side.
        assert_eq!(ip_scope(ip("100.63.255.255")), IpScope::Global);
        assert_eq!(ip_scope(ip("100.128.0.0")), IpScope::Global);
        // Just outside the special-purpose ranges.
        for g in [
            "198.17.255.255",
            "198.20.0.0",
            "192.0.1.1",
            "64:ff9b::1.2.3.4", // well-known NAT64 prefix is global
            "64:ff9b:2::1",
            "2001:3::1",
            "100:0:0:1::1",
            "4000::1",
        ] {
            assert_eq!(ip_scope(ip(g)), IpScope::Global, "{g}");
        }
    }

    #[test]
    fn local_subnets_prefix_match() {
        let local = LocalSubnets::from_nets(vec![
            (ip("192.168.1.7"), 24),
            (ip("10.0.2.15"), 20),
            (ip("fd12:3456::7"), 64),
            (ip("100.101.102.103"), 32),
            (ip("172.16.0.1"), 0),
        ]);
        assert!(local.contains(ip("192.168.1.20")));
        assert!(!local.contains(ip("192.168.2.20")));
        assert!(local.contains(ip("10.0.15.255")));
        assert!(!local.contains(ip("10.0.16.0")));
        assert!(local.contains(ip("fd12:3456::99")));
        assert!(!local.contains(ip("fd12:3457::99")));
        assert!(local.contains(ip("100.101.102.103")));
        assert!(!local.contains(ip("100.101.102.104")));
        // A /0 "subnet" must not admit everything.
        assert!(!local.contains(ip("172.17.0.3")));
        // IPv4-mapped IPv6 matches as its embedded IPv4 address (the same
        // way `ip_scope` classifies it), so a same-LAN peer advertising
        // `/ip6/::ffff:192.168.1.20` is kept …
        assert!(local.contains(ip("::ffff:192.168.1.20")));
        assert!(!local.contains(ip("::ffff:192.168.2.20")));
        // … but otherwise families never cross-match.
        let v6_only = LocalSubnets::from_nets(vec![(ip("::"), 96)]);
        assert!(!v6_only.contains(ip("0.0.0.5")));
        let kept =
            filter_dialable_underlays(&[ma("/ip6/::ffff:192.168.1.20/tcp/1634")], &local, false);
        assert_eq!(kept.len(), 1);
    }

    fn iface(name: &str, up: bool, addr: &str, prefix: u8) -> (String, bool, IpAddr, u8) {
        (name.to_string(), up, ip(addr), prefix)
    }

    /// Issue #92: Docker/virtual bridges and down interfaces don't count
    /// as "same LAN".
    #[test]
    fn local_subnets_skip_virtual_and_down_interfaces() {
        let local = LocalSubnets::from_interface_list(vec![
            iface("lo", true, "127.0.0.1", 8),
            iface("docker0", true, "172.17.0.1", 16),
            iface("wlan0", true, "192.168.1.7", 24),
        ]);
        assert!(local.contains(ip("192.168.1.20")));
        assert!(!local.contains(ip("172.17.0.5")));
        let addrs = vec![
            ma("/ip4/192.168.1.20/tcp/1634"),
            ma("/ip4/172.17.0.5/tcp/1634"),
        ];
        assert_eq!(
            filter_dialable_underlays(&addrs, &local, false),
            vec![ma("/ip4/192.168.1.20/tcp/1634")],
        );
        // `allow_private_dials` stays the escape hatch.
        assert_eq!(filter_dialable_underlays(&addrs, &local, true), addrs);

        // The vibing.at shape from the issue, plus the other common
        // virtual networks; only the real LAN survives.
        let local = LocalSubnets::from_interface_list(vec![
            iface("br-68148f6025cd", true, "172.18.0.1", 16),
            iface("docker0", false, "172.17.0.1", 16),
            iface("veth1a2b3c", true, "fd00:dead::1", 64),
            iface("cni0", true, "10.42.0.1", 24),
            iface("flannel.1", true, "10.244.0.0", 32),
            iface("cali1234abcd", true, "10.233.64.1", 32),
            iface("virbr0", true, "192.168.122.1", 24),
            iface("vboxnet0", true, "192.168.56.1", 24),
            iface("podman0", true, "10.88.0.1", 16),
            iface("vEthernet (WSL)", true, "172.29.16.1", 20),
            iface("eth0", true, "10.0.0.5", 24),
        ]);
        for foreign in [
            "172.18.0.2",
            "172.17.0.2",
            "fd00:dead::2",
            "10.42.0.9",
            "10.244.0.0",
            "10.233.64.1",
            "192.168.122.5",
            "192.168.56.101",
            "10.88.0.2",
            "172.29.16.5",
        ] {
            assert!(!local.contains(ip(foreign)), "{foreign}");
        }
        assert!(local.contains(ip("10.0.0.9")));

        // Real LAN bridges that share a naming family with virtual ones:
        // OpenWrt's `br-lan`, a Hyper-V External switch.
        for lan in ["br-lan", "vEthernet (External)"] {
            let local = LocalSubnets::from_interface_list(vec![
                iface(lan, true, "192.168.1.7", 24),
                iface("br-68148f6025cd", true, "172.18.0.1", 16),
            ]);
            assert!(local.contains(ip("192.168.1.20")), "{lan}");
            assert!(!local.contains(ip("172.18.0.2")), "{lan}");
        }

        // A real interface that is down doesn't count either.
        let down = LocalSubnets::from_interface_list(vec![iface("en0", false, "192.168.1.7", 24)]);
        assert!(!down.contains(ip("192.168.1.20")));
    }

    /// A carrier drop that keeps the address (Wi-Fi reassociation clearing
    /// `IFF_RUNNING`) stops same-LAN matching while it lasts but is not a
    /// network change; losing or changing the address still is.
    #[test]
    fn local_subnets_carrier_flap_is_not_a_network_change() {
        let up = LocalSubnets::from_interface_list(vec![
            iface("wlan0", true, "192.168.1.7", 24),
            iface("docker0", true, "172.17.0.1", 16),
        ]);
        let flapped = LocalSubnets::from_interface_list(vec![
            iface("wlan0", false, "192.168.1.7", 24),
            iface("docker0", false, "172.17.0.1", 16),
        ]);
        assert!(up.contains(ip("192.168.1.20")));
        assert!(!flapped.contains(ip("192.168.1.20")));
        assert!(up.same_networks(&flapped));
        assert!(flapped.same_networks(&up));

        let gone =
            LocalSubnets::from_interface_list(vec![iface("docker0", true, "172.17.0.1", 16)]);
        assert!(!up.same_networks(&gone));
        let new_lease =
            LocalSubnets::from_interface_list(vec![iface("wlan0", false, "192.168.1.8", 24)]);
        assert!(!up.same_networks(&new_lease));
        // A virtual bridge appearing or disappearing is never a move.
        let no_docker =
            LocalSubnets::from_interface_list(vec![iface("wlan0", true, "192.168.1.7", 24)]);
        assert!(up.same_networks(&no_docker));
    }

    #[test]
    fn virtual_interface_names() {
        for v in [
            "docker0",
            "br-68148f6025cd",
            "veth9f8e7d",
            "cni0",
            "flannel.1",
            "cali0123",
            "virbr0",
            "vboxnet0",
            "vmnet8",
            "podman1",
            "vEthernet (Default Switch)",
            "VETHERNET (WSL)",
            "vEthernet (WSL (Hyper-V firewall))",
            "vEthernet (nat)",
        ] {
            assert!(is_virtual_interface(v), "{v}");
        }
        for real in [
            "eth0",
            "wlan0",
            "en0",
            "enp3s0",
            "wlp2s0",
            "Wi-Fi",
            "Ethernet",
            "utun3",
            "tun0",
            "wg0",
            "tailscale0",
            "bridge0",
            "br0",
            // OpenWrt's LAN bridge, and near-misses of Docker's `br-<12 hex>`.
            "br-lan",
            "br-wan",
            "br-68148f6025c",
            "br-68148f6025cdx",
            "br-68148f6025cg",
            // A Hyper-V External switch bridges the physical NIC and
            // carries the host's real LAN address.
            "vEthernet (External)",
            "vEthernet (Intel(R) Wi-Fi 6 AX201 160MHz Virtual Switch)",
            "",
        ] {
            assert!(!is_virtual_interface(real), "{real}");
        }
    }

    #[test]
    fn local_subnets_snapshot_equality_ignores_order() {
        let home = LocalSubnets::from_nets(vec![(ip("192.168.1.7"), 24), (ip("fd00::7"), 64)]);
        let reordered = LocalSubnets::from_nets(vec![(ip("fd00::7"), 64), (ip("192.168.1.7"), 24)]);
        assert!(home.same_networks(&reordered));
        // Same subnet, new lease → a different snapshot.
        let new_lease = LocalSubnets::from_nets(vec![(ip("192.168.1.8"), 24), (ip("fd00::7"), 64)]);
        assert!(!home.same_networks(&new_lease));
        // Moving off the private IPv6 network is a change.
        let v4_only = LocalSubnets::from_nets(vec![(ip("192.168.1.7"), 24)]);
        assert!(!home.same_networks(&v4_only));
        let other_ula =
            LocalSubnets::from_nets(vec![(ip("192.168.1.7"), 24), (ip("fd00:1::7"), 64)]);
        assert!(!home.same_networks(&other_ula));
    }

    /// R2-M1: IPv6 privacy-address rotation (RFC 4941) is not a network
    /// move — neither a new temporary global address nor a new temporary
    /// ULA address inside the same /64.
    #[test]
    fn local_subnets_ignore_ipv6_temporary_address_rotation() {
        let before = LocalSubnets::from_nets(vec![
            (ip("192.168.1.7"), 24),
            (ip("fd12:3456:789a:1::aaaa"), 64),
            (ip("2a01:4f8:1:2::1111"), 64),
            (ip("2a01:4f8:1:2:dead:beef:1:2"), 64),
            (ip("fe80::1234"), 64),
        ]);
        let after = LocalSubnets::from_nets(vec![
            (ip("192.168.1.7"), 24),
            (ip("fd12:3456:789a:1::bbbb"), 64),
            (ip("2a01:4f8:1:2::1111"), 64),
            (ip("2a01:4f8:1:2:cafe:f00d:3:4"), 64),
            (ip("fe80::5678"), 64),
        ]);
        assert!(before.same_networks(&after));
        // A whole new global prefix (different ISP) with the same private
        // LAN is still not a move as far as private underlays go.
        let new_isp = LocalSubnets::from_nets(vec![
            (ip("192.168.1.7"), 24),
            (ip("fd12:3456:789a:1::aaaa"), 64),
            (ip("2001:470:1::1"), 64),
        ]);
        assert!(before.same_networks(&new_isp));
        assert_eq!(
            mask_v6("fd12::ffff".parse().unwrap(), 0),
            Ipv6Addr::UNSPECIFIED
        );
        assert_eq!(
            mask_v6("fd12::ffff".parse().unwrap(), 128),
            "fd12::ffff".parse::<Ipv6Addr>().unwrap(),
        );
    }

    #[test]
    fn has_private_ip_flags_only_private_scope() {
        assert!(has_private_ip(&ma("/ip4/192.168.1.20/tcp/1634")));
        assert!(has_private_ip(&ma("/ip6/::ffff:10.0.0.1/tcp/1634")));
        assert!(has_private_ip(&ma("/ip6/fd00::1/tcp/1634")));
        assert!(!has_private_ip(&ma("/ip4/1.2.3.4/tcp/1634")));
        assert!(!has_private_ip(&ma("/ip4/127.0.0.1/tcp/1634")));
        assert!(!has_private_ip(&ma("/dns4/node.example.org/tcp/1634")));
    }

    #[test]
    fn filter_drops_foreign_private_underlays_keeps_same_lan() {
        let local = LocalSubnets::from_nets(vec![(ip("192.168.1.7"), 24)]);
        let addrs = vec![
            ma("/ip4/10.233.64.12/tcp/1634/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"),
            ma("/ip4/172.17.0.3/tcp/1634"),
            ma("/ip4/127.0.0.1/tcp/1634"),
            ma("/ip4/100.64.3.4/tcp/1634"),
            ma("/ip6/fe80::1/tcp/1634"),
            ma("/ip6/fd00::5/tcp/1634"),
            ma("/ip6/::1/tcp/1634"),
            ma("/ip4/192.168.1.20/tcp/1634"),
            ma("/ip4/1.2.3.4/tcp/1634"),
            ma("/ip6/2a01:4f8::1/tcp/1634"),
            ma("/dns4/node.example.org/tcp/1634"),
        ];
        let kept = filter_dialable_underlays(&addrs, &local, false);
        assert_eq!(
            kept,
            vec![
                ma("/ip4/192.168.1.20/tcp/1634"),
                ma("/ip4/1.2.3.4/tcp/1634"),
                ma("/ip6/2a01:4f8::1/tcp/1634"),
                ma("/dns4/node.example.org/tcp/1634"),
            ],
        );
        // Off the LAN, the same-subnet address goes too.
        let kept = filter_dialable_underlays(&addrs, &LocalSubnets::default(), false);
        assert!(!kept.contains(&ma("/ip4/192.168.1.20/tcp/1634")));
        // Escape hatch keeps everything.
        assert_eq!(filter_dialable_underlays(&addrs, &local, true), addrs);
    }

    #[test]
    fn truncate_drops_low_priority_when_over_cap() {
        let mut addrs: Vec<Multiaddr> = (0..MAX_UNDERLAYS_PER_PEER + 5)
            .map(|i| ma(&format!("/ip6/::1/tcp/{i}")))
            .collect();
        // One IPv4 public TCP entry should always survive truncation.
        let must_keep = ma("/ip4/1.2.3.4/tcp/1634");
        addrs.push(must_keep.clone());
        let truncated = truncate_underlays(&addrs);
        assert!(truncated.len() <= MAX_UNDERLAYS_PER_PEER);
        assert_eq!(truncated[0], must_keep);
    }

    #[test]
    fn serialize_checked_rejects_oversize_count() {
        let addrs: Vec<Multiaddr> = (0..=MAX_UNDERLAYS_PER_PEER)
            .map(|i| ma(&format!("/ip4/127.0.0.1/tcp/{i}")))
            .collect();
        let err = serialize_underlays_checked(&addrs).unwrap_err();
        matches!(err, UnderlayError::CountExceeded(_));
    }

    #[test]
    fn deserialize_rejects_oversize_payload() {
        let oversize = vec![0u8; MAX_UNDERLAY_BYTES + 1];
        let err = deserialize_underlays(&oversize).unwrap_err();
        matches!(err, UnderlayError::ByteSizeExceeded(_));
    }

    #[test]
    fn deserialize_rejects_too_many_entries() {
        let mut buf = vec![UNDERLAY_LIST_PREFIX];
        let addr = ma("/ip4/127.0.0.1/tcp/1");
        let b = addr.to_vec();
        let mut enc = unsigned_varint::encode::u64_buffer();
        let v = unsigned_varint::encode::u64(b.len() as u64, &mut enc).to_vec();
        for _ in 0..=MAX_UNDERLAYS_PER_PEER {
            buf.extend_from_slice(&v);
            buf.extend_from_slice(&b);
        }
        if buf.len() > MAX_UNDERLAY_BYTES {
            // Test would conflate two limits; keep the byte budget below
            // the size cap so the count cap is the one that fires.
            buf.truncate(MAX_UNDERLAY_BYTES);
        }
        let err = deserialize_underlays(&buf).unwrap_err();
        matches!(err, UnderlayError::CountExceeded(_));
    }
}
