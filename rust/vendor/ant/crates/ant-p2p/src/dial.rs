//! Multiaddr helpers shared between the bootnode dial path and the UI.

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};

/// For UI: first IP literal or DNS label in a multiaddr.
pub fn endpoint_host(ma: &Multiaddr) -> String {
    for p in ma {
        match p {
            Protocol::Ip4(ip) => return ip.to_string(),
            Protocol::Ip6(ip) => return ip.to_string(),
            Protocol::Dns4(d) | Protocol::Dns6(d) | Protocol::Dnsaddr(d) => {
                return d.to_string();
            }
            _ => {}
        }
    }
    String::new()
}

/// Extract the `/p2p/<peer_id>` component from a multiaddr, if present.
/// Addresses without one are skipped by the bootnode dial path: a returning
/// `ConnectionEstablished` carries the remote peer id and we need it to
/// match back to the in-flight dial.
pub fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        Protocol::P2p(id) => Some(id),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_host_returns_ipv4_literal() {
        let a: Multiaddr = "/ip4/1.2.3.4/tcp/1634".parse().unwrap();
        assert_eq!(endpoint_host(&a), "1.2.3.4");
    }

    #[test]
    fn endpoint_host_returns_dnsaddr_label() {
        let a: Multiaddr = "/dnsaddr/mainnet.ethswarm.org".parse().unwrap();
        assert_eq!(endpoint_host(&a), "mainnet.ethswarm.org");
    }

    #[test]
    fn extract_peer_id_finds_p2p() {
        let a: Multiaddr =
            "/ip4/1.2.3.4/tcp/1634/p2p/QmTxX73q8dDiVbmXU7GqMNwG3gWmjSFECuMoCsTW4xp6CK"
                .parse()
                .unwrap();
        assert!(extract_peer_id(&a).is_some());
    }

    #[test]
    fn extract_peer_id_none_without_p2p() {
        let a: Multiaddr = "/ip4/1.2.3.4/tcp/1634".parse().unwrap();
        assert!(extract_peer_id(&a).is_none());
    }
}
