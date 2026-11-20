//! Recursive `/dnsaddr/` multiaddr resolution.
//!
//! Unlike `libp2p-dns`'s transport — which resolves one TXT chain per dial and
//! picks a single winner — this walks the entire `_dnsaddr.<domain>` TXT tree
//! up front and returns every leaf multiaddr. That matches how Swarm publishes
//! bootnodes: `/dnsaddr/mainnet.ethswarm.org` fans out through a per-region
//! chain into multiple concrete peer addresses, and we want to dial them in
//! parallel.
//!
//! Design adopted from nxm-rs/vertex (`crates/net/dnsaddr`).
//!
//! The resolver uses the system nameservers but strips any search domains so
//! captive-portal / intranet suffixes never end up concatenated onto public
//! Swarm FQDNs. Falls back to Cloudflare if `/etc/resolv.conf` is unreadable.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use libp2p::multiaddr::{Multiaddr, Protocol};
use thiserror::Error;
use tracing::{debug, warn};

/// Recursion cap — the Swarm tree is ~3 levels deep; anything beyond 10 is a loop.
const MAX_RECURSION_DEPTH: usize = 10;

/// True if this multiaddr contains a `/dnsaddr/<domain>` component.
#[must_use]
pub fn is_dnsaddr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::Dnsaddr(_)))
}

/// Expand every `/dnsaddr/` in `addrs` into concrete leaf multiaddrs.
///
/// - Non-dnsaddr entries pass through untouched.
/// - A shared `seen` set deduplicates TXT targets across the whole batch,
///   so identical sub-trees aren't re-walked and CNAME-style cycles terminate.
/// - On lookup failure the original `/dnsaddr/…` is kept as a fallback, so the
///   libp2p-dns transport still has a chance to resolve it later.
pub async fn resolve_all<I>(addrs: I) -> Vec<Multiaddr>
where
    I: IntoIterator<Item = Multiaddr>,
{
    let resolver = build_resolver();

    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for addr in addrs {
        if !is_dnsaddr(&addr) {
            out.push(addr);
            continue;
        }
        match resolve_recursive(&resolver, &addr, &mut seen, 0).await {
            Ok(v) => {
                debug!(target: "ant_p2p::dnsaddr", %addr, count = v.len(), "resolved");
                out.extend(v);
            }
            Err(e) => {
                warn!(target: "ant_p2p::dnsaddr", %addr, "resolve failed: {e}; keeping original");
                out.push(addr);
            }
        }
    }
    out
}

#[derive(Debug, Error)]
enum ResolveError {
    #[error("dns lookup: {0}")]
    DnsLookup(String),
    #[error("max recursion depth exceeded")]
    MaxRecursionDepth,
}

fn extract_domain(addr: &Multiaddr) -> Option<String> {
    addr.iter().find_map(|p| match p {
        Protocol::Dnsaddr(d) => Some(d.to_string()),
        _ => None,
    })
}

fn resolve_recursive<'a>(
    resolver: &'a TokioResolver,
    addr: &'a Multiaddr,
    seen: &'a mut HashSet<String>,
    depth: usize,
) -> Pin<Box<dyn Future<Output = Result<Vec<Multiaddr>, ResolveError>> + Send + 'a>> {
    Box::pin(async move {
        if depth > MAX_RECURSION_DEPTH {
            return Err(ResolveError::MaxRecursionDepth);
        }

        let Some(domain) = extract_domain(addr) else {
            return Ok(vec![addr.clone()]);
        };

        let key = format!("_dnsaddr.{domain}");
        if !seen.insert(key.clone()) {
            debug!(target: "ant_p2p::dnsaddr", %domain, "already seen");
            return Ok(Vec::new());
        }

        debug!(target: "ant_p2p::dnsaddr", name = %key, "TXT query");
        let records = resolver
            .txt_lookup(&key)
            .await
            .map_err(|e| ResolveError::DnsLookup(format!("{key}: {e}")))?;

        let mut out = Vec::new();
        for record in records.iter() {
            for txt in record.txt_data() {
                let s = String::from_utf8_lossy(txt);
                let Some(value) = s.strip_prefix("dnsaddr=") else {
                    continue;
                };
                match value.parse::<Multiaddr>() {
                    Ok(next) => {
                        let nested = resolve_recursive(resolver, &next, seen, depth + 1).await?;
                        out.extend(nested);
                    }
                    Err(e) => {
                        warn!(target: "ant_p2p::dnsaddr", %value, "bad multiaddr in TXT: {e}");
                    }
                }
            }
        }
        Ok(out)
    })
}

fn build_resolver() -> TokioResolver {
    let (system_cfg, opts) = match hickory_resolver::system_conf::read_system_conf() {
        Ok(c) => c,
        Err(_) => (ResolverConfig::cloudflare(), ResolverOpts::default()),
    };
    // System nameservers first (so corporate / split-horizon DNS for
    // private bootnodes still works), then Cloudflare's anycast as a
    // public fallback. The latter is load-bearing on the iOS
    // simulator: even after a sim reboot, `system_conf` returns
    // resolvers that the simulator's network sandbox can't reach
    // (every UDP send returns `EHOSTUNREACH` / "No route to host"
    // os error 65), so without a backup `/dnsaddr/mainnet.ethswarm.org`
    // resolution fails forever and the player has no dialable
    // bootnodes on a fresh install. Verified empirically: clean
    // `data_dir` + clean sim, system DNS only → zero peers in 40 s;
    // with Cloudflare appended → 100 peers in 3 s. hickory's name
    // server pool walks the list on per-server connection failures,
    // so a healthy host's system DNS still wins on the happy path —
    // we only fall through when those entries time out / refuse.
    let mut servers = system_cfg.name_servers().to_vec();
    servers.extend(ResolverConfig::cloudflare().name_servers().iter().cloned());
    let sanitized = ResolverConfig::from_parts(None, Vec::new(), servers);
    let builder = TokioResolver::builder_with_config(sanitized, TokioConnectionProvider::default())
        .with_options(opts);
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_dnsaddr_true_for_dnsaddr() {
        let addr: Multiaddr = "/dnsaddr/mainnet.ethswarm.org".parse().unwrap();
        assert!(is_dnsaddr(&addr));
    }

    #[test]
    fn is_dnsaddr_false_for_ip() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/1634".parse().unwrap();
        assert!(!is_dnsaddr(&addr));
    }

    #[test]
    fn is_dnsaddr_false_for_dns4() {
        let addr: Multiaddr = "/dns4/example.com/tcp/1634".parse().unwrap();
        assert!(!is_dnsaddr(&addr));
    }

    #[test]
    fn extract_domain_returns_dnsaddr_domain() {
        let addr: Multiaddr = "/dnsaddr/mainnet.ethswarm.org".parse().unwrap();
        assert_eq!(
            extract_domain(&addr),
            Some("mainnet.ethswarm.org".to_string())
        );
    }

    #[test]
    fn extract_domain_returns_none_for_ip() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/1634".parse().unwrap();
        assert_eq!(extract_domain(&addr), None);
    }

    #[tokio::test]
    async fn resolve_all_passes_non_dnsaddr_through() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/1634".parse().unwrap();
        let resolved = resolve_all(std::iter::once(addr.clone())).await;
        assert_eq!(resolved, vec![addr]);
    }
}
