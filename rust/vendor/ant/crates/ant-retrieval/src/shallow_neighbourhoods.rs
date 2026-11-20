//! Neighbourhoods where a push could not reach a deep storer.
//!
//! A light node hunts hard for a deep receipt
//! ([`crate::RoutingFetcher::MAX_SHALLOW_ATTEMPTS`] attempts, each after a
//! neighbourhood dial and a bounded wait): a chunk stored outside its
//! neighbourhood is not retrievable by the routed network. But when a
//! neighbourhood has no storer this node can get a deep receipt from (it
//! is empty, or its one node is unreachable), every chunk that falls in
//! it repeats the whole ~30 s hunt and still lands shallow. Measured on
//! mainnet (2026-10-12): after the network's storage radius rose from 8
//! to 9, one depth-9 neighbourhood with a single node caught a chunk of
//! nearly every 2 s video segment, so every segment took ~30 s to
//! publish and 540p/720p broadcasts fell minutes behind.
//!
//! So a hunt that ends shallow marks the chunk's neighbourhood (its
//! address prefix at the storer's reported radius) for [`TTL`]: until
//! then, best-effort pushes of chunks in it accept their first shallow
//! receipt (the chunk *is* stored) instead of hunting again. When the
//! mark expires the next chunk hunts in full, so a neighbourhood that
//! became reachable is noticed. Strict pushes (`with_require_deep`)
//! never consult it.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a neighbourhood stays marked after a hunt ended shallow.
pub const TTL: Duration = Duration::from_mins(10);

/// Shared memory of neighbourhoods without a reachable deep storer.
#[derive(Debug, Default)]
pub struct ShallowNeighbourhoods {
    marked: Mutex<HashMap<(u8, u32), Instant>>,
}

impl ShallowNeighbourhoods {
    /// The neighbourhood of `addr` at `radius` bits (capped at 32).
    fn key(addr: &[u8; 32], radius: u32) -> (u8, u32) {
        let bits = radius.min(32) as u8;
        let prefix = u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]]);
        let prefix = if bits == 0 {
            0
        } else {
            prefix >> (32 - u32::from(bits))
        };
        (bits, prefix)
    }

    /// Whether `addr`'s neighbourhood at `radius` is marked and not expired.
    #[must_use]
    pub fn is_marked(&self, addr: &[u8; 32], radius: u32) -> bool {
        self.is_marked_at(addr, radius, Instant::now())
    }

    fn is_marked_at(&self, addr: &[u8; 32], radius: u32, now: Instant) -> bool {
        let mut marked = self
            .marked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = Self::key(addr, radius);
        match marked.get(&key) {
            Some(&until) if until > now => true,
            Some(_) => {
                marked.remove(&key);
                false
            }
            None => false,
        }
    }

    /// Whether `addr` falls in a marked neighbourhood at any radius (for a
    /// caller that doesn't know the storers' radius yet).
    #[must_use]
    pub fn is_marked_any(&self, addr: &[u8; 32]) -> bool {
        let now = Instant::now();
        let marked = self
            .marked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        marked.iter().any(|(&(bits, prefix), &until)| {
            until > now && Self::key(addr, u32::from(bits)) == (bits, prefix)
        })
    }

    /// Mark `addr`'s neighbourhood at `radius` for [`TTL`].
    pub fn mark(&self, addr: &[u8; 32], radius: u32) {
        self.mark_at(addr, radius, Instant::now());
    }

    fn mark_at(&self, addr: &[u8; 32], radius: u32, now: Instant) {
        let mut marked = self
            .marked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        marked.retain(|_, until| *until > now);
        marked.insert(Self::key(addr, radius), now + TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(first: [u8; 2]) -> [u8; 32] {
        let mut a = [0x55u8; 32];
        a[0] = first[0];
        a[1] = first[1];
        a
    }

    #[test]
    fn a_mark_covers_its_neighbourhood_only_and_expires() {
        let m = ShallowNeighbourhoods::default();
        let now = Instant::now();
        // 0b0000_1100_1 (depth-9 neighbourhood 25), as on mainnet.
        m.mark_at(&addr([0x0c, 0x80]), 9, now);
        assert!(
            m.is_marked_at(&addr([0x0c, 0xff]), 9, now),
            "same 9-bit prefix"
        );
        assert!(
            !m.is_marked_at(&addr([0x0c, 0x7f]), 9, now),
            "sibling neighbourhood"
        );
        assert!(
            !m.is_marked_at(&addr([0x0c, 0x80]), 10, now),
            "another radius is another key"
        );
        assert!(
            !m.is_marked_at(&addr([0x0c, 0x80]), 9, now + TTL),
            "expired"
        );
    }
}
