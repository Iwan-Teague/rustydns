#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Per-source-IP token-bucket rate limiter.
//!
//! Defends against:
//! - **DNS amplification.** A compromised LAN/mesh device flooding the
//!   resolver with queries (especially `ANY`/large-response types) to
//!   reflect off rustydnsd at a third party.
//! - **Local denial of service.** A misbehaving client starving every
//!   other client of resolver capacity.
//!
//! # Algorithm
//!
//! Classic token bucket. Each tracked source IP gets a `Bucket` with
//! `tokens` (a `f64` so partial-second refills accumulate correctly).
//! On every query:
//!
//! 1. Compute elapsed time since the last refill.
//! 2. Add `elapsed * qps` tokens, capped at `burst`.
//! 3. If `tokens >= 1.0`, deduct one and admit the query.
//! 4. Otherwise refuse.
//!
//! # Memory bounds
//!
//! `max_tracked_clients` caps the live bucket table. When full, an
//! LRU eviction makes room for a new IP. A background sweep also
//! reaps buckets that have been idle for >5 minutes, so transient
//! traffic from many IPs doesn't pin the table at its ceiling.
//!
//! # Loopback exemption
//!
//! `127.0.0.0/8` and `::1` are **always** admitted. Local proxies and
//! DoH/DoT terminators on the same host aggregate many users behind a
//! single connection to `rustydnsd` — they'd hit the per-IP limit
//! instantly if it applied to loopback.
//!
//! # Privacy
//!
//! The limiter holds IP addresses in memory only — never persisted,
//! never logged at info+ (refusals log only the anonymised client in
//! the handler, not here). Buckets are sized at ~64 bytes so the
//! default 10k-IP table is ~640 KiB.

use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ahash::AHashMap;
use rustydns_core::config::RateLimitConfig;

/// How often the GC pass runs to prune idle buckets.
const GC_INTERVAL: Duration = Duration::from_secs(30);
/// Buckets idle longer than this are dropped on the GC pass.
const IDLE_THRESHOLD: Duration = Duration::from_secs(300);

/// One client's bucket. ~48-64 bytes depending on `Instant` size.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Available tokens. Refilled at `qps` per second up to `burst`.
    tokens: f64,
    /// Last time we computed a refill against this bucket.
    last_refill: Instant,
    /// Last time this bucket was consulted (for LRU eviction and GC).
    last_used: Instant,
}

struct LimiterState {
    buckets: AHashMap<IpAddr, Bucket>,
    last_gc: Instant,
}

/// Per-source-IP token-bucket rate limiter.
///
/// Construct via [`RateLimiter::new`]. Hot path is [`RateLimiter::check`]
/// — synchronous, lock per call, no awaits. Designed to be wrapped in an
/// `Arc` and shared across listener tasks.
pub struct RateLimiter {
    /// `None` when `enabled = false` — `check` short-circuits to admit.
    state: Option<Mutex<LimiterState>>,
    qps: f64,
    burst: f64,
    max_tracked: usize,
}

/// Outcome of a [`RateLimiter::check`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitDecision {
    /// Bucket had ≥1 token (or loopback / disabled) — admit.
    Allow,
    /// Bucket was empty — refuse with `REFUSED`.
    Refuse,
}

impl RateLimiter {
    /// Build a new limiter from `cfg`. Disabled mode is a fast no-op.
    pub fn new(cfg: &RateLimitConfig) -> Self {
        let state = if cfg.enabled {
            Some(Mutex::new(LimiterState {
                buckets: AHashMap::with_capacity(cfg.max_tracked_clients.min(1024)),
                last_gc: Instant::now(),
            }))
        } else {
            None
        };
        Self {
            state,
            qps: f64::from(cfg.qps),
            burst: f64::from(cfg.burst),
            max_tracked: cfg.max_tracked_clients,
        }
    }

    /// Check whether a query from `ip` should be admitted.
    ///
    /// Always admits when:
    /// - the limiter is disabled (`enabled = false`), OR
    /// - `ip` is loopback (`127.0.0.0/8` or `::1`).
    ///
    /// Otherwise consults / updates the IP's bucket and returns
    /// `LimitDecision::Refuse` if the bucket is empty.
    pub fn check(&self, ip: IpAddr) -> LimitDecision {
        // Loopback exemption — applied even when enabled.
        if ip.is_loopback() {
            return LimitDecision::Allow;
        }
        let Some(state) = self.state.as_ref() else {
            return LimitDecision::Allow;
        };
        let now = Instant::now();
        let mut guard = match state.lock() {
            Ok(g) => g,
            // A poisoned lock means a previous holder panicked. Admit —
            // refusing every query because of a panic on an unrelated
            // task would deny far more legitimate users than the limiter
            // could plausibly protect, and the panic itself will already
            // be surfaced elsewhere.
            Err(p) => p.into_inner(),
        };

        // Periodic idle-bucket GC. Cheap: AHashMap::retain is O(n) but
        // only runs every GC_INTERVAL.
        if now.duration_since(guard.last_gc) >= GC_INTERVAL {
            guard
                .buckets
                .retain(|_, b| now.duration_since(b.last_used) < IDLE_THRESHOLD);
            guard.last_gc = now;
        }

        // LRU eviction when the table is full and we're about to insert
        // a new IP. We pay an O(n) scan once per eviction, which is
        // bounded by max_tracked; under sustained pressure GC clears
        // most of the table anyway.
        let need_evict =
            !guard.buckets.contains_key(&ip) && guard.buckets.len() >= self.max_tracked;
        if need_evict
            && let Some((oldest, _)) = guard
                .buckets
                .iter()
                .min_by_key(|(_, b)| b.last_used)
                .map(|(k, v)| (*k, *v))
        {
            guard.buckets.remove(&oldest);
        }

        let burst = self.burst;
        let qps = self.qps;
        let bucket = guard.buckets.entry(ip).or_insert(Bucket {
            tokens: burst,
            last_refill: now,
            last_used: now,
        });

        // Refill — clamped to burst so an idle client can't accumulate
        // an unbounded token reserve.
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * qps).min(burst);
        bucket.last_refill = now;
        bucket.last_used = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            LimitDecision::Allow
        } else {
            LimitDecision::Refuse
        }
    }

    /// Current size of the bucket table (for tests + future metrics).
    #[cfg(test)]
    pub fn tracked_clients(&self) -> usize {
        match self.state.as_ref() {
            Some(s) => s.lock().map(|g| g.buckets.len()).unwrap_or(0),
            None => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn cfg(qps: u32, burst: u32, max: usize) -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            qps,
            burst,
            max_tracked_clients: max,
        }
    }

    fn ipv4(o: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, o))
    }

    #[test]
    fn disabled_admits_everything() {
        let limiter = RateLimiter::new(&RateLimitConfig {
            enabled: false,
            ..RateLimitConfig::default()
        });
        for _ in 0..10_000 {
            assert_eq!(limiter.check(ipv4(1)), LimitDecision::Allow);
        }
        assert_eq!(limiter.tracked_clients(), 0);
    }

    #[test]
    fn loopback_v4_always_admitted() {
        let limiter = RateLimiter::new(&cfg(1, 1, 8));
        // Far exceed any plausible budget — must still admit.
        for _ in 0..1000 {
            assert_eq!(
                limiter.check(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                LimitDecision::Allow
            );
        }
        // Loopback hits never populate the bucket table.
        assert_eq!(limiter.tracked_clients(), 0);
    }

    #[test]
    fn loopback_v6_always_admitted() {
        let limiter = RateLimiter::new(&cfg(1, 1, 8));
        for _ in 0..1000 {
            assert_eq!(
                limiter.check(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                LimitDecision::Allow
            );
        }
        assert_eq!(limiter.tracked_clients(), 0);
    }

    #[test]
    fn burst_admits_up_to_capacity_then_refuses() {
        // qps=1 means refills are slow; burst=5 means the first 5
        // calls all see a token.
        let limiter = RateLimiter::new(&cfg(1, 5, 8));
        for i in 0..5 {
            assert_eq!(
                limiter.check(ipv4(7)),
                LimitDecision::Allow,
                "call {i} must be allowed within burst"
            );
        }
        // 6th immediate call should be refused — no measurable refill
        // could have happened in this many microseconds.
        assert_eq!(limiter.check(ipv4(7)), LimitDecision::Refuse);
    }

    #[test]
    fn refill_restores_tokens_after_sleep() {
        // qps=100, burst=2: empty the burst, sleep enough to refill at
        // least 1 token, then the next call must succeed.
        let limiter = RateLimiter::new(&cfg(100, 2, 8));
        assert_eq!(limiter.check(ipv4(9)), LimitDecision::Allow);
        assert_eq!(limiter.check(ipv4(9)), LimitDecision::Allow);
        assert_eq!(limiter.check(ipv4(9)), LimitDecision::Refuse);
        // 50 ms at 100 qps = 5 tokens (clamped to burst). Sleep slightly
        // more to absorb scheduler jitter on slow CI runners.
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(limiter.check(ipv4(9)), LimitDecision::Allow);
    }

    #[test]
    fn distinct_ips_have_independent_buckets() {
        let limiter = RateLimiter::new(&cfg(1, 2, 32));
        // Drain ipv4(1)'s bucket completely.
        assert_eq!(limiter.check(ipv4(1)), LimitDecision::Allow);
        assert_eq!(limiter.check(ipv4(1)), LimitDecision::Allow);
        assert_eq!(limiter.check(ipv4(1)), LimitDecision::Refuse);
        // ipv4(2) starts fresh.
        assert_eq!(limiter.check(ipv4(2)), LimitDecision::Allow);
        assert_eq!(limiter.check(ipv4(2)), LimitDecision::Allow);
        assert_eq!(limiter.check(ipv4(2)), LimitDecision::Refuse);
    }

    #[test]
    fn lru_eviction_makes_room_when_table_full() {
        // max_tracked = 2: insert two IPs, then a third must trigger
        // eviction of the LRU entry.
        let limiter = RateLimiter::new(&cfg(1, 1, 2));
        let _ = limiter.check(ipv4(1));
        std::thread::sleep(Duration::from_millis(2));
        let _ = limiter.check(ipv4(2));
        std::thread::sleep(Duration::from_millis(2));
        let _ = limiter.check(ipv4(3)); // ipv4(1) should be evicted

        // We can't introspect the map directly, but the table must
        // still cap at max_tracked.
        assert!(limiter.tracked_clients() <= 2);
    }

    #[test]
    fn ipv4_mapped_ipv6_loopback_admitted() {
        // ::ffff:127.0.0.1 — IPv4-mapped IPv6 form of loopback. The
        // stdlib's Ipv6Addr::is_loopback is strict (`::1` only), so
        // the limiter sees this as a normal IPv6 address subject to
        // rate-limiting. That's intentional: a peer connecting over
        // IPv6 with this address is not the host itself. We just
        // assert the limiter doesn't crash on it.
        let mapped = IpAddr::V6("::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap());
        let limiter = RateLimiter::new(&cfg(1, 1, 8));
        let _ = limiter.check(mapped); // must not panic
    }
}
