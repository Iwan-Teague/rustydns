#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Blocklist engine for `rustydns`.
//!
//! Provides fast in-memory domain blocking with:
//! - **O(1) lookup** via `AHashSet` (randomised hash seed per process).
//! - **Lock-free hot-reload** via `ArcSwap` — readers never block during reload.
//! - **Wildcard support** — RPZ `*.example.com` and AdGuard `||example.com^` rules.
//! - **Suffix-aware allowlist** — `*.example.com` in the allowlist whitelists all subdomains.
//! - **Four input formats**: hosts, plain domain list, RPZ, AdGuard/uBlock.
//!
//! # Usage
//!
//! ```rust,no_run
//! use rustydns_blocklist::BlocklistEngine;
//! use rustydns_core::config::BlocklistConfig;
//!
//! let engine = BlocklistEngine::new(BlocklistConfig::default());
//! engine.load("0.0.0.0 ads.example.com\n");
//!
//! assert!(engine.is_blocked("ads.example.com"));
//! assert!(!engine.is_blocked("safe.example.com"));
//! ```

mod allowlist;
mod engine;
mod parser;

pub use allowlist::Allowlist;
pub use engine::{BlocklistEngine, BlocklistSource};
pub use parser::{ListFormat, ParsedEntry, detect_format, parse};
