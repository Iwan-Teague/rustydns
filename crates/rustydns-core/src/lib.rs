#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Core types shared across all `rustydns` crates.
//!
//! This crate has no I/O and no network access. It defines:
//! - [`config`]: full daemon configuration schema, security-hardened defaults.
//! - [`error`]: unified [`RustyDnsError`] type.
//! - [`record`]: DNS record model wrapping hickory-proto types.
//! - [`client`]: [`client::ClientId`] for per-query identity and anonymised logging.
//! - [`ip_denylist`]: dependency-free IP/CIDR matcher for response-IP blocking.

pub mod client;
pub mod config;
pub mod error;
pub mod ip_denylist;
pub mod record;
pub mod regex_rules;

pub use error::RustyDnsError;
pub use ip_denylist::IpDenylist;
pub use regex_rules::RegexRules;
