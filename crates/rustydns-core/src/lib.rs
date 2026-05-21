#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Core types shared across all `rustydns` crates.
//!
//! This crate has no I/O and no network access. It defines:
//! - [`config`]: full daemon configuration schema, security-hardened defaults.
//! - [`error`]: unified [`RustyDnsError`] type.
//! - [`record`]: DNS record model wrapping hickory-proto types.
//! - [`client`]: [`ClientId`] for per-query identity and anonymised logging.

pub mod client;
pub mod config;
pub mod error;
pub mod record;

pub use error::RustyDnsError;
