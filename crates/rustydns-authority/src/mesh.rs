#![forbid(unsafe_code)]

//! Rustynet mesh-zone bundle loader.
//!
//! `rustynetd` produces a signed line-oriented bundle file describing the
//! mesh's DNS zone. The format is defined by the `rustynet-dns-zone` crate
//! in the Rustynet repository. Each bundle is signed with an ed25519 key
//! whose public half is published out-of-band to the operator.
//!
//! This module reads the bundle file, verifies its ed25519 signature
//! against a configured verifier key, applies freshness checks, and
//! produces a set of [`DnsRecord`]s ready to be merged into the
//! authority's zone store.
//!
//! # Wire format (recap)
//!
//! ```text
//! version=1
//! zone_name=mesh
//! subject_node_id=...
//! generated_at_unix=...
//! expires_at_unix=...
//! nonce=...
//! record_count=N
//! record.0.label=...
//! record.0.fqdn=...
//! record.0.target_node_id=...
//! record.0.rr_type=A
//! record.0.target_addr_kind=mesh_ipv4
//! record.0.expected_ip=100.64.x.y
//! record.0.ttl_secs=...
//! record.0.aliases=alias1,alias2
//! ...
//! signature=<128 hex chars>
//! ```
//!
//! The bytes signed are everything up to and including the `\n` that
//! ends the field BEFORE `signature=` — i.e. `render_signed_dns_zone_bundle_wire`
//! in Rustynet appends `signature={hex}\n` to a `payload` that already
//! ends in `\n`. We extract those payload bytes verbatim and verify.

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

use rustydns_core::record::{DnsRecord, RecordData};

/// Maximum bundle file size we are willing to read into memory.
///
/// Matches `MAX_BUNDLE_BYTES` in `rustynet-dns-zone` (256 KiB). A larger
/// file is almost certainly an attack or corruption; reject without
/// allocating proportionally.
const MAX_BUNDLE_BYTES: usize = 256 * 1024;

/// Upper bound on `record_count` before we even start allocating.
///
/// `record_count` comes from the (signed) payload, but a compromised or
/// buggy signer could set it to a huge value and make us
/// `Vec::with_capacity(huge)` → multi-gigabyte allocation → OOM, from a
/// tiny bundle. A 256 KiB bundle physically cannot contain anywhere near
/// this many records (each needs several `record.N.*` lines), so any count
/// beyond this is malformed and rejected before allocation.
const MAX_BUNDLE_RECORDS: usize = 100_000;

/// Errors that can occur while loading or verifying the mesh bundle.
#[derive(Debug, Error)]
pub enum MeshBundleError {
    /// I/O error reading the bundle or verifier-key file.
    #[error("mesh bundle I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The bundle file exceeded the size limit.
    #[error("mesh bundle exceeds maximum size of {MAX_BUNDLE_BYTES} bytes")]
    TooLarge,

    /// A required field was missing from the bundle.
    #[error("mesh bundle is missing field `{0}`")]
    MissingField(&'static str),

    /// A field had a malformed value.
    #[error("mesh bundle field `{field}` is invalid: {reason}")]
    InvalidField {
        /// Field name.
        field: String,
        /// Human-readable reason.
        reason: String,
    },

    /// The verifier-key file did not contain a valid hex-encoded ed25519 key.
    #[error("mesh verifier key is invalid: {0}")]
    InvalidVerifierKey(String),

    /// The signature line was missing or malformed.
    #[error("mesh bundle signature is missing or malformed")]
    MissingSignature,

    /// The signature failed to verify.
    #[error("mesh bundle signature did not verify against the configured key")]
    SignatureMismatch,

    /// The bundle is too old to trust.
    #[error("mesh bundle is stale ({reason})")]
    Stale {
        /// Human-readable reason — generated-at age, or expired.
        reason: String,
    },

    /// The bundle is older than the one currently applied (anti-rollback).
    ///
    /// A signature- and freshness-valid bundle can still be a *replay* of a
    /// genuinely older snapshot (one generated a few minutes ago, within the
    /// `mesh_zone_max_age_secs` window). Re-applying it would silently roll
    /// the mesh zone back to a previous IP mapping or drop a record. The
    /// authority tracks the last-applied `(generated_at_unix, nonce)` and
    /// refuses any candidate that orders strictly before it.
    #[error(
        "mesh bundle rejected (anti-rollback): candidate (generated_at_unix={candidate_generated_at}, \
         nonce={candidate_nonce}) is older than the applied bundle \
         (generated_at_unix={current_generated_at}, nonce={current_nonce})"
    )]
    Rollback {
        /// `generated_at_unix` of the rejected candidate bundle.
        candidate_generated_at: u64,
        /// `nonce` of the rejected candidate bundle.
        candidate_nonce: u64,
        /// `generated_at_unix` of the currently applied bundle.
        current_generated_at: u64,
        /// `nonce` of the currently applied bundle.
        current_nonce: u64,
    },

    /// The zone_name in the bundle didn't match our configured mesh zone.
    #[error("mesh bundle zone_name `{bundle}` does not match configured mesh_zone `{configured}`")]
    ZoneMismatch {
        /// Zone name read from the bundle (without trailing dot).
        bundle: String,
        /// Configured mesh_zone (with trailing dot).
        configured: String,
    },
}

/// A loaded, signature-verified mesh bundle.
#[derive(Debug, Clone)]
pub struct LoadedBundle {
    /// Records ready to merge into the authority zone store.
    /// Each [`DnsRecord`] is tagged with the originating mesh node id
    /// via [`DnsRecord::mesh_node_id`].
    pub records: Vec<DnsRecord>,

    /// Bundle's `generated_at_unix` field (seconds since epoch).
    pub generated_at_unix: u64,

    /// Bundle's `expires_at_unix` field (seconds since epoch).
    pub expires_at_unix: u64,

    /// Nonce — useful for ordering subsequent loads.
    pub nonce: u64,
}

/// Read, verify, and parse the mesh bundle at `bundle_path`.
///
/// `mesh_zone` must be the normalised configured zone (lowercased,
/// trailing dot). `max_age_secs` is the maximum allowed clock-age of
/// `generated_at_unix` — older bundles are rejected even if their
/// `expires_at_unix` is still in the future.
pub fn load_mesh_bundle(
    bundle_path: &Path,
    verifier_key_path: &Path,
    mesh_zone: &str,
    max_age_secs: u64,
) -> Result<LoadedBundle, MeshBundleError> {
    let key = read_verifier_key(verifier_key_path)?;
    let raw = read_bundle_file(bundle_path)?;

    let (payload, signature_hex) = split_payload_and_signature(&raw)?;
    let signature = parse_signature(signature_hex)?;
    // verify_strict rejects non-canonical signatures (small-order R, malleable
    // s >= L forms) that plain `verify` accepts — free defence-in-depth on the
    // signature that gates the entire mesh zone.
    key.verify_strict(payload, &signature)
        .map_err(|_| MeshBundleError::SignatureMismatch)?;

    let fields = parse_fields(payload)?;
    let bundle = build_loaded_bundle(&fields, mesh_zone)?;

    enforce_freshness(&bundle, max_age_secs)?;
    Ok(bundle)
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

fn read_verifier_key(path: &Path) -> Result<VerifyingKey, MeshBundleError> {
    let contents = fs::read_to_string(path)?;
    let line = contents
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .ok_or_else(|| {
            MeshBundleError::InvalidVerifierKey("verifier key file is empty".to_string())
        })?;
    let bytes = decode_hex_fixed::<32>(line)
        .map_err(|e| MeshBundleError::InvalidVerifierKey(format!("hex decode failed: {e}")))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| MeshBundleError::InvalidVerifierKey(format!("not a valid ed25519 key: {e}")))
}

fn read_bundle_file(path: &Path) -> Result<Vec<u8>, MeshBundleError> {
    use std::io::Read;
    // Read at most MAX_BUNDLE_BYTES + 1 bytes regardless of the file's
    // reported size. This avoids a metadata()-then-read() TOCTOU where the
    // file is swapped for a much larger one between the size check and the
    // read — a capped reader can never allocate more than the limit + 1.
    let file = fs::File::open(path)?;
    let mut buf = Vec::new();
    let read = file
        .take(MAX_BUNDLE_BYTES as u64 + 1)
        .read_to_end(&mut buf)?;
    if read > MAX_BUNDLE_BYTES {
        return Err(MeshBundleError::TooLarge);
    }
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Signature extraction
// ---------------------------------------------------------------------------

/// Split bundle bytes into `(payload, signature_hex)`.
///
/// Rustynet writes the wire format as `<payload>signature=<hex>\n` where
/// `<payload>` ends with `\n`. We find the LAST occurrence of
/// `\nsignature=` and use it as the boundary — the line that the
/// signature is calculated over is everything up to and including the
/// preceding `\n`.
fn split_payload_and_signature(raw: &[u8]) -> Result<(&[u8], &str), MeshBundleError> {
    let needle = b"\nsignature=";
    let pos = raw
        .windows(needle.len())
        .rposition(|w| w == needle)
        .ok_or(MeshBundleError::MissingSignature)?;
    // Payload includes the \n that ends the last payload field.
    let payload = &raw[..=pos];
    let sig_bytes = &raw[pos + needle.len()..];
    let sig_str = std::str::from_utf8(sig_bytes)
        .map_err(|_| MeshBundleError::MissingSignature)?
        .trim_end_matches('\n')
        .trim();
    if sig_str.is_empty() {
        return Err(MeshBundleError::MissingSignature);
    }
    Ok((payload, sig_str))
}

fn parse_signature(hex: &str) -> Result<Signature, MeshBundleError> {
    let bytes = decode_hex_fixed::<64>(hex).map_err(|_| MeshBundleError::MissingSignature)?;
    Ok(Signature::from_bytes(&bytes))
}

// ---------------------------------------------------------------------------
// Payload parsing
// ---------------------------------------------------------------------------

/// Parse a `key=value` line-oriented payload into a flat map.
fn parse_fields(
    payload: &[u8],
) -> Result<std::collections::BTreeMap<String, String>, MeshBundleError> {
    let text = std::str::from_utf8(payload).map_err(|_| MeshBundleError::InvalidField {
        field: "<payload>".to_string(),
        reason: "payload is not valid UTF-8".to_string(),
    })?;
    let mut map = std::collections::BTreeMap::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| MeshBundleError::InvalidField {
                field: line.to_string(),
                reason: "line is not `key=value`".to_string(),
            })?;
        // Rustynet rejects duplicates; we mirror that.
        if map
            .insert(k.trim().to_string(), v.trim().to_string())
            .is_some()
        {
            return Err(MeshBundleError::InvalidField {
                field: k.trim().to_string(),
                reason: "duplicate field in bundle".to_string(),
            });
        }
    }
    Ok(map)
}

fn build_loaded_bundle(
    fields: &std::collections::BTreeMap<String, String>,
    mesh_zone: &str,
) -> Result<LoadedBundle, MeshBundleError> {
    let version = require(fields, "version")?;
    if version != "1" {
        return Err(MeshBundleError::InvalidField {
            field: "version".to_string(),
            reason: format!("unsupported bundle version `{version}`"),
        });
    }

    let zone_name = require(fields, "zone_name")?;
    let bundle_zone = normalise_zone(&zone_name);
    if bundle_zone != mesh_zone {
        return Err(MeshBundleError::ZoneMismatch {
            bundle: zone_name,
            configured: mesh_zone.to_string(),
        });
    }

    let generated_at_unix = parse_u64(fields, "generated_at_unix")?;
    let expires_at_unix = parse_u64(fields, "expires_at_unix")?;
    if generated_at_unix >= expires_at_unix {
        return Err(MeshBundleError::InvalidField {
            field: "expires_at_unix".to_string(),
            reason: "expires_at_unix must be greater than generated_at_unix".to_string(),
        });
    }

    let nonce = parse_u64(fields, "nonce")?;
    let record_count = parse_usize(fields, "record_count")?;
    if record_count > MAX_BUNDLE_RECORDS {
        return Err(MeshBundleError::InvalidField {
            field: "record_count".to_string(),
            reason: format!(
                "record_count {record_count} exceeds the maximum of {MAX_BUNDLE_RECORDS}"
            ),
        });
    }

    // Capacity is now bounded by the check above (and, in practice, far
    // lower by the 256 KiB bundle-size limit).
    let mut records = Vec::with_capacity(record_count);
    for i in 0..record_count {
        let rec = build_record(fields, i, mesh_zone)?;
        records.extend(rec);
    }

    Ok(LoadedBundle {
        records,
        generated_at_unix,
        expires_at_unix,
        nonce,
    })
}

fn build_record(
    fields: &std::collections::BTreeMap<String, String>,
    index: usize,
    mesh_zone: &str,
) -> Result<Vec<DnsRecord>, MeshBundleError> {
    let label = required_indexed(fields, index, "label")?;
    validate_single_label(&label, &format!("record.{index}.label"))?;
    let rr_type = required_indexed(fields, index, "rr_type")?;
    let target_addr_kind = required_indexed(fields, index, "target_addr_kind")?;
    let expected_ip = required_indexed(fields, index, "expected_ip")?;
    let ttl_secs_str = required_indexed(fields, index, "ttl_secs")?;
    let target_node_id = required_indexed(fields, index, "target_node_id")?;
    let aliases = fields
        .get(&format!("record.{index}.aliases"))
        .cloned()
        .unwrap_or_default();

    if rr_type != "A" {
        return Err(MeshBundleError::InvalidField {
            field: format!("record.{index}.rr_type"),
            reason: format!("only `A` is supported (got `{rr_type}`)"),
        });
    }
    if target_addr_kind != "mesh_ipv4" {
        return Err(MeshBundleError::InvalidField {
            field: format!("record.{index}.target_addr_kind"),
            reason: format!("only `mesh_ipv4` is supported (got `{target_addr_kind}`)"),
        });
    }
    let ip: Ipv4Addr = expected_ip
        .parse()
        .map_err(|e| MeshBundleError::InvalidField {
            field: format!("record.{index}.expected_ip"),
            reason: format!("not a valid IPv4 address: {e}"),
        })?;
    let ttl_secs: u64 = ttl_secs_str
        .parse()
        .map_err(|_| MeshBundleError::InvalidField {
            field: format!("record.{index}.ttl_secs"),
            reason: format!("not a u64: `{ttl_secs_str}`"),
        })?;

    let ttl = Duration::from_secs(ttl_secs);

    let mut names = vec![label.clone()];
    for alias in aliases.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        validate_single_label(alias, &format!("record.{index}.aliases"))?;
        names.push(alias.to_string());
    }

    let mut out = Vec::with_capacity(names.len());
    for n in names {
        let fqdn = format!("{}{}", n, mesh_zone_dotted(mesh_zone));
        let rec =
            DnsRecord::new(fqdn, RecordData::A(ip), ttl).with_mesh_node(target_node_id.clone());
        out.push(rec);
    }
    Ok(out)
}

fn enforce_freshness(bundle: &LoadedBundle, max_age_secs: u64) -> Result<(), MeshBundleError> {
    enforce_freshness_at(bundle, max_age_secs, unix_now_secs())
}

/// Wall clock, floored at 0 for pre-epoch clocks. Callers MUST treat a value
/// below [`MIN_TRUSTED_UNIX_SECS`] as an untrusted clock (see
/// `enforce_freshness_at`) rather than evaluating freshness with it.
fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn enforce_freshness_at(
    bundle: &LoadedBundle,
    max_age_secs: u64,
    now: u64,
) -> Result<(), MeshBundleError> {
    if now < rustydns_core::schedule::MIN_TRUSTED_UNIX_SECS {
        return Err(MeshBundleError::Stale {
            reason: format!(
                "system clock reads unix={now}, before the plausibility floor \
                 ({floor}); refusing to evaluate bundle freshness with an \
                 untrusted clock. Fix the system time and reload.",
                floor = rustydns_core::schedule::MIN_TRUSTED_UNIX_SECS
            ),
        });
    }

    if now >= bundle.expires_at_unix {
        return Err(MeshBundleError::Stale {
            reason: format!(
                "expires_at_unix={} is in the past (now={})",
                bundle.expires_at_unix, now
            ),
        });
    }
    if max_age_secs > 0 && now > bundle.generated_at_unix.saturating_add(max_age_secs) {
        return Err(MeshBundleError::Stale {
            reason: format!(
                "generated_at_unix={} is older than mesh_zone_max_age_secs={} (now={})",
                bundle.generated_at_unix, max_age_secs, now
            ),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require(
    fields: &std::collections::BTreeMap<String, String>,
    name: &'static str,
) -> Result<String, MeshBundleError> {
    fields
        .get(name)
        .cloned()
        .ok_or(MeshBundleError::MissingField(name))
}

fn required_indexed(
    fields: &std::collections::BTreeMap<String, String>,
    index: usize,
    name: &str,
) -> Result<String, MeshBundleError> {
    let key = format!("record.{index}.{name}");
    fields
        .get(&key)
        .cloned()
        .ok_or(MeshBundleError::InvalidField {
            field: key,
            reason: "missing required record field".to_string(),
        })
}

fn parse_u64(
    fields: &std::collections::BTreeMap<String, String>,
    name: &'static str,
) -> Result<u64, MeshBundleError> {
    require(fields, name)?
        .parse::<u64>()
        .map_err(|_| MeshBundleError::InvalidField {
            field: name.to_string(),
            reason: "not a u64".to_string(),
        })
}

/// A mesh record's FQDN is always `<label><zone>`, so every component (the
/// label and each alias) must be a **single** well-formed DNS label. The
/// bundle is signature-gated, but the signer is not free to inject names the
/// format never intended: a dotted label (`evil.com`) would mint
/// `evil.com.mesh.`-shaped multi-level names, an empty label would target the
/// zone apex, and oversized/non-ASCII labels would violate the same domain
/// invariants the blocklist parser enforces. Fail closed at parse time —
/// defence-in-depth against a compromised or buggy signer.
fn validate_single_label(value: &str, field: &str) -> Result<(), MeshBundleError> {
    let reject = |reason: String| MeshBundleError::InvalidField {
        field: field.to_string(),
        reason,
    };
    if value.is_empty() {
        return Err(reject("label is empty".to_string()));
    }
    if value.len() > 63 {
        return Err(reject(format!("label is {} bytes (max 63)", value.len())));
    }
    if !value.is_ascii() {
        return Err(reject("label is not ASCII".to_string()));
    }
    if value.contains('.') {
        return Err(reject(format!("label `{value}` contains a dot")));
    }
    Ok(())
}

fn parse_usize(
    fields: &std::collections::BTreeMap<String, String>,
    name: &'static str,
) -> Result<usize, MeshBundleError> {
    require(fields, name)?
        .parse::<usize>()
        .map_err(|_| MeshBundleError::InvalidField {
            field: name.to_string(),
            reason: "not a usize".to_string(),
        })
}

/// Normalise the zone_name field from the bundle to match the
/// `mesh_zone` style we use internally (lowercase, trailing dot).
fn normalise_zone(value: &str) -> String {
    let trimmed = value.trim().trim_end_matches('.');
    let mut s = trimmed.to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

/// `mesh_zone` is already `"mesh."` shape. For building FQDNs from a
/// bare label we want `"label.mesh."`, so just append.
fn mesh_zone_dotted(mesh_zone: &str) -> String {
    if mesh_zone.is_empty() {
        ".".to_string()
    } else if mesh_zone.starts_with('.') {
        mesh_zone.to_string()
    } else {
        format!(".{mesh_zone}")
    }
}

fn decode_hex_fixed<const N: usize>(s: &str) -> Result<[u8; N], &'static str> {
    let s = s.trim();
    if s.len() != N * 2 {
        return Err("hex length mismatch");
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = nibble(bytes[2 * i])?;
        let lo = nibble(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn nibble(b: u8) -> Result<u8, &'static str> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("invalid hex digit"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle_at(generated: u64, expires: u64) -> LoadedBundle {
        LoadedBundle {
            records: Vec::new(),
            generated_at_unix: generated,
            expires_at_unix: expires,
            nonce: 1,
        }
    }

    #[test]
    fn freshness_untrusted_clock_fails_closed() {
        // A pre-floor clock (dead RTC, fresh board) must REJECT the bundle:
        // with now=0 every expiry check would trivially pass, letting old
        // signed bundles replay indefinitely.
        let b = bundle_at(1_000_000_000, 2_000_000_000);
        let err = enforce_freshness_at(&b, 600, 0).expect_err("untrusted clock must fail closed");
        assert!(matches!(err, MeshBundleError::Stale { .. }));
    }

    #[test]
    fn freshness_sane_clock_still_enforces_windows() {
        const NOW: u64 = 1_700_000_000; // post-floor sanity
        // Fresh + unexpired -> ok.
        enforce_freshness_at(&bundle_at(NOW - 60, NOW + 3600), 600, NOW).unwrap();
        // Expired -> rejected.
        let expired = bundle_at(NOW - 7200, NOW - 3600);
        assert!(enforce_freshness_at(&expired, 600, NOW).is_err());
        // Older than max_age -> rejected.
        let aged = bundle_at(NOW - 10_000, NOW + 3600);
        assert!(enforce_freshness_at(&aged, 600, NOW).is_err());
    }

    use ed25519_dalek::{Signer, SigningKey};
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Build a synthetic bundle wire-string in the Rustynet format.
    /// Returns (wire_bytes, verifier_key_hex).
    fn build_signed_bundle(
        zone: &str,
        records: &[(&str, &str, &[&str])], // (label, ip, aliases)
        generated_at_unix: u64,
        expires_at_unix: u64,
    ) -> (Vec<u8>, String) {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let verifier = signing.verifying_key();
        let verifier_hex = verifier
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        let mut payload = String::new();
        payload.push_str("version=1\n");
        payload.push_str(&format!("zone_name={zone}\n"));
        payload.push_str("subject_node_id=test-subject\n");
        payload.push_str(&format!("generated_at_unix={generated_at_unix}\n"));
        payload.push_str(&format!("expires_at_unix={expires_at_unix}\n"));
        payload.push_str("nonce=1\n");
        payload.push_str(&format!("record_count={}\n", records.len()));
        for (i, (label, ip, aliases)) in records.iter().enumerate() {
            payload.push_str(&format!("record.{i}.label={label}\n"));
            payload.push_str(&format!("record.{i}.fqdn={label}.{zone}\n"));
            payload.push_str(&format!("record.{i}.target_node_id=node-{i}\n"));
            payload.push_str(&format!("record.{i}.rr_type=A\n"));
            payload.push_str(&format!("record.{i}.target_addr_kind=mesh_ipv4\n"));
            payload.push_str(&format!("record.{i}.expected_ip={ip}\n"));
            payload.push_str(&format!("record.{i}.ttl_secs=60\n"));
            payload.push_str(&format!("record.{i}.aliases={}\n", aliases.join(",")));
        }
        let sig = signing.sign(payload.as_bytes());
        let sig_hex = sig
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let wire = format!("{payload}signature={sig_hex}\n");
        (wire.into_bytes(), verifier_hex)
    }

    fn write_temp(contents: &[u8], name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("rustydns-mesh-test-{}-{name}", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents).unwrap();
        path
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn loads_valid_bundle_with_two_records() {
        let now = now();
        let (wire, key_hex) = build_signed_bundle(
            "mesh",
            &[
                ("router", "100.64.0.1", &[]),
                ("nas", "100.64.0.2", &["storage"]),
            ],
            now,
            now + 300,
        );
        let bundle_path = write_temp(&wire, "loads-ok-bundle");
        let key_path = write_temp(key_hex.as_bytes(), "loads-ok-key");

        let loaded =
            load_mesh_bundle(&bundle_path, &key_path, "mesh.", 600).expect("bundle must load");
        // router + nas + storage alias = 3 records
        assert_eq!(loaded.records.len(), 3);
        let names: Vec<&str> = loaded.records.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"router.mesh."));
        assert!(names.contains(&"nas.mesh."));
        assert!(names.contains(&"storage.mesh."));

        // Mesh node id propagates.
        for r in &loaded.records {
            assert!(r.mesh_node_id.is_some(), "{} should be tagged", r.name);
        }
    }

    #[test]
    fn rejects_bad_signature() {
        let now = now();
        let (mut wire, key_hex) =
            build_signed_bundle("mesh", &[("router", "100.64.0.1", &[])], now, now + 300);
        // Flip a byte in the payload so the signature no longer matches.
        let payload_pos = wire.iter().position(|&b| b == b'r').unwrap();
        wire[payload_pos] ^= 0x01;
        let bundle_path = write_temp(&wire, "bad-sig-bundle");
        let key_path = write_temp(key_hex.as_bytes(), "bad-sig-key");

        let err = load_mesh_bundle(&bundle_path, &key_path, "mesh.", 600).unwrap_err();
        assert!(matches!(err, MeshBundleError::SignatureMismatch), "{err:?}");
    }

    #[test]
    fn rejects_expired_bundle() {
        let now = now();
        let (wire, key_hex) = build_signed_bundle(
            "mesh",
            &[("router", "100.64.0.1", &[])],
            now - 1000,
            now - 10,
        );
        let bundle_path = write_temp(&wire, "expired-bundle");
        let key_path = write_temp(key_hex.as_bytes(), "expired-key");

        let err = load_mesh_bundle(&bundle_path, &key_path, "mesh.", 600).unwrap_err();
        match err {
            MeshBundleError::Stale { reason } => assert!(reason.contains("expires_at_unix")),
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bundle_older_than_max_age() {
        let now = now();
        let (wire, key_hex) = build_signed_bundle(
            "mesh",
            &[("router", "100.64.0.1", &[])],
            now - 4000,
            now + 300, // not expired
        );
        let bundle_path = write_temp(&wire, "old-bundle");
        let key_path = write_temp(key_hex.as_bytes(), "old-key");

        let err = load_mesh_bundle(&bundle_path, &key_path, "mesh.", 60).unwrap_err();
        match err {
            MeshBundleError::Stale { reason } => assert!(reason.contains("mesh_zone_max_age_secs")),
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn rejects_zone_name_mismatch() {
        let now = now();
        let (wire, key_hex) =
            build_signed_bundle("internal", &[("router", "100.64.0.1", &[])], now, now + 300);
        let bundle_path = write_temp(&wire, "wrong-zone-bundle");
        let key_path = write_temp(key_hex.as_bytes(), "wrong-zone-key");

        let err = load_mesh_bundle(&bundle_path, &key_path, "mesh.", 600).unwrap_err();
        match err {
            MeshBundleError::ZoneMismatch { bundle, configured } => {
                assert_eq!(bundle, "internal");
                assert_eq!(configured, "mesh.");
            }
            other => panic!("expected ZoneMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unsupported_record_type() {
        // hand-craft a bundle with rr_type=TXT to trigger the InvalidField path.
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let verifier_hex = signing
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let now = now();
        let mut payload = String::new();
        payload.push_str("version=1\n");
        payload.push_str("zone_name=mesh\n");
        payload.push_str("subject_node_id=test\n");
        payload.push_str(&format!("generated_at_unix={now}\n"));
        payload.push_str(&format!("expires_at_unix={}\n", now + 300));
        payload.push_str("nonce=1\n");
        payload.push_str("record_count=1\n");
        payload.push_str("record.0.label=router\n");
        payload.push_str("record.0.fqdn=router.mesh\n");
        payload.push_str("record.0.target_node_id=node-0\n");
        payload.push_str("record.0.rr_type=TXT\n");
        payload.push_str("record.0.target_addr_kind=mesh_ipv4\n");
        payload.push_str("record.0.expected_ip=100.64.0.1\n");
        payload.push_str("record.0.ttl_secs=60\n");
        payload.push_str("record.0.aliases=\n");
        let sig = signing.sign(payload.as_bytes());
        let sig_hex = sig
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let wire = format!("{payload}signature={sig_hex}\n");

        let bundle_path = write_temp(wire.as_bytes(), "txt-bundle");
        let key_path = write_temp(verifier_hex.as_bytes(), "txt-key");

        let err = load_mesh_bundle(&bundle_path, &key_path, "mesh.", 600).unwrap_err();
        match err {
            MeshBundleError::InvalidField { field, reason } => {
                assert!(field.contains("rr_type"));
                assert!(reason.contains("only `A`"));
            }
            other => panic!("expected InvalidField, got {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_verifier_keys() {
        use super::MeshBundleError;
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let now = now();

        // Empty key file.
        let bundle_path = write_temp(
            format!(
                "version=1\nzone_name=mesh\nrecord_count=0\nsignature={}\n",
                "0".repeat(128)
            )
            .as_bytes(),
            "empty-key-bundle",
        );
        let key_path = write_temp(b"\n", "empty-key");
        match load_mesh_bundle(&bundle_path, &key_path, "mesh.", 600) {
            Err(MeshBundleError::InvalidVerifierKey(_)) => {}
            other => panic!("empty key must yield InvalidVerifierKey, got {other:?}"),
        }

        // Non-hex content.
        let key_path2 = write_temp(b"not hex at all\n", "nonhex-key");
        match load_mesh_bundle(&bundle_path, &key_path2, "mesh.", 600) {
            Err(MeshBundleError::InvalidVerifierKey(_)) => {}
            other => panic!("non-hex key must yield InvalidVerifierKey, got {other:?}"),
        }

        // Wrong length (31 bytes = 62 hex chars).
        let short_hex: String = signing.verifying_key().to_bytes()[..31]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let key_path3 = write_temp(short_hex.as_bytes(), "short-key");
        match load_mesh_bundle(&bundle_path, &key_path3, "mesh.", 600) {
            Err(MeshBundleError::InvalidVerifierKey(_)) => {}
            other => panic!("short key must yield InvalidVerifierKey, got {other:?}"),
        }
    }

    #[test]
    fn rejects_oversized_bundle() {
        // Write a file with size > MAX_BUNDLE_BYTES.
        let huge = vec![b'A'; MAX_BUNDLE_BYTES + 1];
        let bundle_path = write_temp(&huge, "huge-bundle");
        // Any verifier key — we should fail before signature check.
        let key_path = write_temp(&[b'0'; 64], "huge-key");
        let err = load_mesh_bundle(&bundle_path, &key_path, "mesh.", 600).unwrap_err();
        assert!(matches!(err, MeshBundleError::TooLarge));
    }

    #[test]
    fn rejects_absurd_record_count_before_allocating() {
        // A *validly signed* bundle that claims billions of records must be
        // rejected at the count check — never reach Vec::with_capacity(huge)
        // and OOM. This models a compromised/buggy signer.
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let verifier_hex = signing
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let now = now();
        let mut payload = String::new();
        payload.push_str("version=1\n");
        payload.push_str("zone_name=mesh\n");
        payload.push_str("subject_node_id=test\n");
        payload.push_str(&format!("generated_at_unix={now}\n"));
        payload.push_str(&format!("expires_at_unix={}\n", now + 300));
        payload.push_str("nonce=1\n");
        // Way beyond MAX_BUNDLE_RECORDS, with no record fields present.
        payload.push_str("record_count=4000000000\n");
        let sig = signing.sign(payload.as_bytes());
        let sig_hex = sig
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let wire = format!("{payload}signature={sig_hex}\n");

        let bundle_path = write_temp(wire.as_bytes(), "absurd-count-bundle");
        let key_path = write_temp(verifier_hex.as_bytes(), "absurd-count-key");

        let err = load_mesh_bundle(&bundle_path, &key_path, "mesh.", 600).unwrap_err();
        match err {
            MeshBundleError::InvalidField { field, reason } => {
                assert_eq!(field, "record_count");
                assert!(reason.contains("exceeds the maximum"), "{reason}");
            }
            other => panic!("expected InvalidField for record_count, got {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_signature() {
        let bundle_path = write_temp(b"version=1\nzone_name=mesh\n", "nosig-bundle");
        let key_path = write_temp(&[b'0'; 64], "nosig-key");
        let err = load_mesh_bundle(&bundle_path, &key_path, "mesh.", 600).unwrap_err();
        assert!(
            matches!(
                err,
                MeshBundleError::MissingSignature | MeshBundleError::InvalidVerifierKey(_)
            ),
            "got {err:?}"
        );
    }

    /// Sign an arbitrary payload (byte-exact — the payload may be non-UTF8) in
    /// the Rustynet wire format and return (wire_bytes, verifier_key_hex).
    fn sign_arbitrary_payload(payload: &[u8]) -> (Vec<u8>, String) {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let verifier_hex = signing
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let sig_hex = signing
            .sign(payload)
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let mut wire = payload.to_vec();
        wire.extend_from_slice(b"signature=");
        wire.extend_from_slice(sig_hex.as_bytes());
        wire.push(b'\n');
        (wire, verifier_hex)
    }

    fn assert_invalid_field(err: MeshBundleError, field: &str, reason_contains: &str) {
        match err {
            MeshBundleError::InvalidField { field: f, reason } => {
                assert_eq!(f, field, "field");
                assert!(reason.contains(reason_contains), "reason: {reason}");
            }
            other => panic!("expected InvalidField for {field}, got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_field_in_bundle() {
        let now = now();
        let payload = format!(
            "version=1\nzone_name=mesh\nsubject_node_id=test-subject\n\
             generated_at_unix={now}\nexpires_at_unix={}\nnonce=1\nnonce=2\nrecord_count=0\n",
            now + 300
        );
        let (wire, key_hex) = sign_arbitrary_payload(payload.as_bytes());
        let err = load_mesh_bundle(
            &write_temp(&wire, "dup-field-bundle"),
            &write_temp(key_hex.as_bytes(), "dup-field-key"),
            "mesh.",
            600,
        )
        .unwrap_err();
        assert_invalid_field(err, "nonce", "duplicate field");
    }

    #[test]
    fn rejects_non_key_value_line() {
        let now = now();
        let payload = format!(
            "version=1\nzone_name=mesh\nthis line has no equals sign\n\
             subject_node_id=test-subject\ngenerated_at_unix={now}\n\
             expires_at_unix={}\nnonce=1\nrecord_count=0\n",
            now + 300
        );
        let (wire, key_hex) = sign_arbitrary_payload(payload.as_bytes());
        let err = load_mesh_bundle(
            &write_temp(&wire, "nonkv-bundle"),
            &write_temp(key_hex.as_bytes(), "nonkv-key"),
            "mesh.",
            600,
        )
        .unwrap_err();
        assert_invalid_field(err, "this line has no equals sign", "not `key=value`");
    }

    #[test]
    fn rejects_unsupported_bundle_version() {
        let now = now();
        // A future version must never parse with this reader: version is
        // pinned to the literal "1" so a v2 format cannot silently downgrade.
        let payload = format!(
            "version=2\nzone_name=mesh\nsubject_node_id=test-subject\n\
             generated_at_unix={now}\nexpires_at_unix={}\nnonce=1\nrecord_count=0\n",
            now + 300
        );
        let (wire, key_hex) = sign_arbitrary_payload(payload.as_bytes());
        let err = load_mesh_bundle(
            &write_temp(&wire, "v2-bundle"),
            &write_temp(key_hex.as_bytes(), "v2-key"),
            "mesh.",
            600,
        )
        .unwrap_err();
        assert_invalid_field(err, "version", "unsupported bundle version");
    }

    #[test]
    fn rejects_expiry_not_after_generation() {
        let now = now();
        let payload = format!(
            "version=1\nzone_name=mesh\nsubject_node_id=test-subject\n\
             generated_at_unix={}\nexpires_at_unix={}\nnonce=1\nrecord_count=0\n",
            now + 300,
            now + 300
        );
        let (wire, key_hex) = sign_arbitrary_payload(payload.as_bytes());
        let err = load_mesh_bundle(
            &write_temp(&wire, "zero-window-bundle"),
            &write_temp(key_hex.as_bytes(), "zero-window-key"),
            "mesh.",
            600,
        )
        .unwrap_err();
        assert_invalid_field(
            err,
            "expires_at_unix",
            "must be greater than generated_at_unix",
        );
    }

    #[test]
    fn rejects_signature_that_is_not_64_hex_bytes() {
        let now = now();
        let (mut wire, key_hex) =
            build_signed_bundle("mesh", &[("router", "100.64.0.1", &[])], now, now + 300);
        // Truncate the signature to an odd number of hex nibbles: decode must
        // fail before any ed25519 work happens.
        let sig_pos =
            String::from_utf8_lossy(&wire).rfind("signature=").unwrap() + "signature=".len();
        wire.truncate(wire.len() - 1); // drop trailing \n
        while wire.len() - sig_pos > 63 {
            wire.pop();
        }
        let err = load_mesh_bundle(
            &write_temp(&wire, "short-sig-bundle"),
            &write_temp(key_hex.as_bytes(), "short-sig-key"),
            "mesh.",
            600,
        )
        .unwrap_err();
        assert!(matches!(err, MeshBundleError::MissingSignature), "{err:?}");
    }

    #[test]
    fn rejects_non_utf8_payload() {
        let now = now();
        let mut payload = Vec::new();
        payload.extend_from_slice(b"version=1\nzone_name=me");
        payload.push(0xFF); // invalid UTF-8 inside a field value
        payload.extend_from_slice(
            format!(
                "sh\nsubject_node_id=test-subject\ngenerated_at_unix={now}\n\
                     expires_at_unix={}\nnonce=1\nrecord_count=0\n",
                now + 300
            )
            .as_bytes(),
        );
        let (wire, key_hex) = sign_arbitrary_payload(&payload);
        let err = load_mesh_bundle(
            &write_temp(&wire, "nonutf8-bundle"),
            &write_temp(key_hex.as_bytes(), "nonutf8-key"),
            "mesh.",
            600,
        )
        .unwrap_err();
        assert_invalid_field(err, "<payload>", "not valid UTF-8");
    }

    #[test]
    fn appended_second_signature_invalidates_verification() {
        let now = now();
        let (mut wire, key_hex) =
            build_signed_bundle("mesh", &[("router", "100.64.0.1", &[])], now, now + 300);
        // Append a second `signature=` line carrying a well-formed but wrong
        // 64-byte signature value. Extraction takes the LAST marker, so the
        // verified payload now includes the first signature line and no longer
        // matches — append/extension games cannot smuggle content past
        // verification.
        let extra = format!("\nsignature={}", "ab".repeat(64));
        wire.extend_from_slice(extra.as_bytes());
        let err = load_mesh_bundle(
            &write_temp(&wire, "double-sig-bundle"),
            &write_temp(key_hex.as_bytes(), "double-sig-key"),
            "mesh.",
            600,
        )
        .unwrap_err();
        assert!(matches!(err, MeshBundleError::SignatureMismatch), "{err:?}");
    }

    #[test]
    fn signature_binds_every_header_field_tamper_rejected() {
        // The signature covers the ENTIRE payload — every header field
        // (zone_name, generated_at_unix, expires_at_unix, nonce) and every
        // record line — so there is no field an attacker can rewrite after
        // signing without invalidating the attestation. Flip one byte inside
        // three different header/record values (format stays `key=value`, so
        // parsing would happily accept the mutation if verification were not
        // performed first); each must fail as SignatureMismatch. This is the
        // closest analogue rustydns has to a "head attestation over a tuple":
        // the tuple here is the whole payload, and it is bound by one
        // signature over verbatim bytes.
        let now = now();

        // Locate the payload region: everything before the LAST
        // "\nsignature=" marker.
        let payload_end = |wire: &[u8]| -> usize {
            wire.windows(11)
                .rposition(|w| w == b"\nsignature=")
                .expect("signed bundle has a signature marker")
        };
        let flip = |wire: &mut Vec<u8>, marker: &[u8]| {
            let start = wire
                .windows(marker.len())
                .position(|w| w == marker)
                .expect("marker present");
            let idx = start + marker.len(); // first byte of the VALUE
            wire[idx] ^= 0x01; // ASCII letter/digit → different byte, still valid UTF-8
        };

        for (i, field_marker) in [
            b"zone_name=".as_slice(),
            b"generated_at_unix=".as_slice(),
            b"record.0.label=".as_slice(),
        ]
        .into_iter()
        .enumerate()
        {
            let (mut wire, key_hex) =
                build_signed_bundle("mesh", &[("router", "100.64.0.5", &[])], now, now + 300);
            assert!(
                flip_target_within_payload(&wire, field_marker, payload_end(&wire)),
                "tamper target must lie inside the signed region"
            );
            flip(&mut wire, field_marker);
            let err = load_mesh_bundle(
                &write_temp(&wire, &format!("field-tamper-{i}")),
                &write_temp(key_hex.as_bytes(), &format!("field-tamper-key-{i}")),
                "mesh.",
                600,
            )
            .unwrap_err();
            assert!(
                matches!(err, MeshBundleError::SignatureMismatch),
                "tampered {field:?} must fail signature verification: {err:?}",
                field = String::from_utf8_lossy(field_marker)
            );
        }
    }

    /// True when `marker`'s value byte sits before `payload_end` (inside the
    /// signed region rather than in the trailing `signature=` hex).
    fn flip_target_within_payload(wire: &[u8], marker: &[u8], payload_end: usize) -> bool {
        wire.windows(marker.len())
            .position(|w| w == marker)
            .is_some_and(|start| start + marker.len() < payload_end)
    }

    #[test]
    fn rejects_dotted_label() {
        let now = now();
        let (wire, key_hex) =
            build_signed_bundle("mesh", &[("evil.com", "100.64.0.1", &[])], now, now + 300);
        let err = load_mesh_bundle(
            &write_temp(&wire, "dotted-label-bundle"),
            &write_temp(key_hex.as_bytes(), "dotted-label-key"),
            "mesh.",
            600,
        )
        .unwrap_err();
        assert_invalid_field(err, "record.0.label", "contains a dot");
    }

    #[test]
    fn rejects_empty_label() {
        let now = now();
        let (wire, key_hex) =
            build_signed_bundle("mesh", &[("", "100.64.0.1", &[])], now, now + 300);
        // An empty label would build the zone apex itself ("mesh." + ".").
        // The bundle builder writes `record.0.fqdn=.mesh.` for it — still a
        // well-formed signed payload, so only label validation catches it.
        let err = load_mesh_bundle(
            &write_temp(&wire, "empty-label-bundle"),
            &write_temp(key_hex.as_bytes(), "empty-label-key"),
            "mesh.",
            600,
        )
        .unwrap_err();
        assert_invalid_field(err, "record.0.label", "label is empty");
    }

    #[test]
    fn rejects_oversized_label() {
        let now = now();
        let long_label = "a".repeat(64);
        let (wire, key_hex) =
            build_signed_bundle("mesh", &[(&long_label, "100.64.0.1", &[])], now, now + 300);
        let err = load_mesh_bundle(
            &write_temp(&wire, "long-label-bundle"),
            &write_temp(key_hex.as_bytes(), "long-label-key"),
            "mesh.",
            600,
        )
        .unwrap_err();
        assert_invalid_field(err, "record.0.label", "max 63");
    }

    #[test]
    fn rejects_non_ascii_label() {
        let now = now();
        let (wire, key_hex) =
            build_signed_bundle("mesh", &[("routör", "100.64.0.1", &[])], now, now + 300);
        let err = load_mesh_bundle(
            &write_temp(&wire, "unicode-label-bundle"),
            &write_temp(key_hex.as_bytes(), "unicode-label-key"),
            "mesh.",
            600,
        )
        .unwrap_err();
        assert_invalid_field(err, "record.0.label", "not ASCII");
    }

    #[test]
    fn rejects_dotted_alias() {
        let now = now();
        let (wire, key_hex) = build_signed_bundle(
            "mesh",
            &[("nas", "100.64.0.2", &["storage.box"])],
            now,
            now + 300,
        );
        let err = load_mesh_bundle(
            &write_temp(&wire, "dotted-alias-bundle"),
            &write_temp(key_hex.as_bytes(), "dotted-alias-key"),
            "mesh.",
            600,
        )
        .unwrap_err();
        assert_invalid_field(err, "record.0.aliases", "contains a dot");
    }

    #[test]
    fn validate_single_label_rejects_multi_label_and_empty_directly() {
        // Direct unit on the validator itself (the bundle-level tests above
        // exercise it end-to-end through load_mesh_bundle).
        let err = validate_single_label("a.b", "record.0.label").unwrap_err();
        assert_invalid_field(err, "record.0.label", "contains a dot");

        let err = validate_single_label("", "record.0.aliases").unwrap_err();
        assert_invalid_field(err, "record.0.aliases", "label is empty");

        // Sanity: a well-formed single label is accepted.
        assert!(validate_single_label("router", "record.0.label").is_ok());
    }

    #[test]
    fn fuzz_mutated_bundles_never_panic_and_valid_labels_hold() {
        // Dependency-free LCG fuzz over the full signed-bundle path (the same
        // shape the blocklist parser's property test uses): mutate a valid
        // payload byte-wise, re-sign (so mutations reach the PARSER, not just
        // signature verification), and require no panic. Any bundle that DOES
        // load must contain only single-label names under the mesh zone.
        let mut seed: u64 = 0x5EED_BABE_F00D;
        let mut lcg = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let now = now();
        let (base_wire, key_hex) = build_signed_bundle(
            "mesh",
            &[("router", "100.64.0.1", &["storage"])],
            now,
            now + 300,
        );
        let key_path = write_temp(key_hex.as_bytes(), "fuzz-label-key");
        let signing = SigningKey::from_bytes(&[42u8; 32]);

        for i in 0..2000u32 {
            let mut wire = base_wire.clone();
            // 1-4 point mutations per iteration.
            for _ in 0..(lcg() % 4 + 1) {
                let idx = (lcg() as usize) % wire.len();
                match lcg() % 3 {
                    0 => wire[idx] = (lcg() % 256) as u8,
                    1 => {
                        wire.remove(idx);
                    }
                    _ => wire.insert(idx, b"=.\n abc0"[(lcg() % 8) as usize]),
                }
            }
            // Re-sign whatever mangled payload precedes the LAST signature
            // marker; malformed payloads must be rejected by extraction or
            // parsing, never panic.
            let sig = signing.sign(&wire);
            let hex = sig
                .to_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let text = String::from_utf8_lossy(&wire).to_string();
            let signed = match text.rfind("\nsignature=") {
                Some(p) => format!("{}signature={hex}\n", &text[..p]),
                None => format!("{}signature={hex}\n", text.trim_end()),
            };
            let path = write_temp(signed.as_bytes(), &format!("fuzz-label-{i}"));
            if let Ok(loaded) = load_mesh_bundle(&path, &key_path, "mesh.", 600) {
                for r in &loaded.records {
                    let stem = r.name.strip_suffix(".mesh.").expect("zone suffix");
                    assert!(
                        !stem.is_empty()
                            && !stem.contains('.')
                            && stem.len() <= 63
                            && stem.is_ascii(),
                        "invalid record name from mutated bundle: {}",
                        r.name
                    );
                }
            }
            let _ = std::fs::remove_file(&path);
        }
    }
}
