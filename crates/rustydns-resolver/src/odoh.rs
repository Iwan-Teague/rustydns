//! Oblivious DoH (ODoH, RFC 9230) upstream arm.
//!
//! ODoH breaks the link between *who* is asking and *what* they ask. The DNS
//! query is HPKE-encrypted to the **target** resolver's public key and relayed
//! through an **oblivious proxy**:
//!
//! - the **proxy** sees the client IP but only ciphertext (never the query);
//! - the **target** sees the query but only the proxy's IP (never the client).
//!
//! No single party can correlate "who asked what" — provided the proxy and
//! target are operated independently (enforced operationally, documented in the
//! config). This is dnscrypt-proxy's flagship privacy mode.
//!
//! # Where this sits in the resolver
//!
//! The doh/doq/plain arms run through `hickory-resolver`, which gives us DNSSEC
//! validation, fail-closed retries, ECS handling and rdata filtering. The ODoH
//! arm is a **parallel transport that bypasses hickory-resolver**, so it must
//! re-establish the rustydns invariants itself:
//!
//! - **Fail-closed.** Every failure path — config fetch, HPKE encrypt, the
//!   relay POST, decrypt, DNS parse, or a target SERVFAIL/REFUSED — returns an
//!   [`OdohError`]. The caller ([`crate::Resolver`]) maps that to
//!   `AllUpstreamsFailed` → `SERVFAIL`. **We never** fall back to plain DoH or
//!   to querying the target directly; either would de-anonymise the operator,
//!   which is the entire thing ODoH exists to prevent.
//! - **No EDNS Client Subnet.** The query we build carries no ECS option.
//! - **No client-side DNSSEC.** The oblivious arm does not validate the chain
//!   (that lives inside hickory-resolver). `validate_config` rejects
//!   `protocol = "odoh"` together with `dnssec_validation = true` so the knob
//!   never silently means nothing — integrity rests on a validating target.
//! - **Rebinding defence.** Private/loopback rdata is stripped from default-arm
//!   answers exactly as on the doh/doq arms.
//!
//! # Transport
//!
//! The HTTPS hops (config fetch from the target, query POST to the proxy) use
//! `reqwest` with the workspace rustls stack, the configured TLS-version floor,
//! and `https_only`. The transport is abstracted behind [`OdohHttp`] so tests
//! can drive the **real** HPKE round-trip against an in-process mock target
//! without standing up a TLS server.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use odoh_rs::{
    ObliviousDoHConfigContents, ObliviousDoHConfigs, ObliviousDoHMessage,
    ObliviousDoHMessagePlaintext, compose, decrypt_response, encrypt_query, parse,
};
use rustls_pki_types::CertificateDer;

use rustydns_core::config::{DnsConfig, TlsVersion};

use crate::{ResolveOutcome, filter_private_rdata, lookup_to_dns_records};

/// RFC 9230 media type for both the request body and the response.
const ODOH_MEDIA_TYPE: &str = "application/oblivious-dns-message";
/// Where a target publishes its `ObliviousDoHConfigs`.
const ODOH_CONFIGS_PATH: &str = "/.well-known/odohconfigs";

/// Errors from the oblivious arm. Deliberately coarse and qname-free: the
/// caller logs only [`OdohError::kind_label`] at `warn`, and the full value at
/// `debug`, so a query name never reaches a promoted log line.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OdohError {
    #[error("ODoH arm construction failed: {0}")]
    Build(String),
    #[error("ODoH HTTPS transport error: {0}")]
    Http(String),
    #[error("ODoH config fetch returned HTTP {0}")]
    ConfigStatus(u16),
    #[error("ODoH relay returned HTTP {0}")]
    RelayStatus(u16),
    #[error("ODoH target published no usable ObliviousDoHConfig")]
    NoConfig,
    #[error("malformed ObliviousDoHConfigs from target: {0}")]
    ConfigParse(String),
    #[error("could not build the DNS query: {0}")]
    QueryBuild(String),
    #[error("HPKE encrypt_query failed: {0}")]
    Encrypt(String),
    #[error("could not serialise the oblivious query: {0}")]
    Compose(String),
    #[error("malformed oblivious response from proxy: {0}")]
    ResponseParse(String),
    #[error("HPKE decrypt_response failed: {0}")]
    Decrypt(String),
    #[error("target returned an undecodable DNS message: {0}")]
    DnsParse(String),
    #[error("target returned response code {0:?}")]
    TargetRcode(ResponseCode),
    #[cfg(test)]
    #[error("mock transport error: {0}")]
    Mock(String),
}

impl OdohError {
    /// A stable, qname-free label for `warn`-level logging.
    pub(crate) fn kind_label(&self) -> &'static str {
        match self {
            OdohError::Build(_) => "build",
            OdohError::Http(_) => "http",
            OdohError::ConfigStatus(_) => "config_status",
            OdohError::RelayStatus(_) => "relay_status",
            OdohError::NoConfig => "no_config",
            OdohError::ConfigParse(_) => "config_parse",
            OdohError::QueryBuild(_) => "query_build",
            OdohError::Encrypt(_) => "encrypt",
            OdohError::Compose(_) => "compose",
            OdohError::ResponseParse(_) => "response_parse",
            OdohError::Decrypt(_) => "decrypt",
            OdohError::DnsParse(_) => "dns_parse",
            OdohError::TargetRcode(_) => "target_rcode",
            #[cfg(test)]
            OdohError::Mock(_) => "mock",
        }
    }
}

/// One ODoH target resolver: its query URL plus a lazily-fetched, refreshable
/// `ObliviousDoHConfig`. The config is cached in an [`ArcSwapOption`] so a key
/// rotation (signalled by a decrypt failure) clears and refetches it without a
/// lock.
struct OdohTarget {
    /// Full target query URL — kept only for logging (`debug`).
    query_url: String,
    /// `host[:port]` placed in the proxy's `?targethost=` parameter.
    target_host: String,
    /// Path placed in the proxy's `?targetpath=` parameter (e.g. `/dns-query`).
    target_path: String,
    /// `https://host[:port]/.well-known/odohconfigs`.
    configs_url: String,
    /// Cached target config; `None` until first fetch or after a refresh.
    config: ArcSwapOption<ObliviousDoHConfigContents>,
}

impl OdohTarget {
    /// Parse an `https://host[:port]/path` target URL into its ODoH parts.
    fn parse(url: &str) -> Result<Self, OdohError> {
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| OdohError::Build(format!("invalid ODoH target URL `{url}`: {e}")))?;
        if parsed.scheme() != "https" {
            return Err(OdohError::Build(format!(
                "ODoH target `{url}` must be https://"
            )));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| OdohError::Build(format!("ODoH target `{url}` has no host")))?;
        // Include the port only when explicitly present, so default-443 targets
        // produce a clean `targethost=host`; a mock on a random port keeps it.
        let target_host = match parsed.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        };
        let target_path = {
            let p = parsed.path();
            if p.is_empty() {
                "/".to_string()
            } else {
                p.to_string()
            }
        };
        let configs_url = {
            let mut u = parsed.clone();
            u.set_path(ODOH_CONFIGS_PATH);
            u.set_query(None);
            u.to_string()
        };
        Ok(OdohTarget {
            query_url: url.to_string(),
            target_host,
            target_path,
            configs_url,
            config: ArcSwapOption::from(None),
        })
    }
}

/// HTTPS transport for the oblivious hops. An enum (not a `dyn` trait) so the
/// hot path stays monomorphic and tests need no `async-trait`.
enum OdohHttp {
    /// Production: a reqwest client with the TLS floor + `https_only`.
    Reqwest(reqwest::Client),
    /// Tests: an in-process mock target driving the real `odoh-rs` server side.
    #[cfg(test)]
    Mock(Arc<tests::MockRelay>),
}

impl OdohHttp {
    /// `GET {configs_url}` → raw `ObliviousDoHConfigs` bytes.
    async fn fetch_configs(&self, configs_url: &str) -> Result<Vec<u8>, OdohError> {
        match self {
            OdohHttp::Reqwest(client) => {
                let resp = client
                    .get(configs_url)
                    .send()
                    .await
                    .map_err(|e| OdohError::Http(e.to_string()))?;
                if !resp.status().is_success() {
                    return Err(OdohError::ConfigStatus(resp.status().as_u16()));
                }
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| OdohError::Http(e.to_string()))?;
                Ok(bytes.to_vec())
            }
            #[cfg(test)]
            OdohHttp::Mock(m) => m.fetch_configs().map_err(OdohError::Mock),
        }
    }

    /// `POST {proxy}?targethost=&targetpath=` with the oblivious query body →
    /// raw oblivious response bytes.
    async fn post_oblivious(
        &self,
        proxy_url: &str,
        target_host: &str,
        target_path: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, OdohError> {
        match self {
            OdohHttp::Reqwest(client) => {
                use reqwest::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE};
                let resp = client
                    .post(proxy_url)
                    .query(&[("targethost", target_host), ("targetpath", target_path)])
                    .header(CONTENT_TYPE, ODOH_MEDIA_TYPE)
                    .header(ACCEPT, ODOH_MEDIA_TYPE)
                    .header(CACHE_CONTROL, "no-cache, no-store")
                    .body(body)
                    .send()
                    .await
                    .map_err(|e| OdohError::Http(e.to_string()))?;
                if !resp.status().is_success() {
                    return Err(OdohError::RelayStatus(resp.status().as_u16()));
                }
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| OdohError::Http(e.to_string()))?;
                Ok(bytes.to_vec())
            }
            #[cfg(test)]
            OdohHttp::Mock(m) => m
                .relay(target_host, target_path, &body)
                .map_err(OdohError::Mock),
        }
    }
}

/// The oblivious upstream arm (global default only — ODoH is not offered on
/// conditional-forwarding routes).
pub(crate) struct OdohArm {
    targets: Vec<OdohTarget>,
    proxy_url: String,
    http: OdohHttp,
    randomize: bool,
}

impl OdohArm {
    /// Build the arm from the daemon config. `test_roots`, when non-empty,
    /// are added to the HTTPS client's trust store (DoH/ODoH integration tests
    /// inject a mock CA); production passes `&[]`.
    pub(crate) fn new(
        config: &DnsConfig,
        test_roots: &[CertificateDer<'static>],
    ) -> Result<Self, OdohError> {
        let proxy_url =
            config.upstream.odoh_proxy.clone().ok_or_else(|| {
                OdohError::Build("upstream.odoh_proxy is required for ODoH".into())
            })?;
        let mut targets = Vec::with_capacity(config.upstream.resolvers.len());
        for url in &config.upstream.resolvers {
            targets.push(OdohTarget::parse(url)?);
        }
        if targets.is_empty() {
            return Err(OdohError::Build("no ODoH targets configured".into()));
        }
        let http = OdohHttp::Reqwest(build_http_client(
            config.upstream.min_tls_version,
            Duration::from_millis(config.upstream.timeout_ms),
            test_roots,
        )?);
        Ok(OdohArm {
            targets,
            proxy_url,
            http,
            randomize: config.privacy.randomize_upstream_selection,
        })
    }

    /// Resolve `name`/`qtype` over the oblivious transport. Errors are returned
    /// raw; the caller decides fail-closed vs. soft per `upstream.fail_closed`.
    pub(crate) async fn resolve(
        &self,
        name: &str,
        qtype: RecordType,
        block_private_rdata: bool,
    ) -> Result<ResolveOutcome, OdohError> {
        let target = self.select_target();
        let query_wire = build_query_wire(name, qtype)?;
        let response_wire = self.exchange(target, &query_wire).await?;

        let msg =
            Message::from_bytes(&response_wire).map_err(|e| OdohError::DnsParse(e.to_string()))?;
        match msg.metadata.response_code {
            ResponseCode::NoError => {
                let mut records = lookup_to_dns_records(&msg.answers);
                let mut dropped = 0;
                if block_private_rdata {
                    dropped = filter_private_rdata(&mut records);
                }
                Ok(ResolveOutcome {
                    records,
                    private_rdata_dropped: dropped,
                    nxdomain: false,
                })
            }
            // A genuine "name does not exist" — an answer, not a failure.
            ResponseCode::NXDomain => Ok(ResolveOutcome {
                records: Vec::new(),
                private_rdata_dropped: 0,
                nxdomain: true,
            }),
            // SERVFAIL/REFUSED/etc. from the target are upstream failures. Fail
            // closed — never retry over a less-private path.
            other => Err(OdohError::TargetRcode(other)),
        }
    }

    /// Pick a target — random when `randomize_upstream_selection`, else the
    /// first. A single oblivious request goes to exactly one target.
    fn select_target(&self) -> &OdohTarget {
        if self.randomize && self.targets.len() > 1 {
            let idx = (rand::random::<u32>() as usize) % self.targets.len();
            &self.targets[idx]
        } else {
            &self.targets[0]
        }
    }

    /// One oblivious round-trip: fetch/cached config → encrypt → relay POST →
    /// decrypt. On a decrypt failure (most likely a rotated target key) the
    /// cached config is cleared and the whole exchange is retried **once**.
    async fn exchange(&self, target: &OdohTarget, query_wire: &[u8]) -> Result<Bytes, OdohError> {
        let mut last_decrypt_err: Option<String> = None;
        for attempt in 0..2u8 {
            let config = self.config_for(target).await?;
            let query = ObliviousDoHMessagePlaintext::new(query_wire, 0);
            // Scope the (non-Send) ThreadRng so it is dropped before the
            // `.await` below — otherwise the resolve future would be !Send and
            // hickory's RequestHandler could not drive it.
            let (omsg, secret) = {
                let mut rng = rand::rng();
                encrypt_query(&query, &config, &mut rng)
                    .map_err(|e| OdohError::Encrypt(e.to_string()))?
            };
            let body = compose(&omsg)
                .map_err(|e| OdohError::Compose(e.to_string()))?
                .to_vec();

            let resp_bytes = self
                .http
                .post_oblivious(
                    &self.proxy_url,
                    &target.target_host,
                    &target.target_path,
                    body,
                )
                .await?;

            let mut rb = Bytes::from(resp_bytes);
            let resp_msg: ObliviousDoHMessage =
                parse(&mut rb).map_err(|e| OdohError::ResponseParse(e.to_string()))?;
            match decrypt_response(&query, &resp_msg, secret) {
                Ok(plain) => return Ok(plain.into_msg()),
                Err(e) => {
                    last_decrypt_err = Some(e.to_string());
                    if attempt == 0 {
                        // Possible key rotation: drop the cached config and try
                        // a fresh one before giving up.
                        target.config.store(None);
                        continue;
                    }
                }
            }
        }
        Err(OdohError::Decrypt(
            last_decrypt_err.unwrap_or_else(|| "decrypt failed".into()),
        ))
    }

    /// Return the cached target config, fetching + parsing it on a cache miss.
    async fn config_for(
        &self,
        target: &OdohTarget,
    ) -> Result<Arc<ObliviousDoHConfigContents>, OdohError> {
        if let Some(c) = target.config.load_full() {
            return Ok(c);
        }
        tracing::debug!(target = %target.query_url, "fetching ODoH target config");
        let bytes = self.http.fetch_configs(&target.configs_url).await?;
        let mut b = Bytes::from(bytes);
        let configs: ObliviousDoHConfigs =
            parse(&mut b).map_err(|e| OdohError::ConfigParse(e.to_string()))?;
        let contents: ObliviousDoHConfigContents = configs
            .into_iter()
            .next()
            .ok_or(OdohError::NoConfig)?
            .into();
        let arc = Arc::new(contents);
        target.config.store(Some(arc.clone()));
        Ok(arc)
    }
}

impl std::fmt::Debug for OdohArm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Terse + secret-free: never print the HTTP client or cached configs.
        f.debug_struct("OdohArm")
            .field(
                "targets",
                &self
                    .targets
                    .iter()
                    .map(|t| &t.query_url)
                    .collect::<Vec<_>>(),
            )
            .field("proxy_url", &self.proxy_url)
            .field("randomize", &self.randomize)
            .finish()
    }
}

/// Build the reqwest client for the oblivious HTTPS hops: rustls, the TLS
/// floor, `https_only` (defence in depth — the URLs are already https), and a
/// request timeout. Test roots, when present, are trusted in addition to the
/// built-in webpki roots.
fn build_http_client(
    min_tls: TlsVersion,
    timeout: Duration,
    test_roots: &[CertificateDer<'static>],
) -> Result<reqwest::Client, OdohError> {
    let min = match min_tls {
        TlsVersion::Tls12 => reqwest::tls::Version::TLS_1_2,
        TlsVersion::Tls13 => reqwest::tls::Version::TLS_1_3,
    };
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .min_tls_version(min)
        .timeout(timeout);
    for root in test_roots {
        let cert = reqwest::Certificate::from_der(root.as_ref())
            .map_err(|e| OdohError::Build(format!("invalid test root cert: {e}")))?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build()
        .map_err(|e| OdohError::Build(format!("failed to build ODoH HTTPS client: {e}")))
}

/// Build the DNS query wire for `name`/`qtype`: recursion desired, a random
/// 16-bit id, and crucially **no** EDNS Client Subnet and **no** DNSSEC `DO`
/// bit (the oblivious arm does not do client-side validation).
fn build_query_wire(name: &str, qtype: RecordType) -> Result<Vec<u8>, OdohError> {
    let id: u16 = rand::random();
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let qname = Name::from_str(name)
        .map_err(|e| OdohError::QueryBuild(format!("invalid query name: {e}")))?;
    let mut q = Query::new();
    q.set_name(qname).set_query_type(qtype);
    msg.add_query(q);
    msg.to_bytes()
        .map_err(|e| OdohError::QueryBuild(e.to_string()))
}

#[cfg(test)]
mod tests;
