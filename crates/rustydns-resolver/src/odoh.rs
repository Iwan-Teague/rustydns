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
//! - **Client-side DNSSEC (optional).** When `upstream.dnssec_validation` is on,
//!   queries run through hickory's own [`DnssecDnsHandle`] wrapping our oblivious
//!   [`OdohHandle`], so the validator's DNSKEY/DS chain lookups *also* travel
//!   obliviously and the answer is validated to the IANA root anchor. A BOGUS
//!   answer fails closed. With validation off, no chain is checked (integrity
//!   then rests on choosing a validating target).
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
use hickory_proto::dnssec::{DnssecSummary, TrustAnchors};
use hickory_proto::op::{
    DnsRequest, DnsRequestOptions, DnsResponse, Message, MessageType, OpCode, Query, ResponseCode,
};
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_resolver::net::NetError;
use hickory_resolver::net::dnssec::DnssecDnsHandle;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::xfer::{DnsHandle, DnsResponseStream, FirstAnswer};
use odoh_rs::{
    ObliviousDoHConfigContents, ObliviousDoHConfigs, ObliviousDoHMessage,
    ObliviousDoHMessagePlaintext, compose, decrypt_response, encrypt_query, parse,
};
use rustls_pki_types::CertificateDer;

use rustydns_core::config::{DnsConfig, TlsVersion, redact_url_credentials};

use crate::{ResolveOutcome, filter_answer_sanity, filter_private_rdata, lookup_to_dns_records};

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
    #[error("DNSSEC validation failed: {0}")]
    Validation(String),
    #[error("DNSSEC validation: answer is BOGUS (signed but failed verification)")]
    Bogus,
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
            OdohError::Validation(_) => "validation",
            OdohError::Bogus => "bogus",
            #[cfg(test)]
            OdohError::Mock(_) => "mock",
        }
    }
}

/// One ODoH target resolver: its query URL plus a lazily-fetched, refreshable
/// `ObliviousDoHConfig`. The config is cached in an [`ArcSwapOption`] so a key
/// rotation (signalled by a target 4xx or a response that won't decrypt) clears
/// and refetches it without a lock.
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
    /// Largest acceptable `ObliviousDoHConfigs` document. A single HPKE config
    /// is ~60 bytes; even a long key-rotation history stays far below this.
    const MAX_CONFIG_BYTES: u64 = 64 * 1024;
    /// Largest acceptable oblivious response body. An encrypted DNS message is
    /// bounded by the DNS message size (well under 64 KiB) plus padding.
    const MAX_RESPONSE_BYTES: u64 = 128 * 1024;

    /// Drain a response body under a hard byte cap: content-length precheck,
    /// then a chunked streaming read that aborts as soon as the running total
    /// would exceed `cap`. A hostile relay (the less-trusted half of the ODoH
    /// pair) cannot stream unbounded bytes into memory before parsing — same
    /// defence the blocklist fetcher applies to its sources ("no unbounded
    /// memory" invariant).
    async fn read_capped(
        resp: reqwest::Response,
        cap: u64,
        what: &'static str,
    ) -> Result<Vec<u8>, OdohError> {
        if let Some(len) = resp.content_length()
            && len > cap
        {
            return Err(OdohError::Http(format!(
                "{what} content-length {len} exceeds {cap}-byte cap"
            )));
        }
        use futures_util::StreamExt;
        let mut body = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            // PRIVACY: reqwest error text can embed the full request URL,
            // credentials included — redact before it reaches logs.
            let chunk =
                chunk.map_err(|e| OdohError::Http(redact_url_credentials(&e.to_string())))?;
            if (body.len() as u64).saturating_add(chunk.len() as u64) > cap {
                return Err(OdohError::Http(format!(
                    "{what} response exceeds {cap}-byte cap"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// `GET {configs_url}` → raw `ObliviousDoHConfigs` bytes.
    async fn fetch_configs(&self, configs_url: &str) -> Result<Vec<u8>, OdohError> {
        match self {
            OdohHttp::Reqwest(client) => {
                let resp = client
                    .get(configs_url)
                    .send()
                    .await
                    .map_err(|e| OdohError::Http(redact_url_credentials(&e.to_string())))?;
                if !resp.status().is_success() {
                    return Err(OdohError::ConfigStatus(resp.status().as_u16()));
                }
                Self::read_capped(resp, Self::MAX_CONFIG_BYTES, "ODoH config").await
            }
            #[cfg(test)]
            OdohHttp::Mock(m) => m.fetch_configs(),
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
                    .map_err(|e| OdohError::Http(redact_url_credentials(&e.to_string())))?;
                if !resp.status().is_success() {
                    return Err(OdohError::RelayStatus(resp.status().as_u16()));
                }
                Self::read_capped(resp, Self::MAX_RESPONSE_BYTES, "oblivious").await
            }
            #[cfg(test)]
            OdohHttp::Mock(m) => m.relay(target_host, target_path, &body),
        }
    }
}

/// Shared oblivious transport state. Held behind an `Arc` so it can back both
/// [`OdohArm`] (the resolver-facing API) and [`OdohHandle`] (the hickory
/// `DnsHandle` the DNSSEC validator drives).
struct OdohTransport {
    targets: Vec<OdohTarget>,
    /// Oblivious relay URLs. One is chosen per query (random when
    /// `randomize_upstream_selection`), so several independent relays spread the
    /// client's encrypted traffic — no single relay sees it all.
    proxy_urls: Vec<String>,
    http: OdohHttp,
    randomize: bool,
    /// Pad the oblivious query plaintext to a fixed block (RFC 8467 style) when
    /// `privacy.upstream_padding` is set, so the encrypted query size no longer
    /// leaks the exact query length. Unlike the doh/doq arms — where hickory
    /// 0.26 can't pad — ODoH can, because odoh-rs pads the plaintext directly.
    pad_queries: bool,
}

/// The oblivious upstream arm (global default only — ODoH is not offered on
/// conditional-forwarding routes).
pub(crate) struct OdohArm {
    transport: Arc<OdohTransport>,
    /// `Some` when `upstream.dnssec_validation` is on: queries run through
    /// hickory's own DNSSEC validator (chaining to this anchor) over the
    /// oblivious transport — every DNSKEY/DS lookup the validator makes also
    /// travels obliviously. `None` = no client-side validation.
    trust_anchor: Option<Arc<TrustAnchors>>,
}

/// A hickory [`DnsHandle`] over the oblivious transport, so hickory's own DNSSEC
/// validator can drive it. Cloneable + `Send`/`Sync` via the shared `Arc`.
#[derive(Clone)]
struct OdohHandle {
    transport: Arc<OdohTransport>,
}

impl OdohArm {
    /// Build the arm from the daemon config. `test_roots`, when non-empty,
    /// are added to the HTTPS client's trust store (DoH/ODoH integration tests
    /// inject a mock CA); production passes `&[]`.
    pub(crate) fn new(
        config: &DnsConfig,
        test_roots: &[CertificateDer<'static>],
    ) -> Result<Self, OdohError> {
        let proxy_urls = config.upstream.odoh_proxies.clone();
        if proxy_urls.is_empty() {
            return Err(OdohError::Build(
                "upstream.odoh_proxies must list at least one oblivious relay for ODoH".into(),
            ));
        }
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
        let transport = Arc::new(OdohTransport {
            targets,
            proxy_urls,
            http,
            randomize: config.privacy.randomize_upstream_selection,
            pad_queries: config.privacy.upstream_padding,
        });
        // Client-side DNSSEC over the oblivious arm: run queries through
        // hickory's validator chaining to the IANA root anchor. The validator's
        // own DNSKEY/DS lookups travel obliviously through the same handle.
        let trust_anchor = if config.upstream.dnssec_validation {
            Some(Arc::new(TrustAnchors::default()))
        } else {
            None
        };
        Ok(OdohArm {
            transport,
            trust_anchor,
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
        match &self.trust_anchor {
            Some(anchor) => {
                self.resolve_validated(name, qtype, block_private_rdata, anchor)
                    .await
            }
            None => self.resolve_plain(name, qtype, block_private_rdata).await,
        }
    }

    /// Unvalidated oblivious resolution: build the query, do one oblivious
    /// exchange, and shape the response into an outcome.
    async fn resolve_plain(
        &self,
        name: &str,
        qtype: RecordType,
        block_private_rdata: bool,
    ) -> Result<ResolveOutcome, OdohError> {
        let target = self.transport.select_target();
        let query_wire = build_query_wire(name, qtype)?;
        let response_wire = self.transport.exchange(target, &query_wire).await?;
        let msg =
            Message::from_bytes(&response_wire).map_err(|e| OdohError::DnsParse(e.to_string()))?;
        outcome_from_parts(
            &msg.answers,
            msg.metadata.response_code,
            name,
            qtype,
            block_private_rdata,
        )
    }

    /// DNSSEC-validated oblivious resolution: drive hickory's `DnssecDnsHandle`
    /// over our oblivious handle. The validator fetches the DNSKEY/DS chain
    /// (also obliviously), checks signatures up to `anchor`, and stamps each
    /// record's proof. We fail closed on a BOGUS answer (signed but forged);
    /// Secure and Insecure (unsigned zone) answers are both served — DNSSEC
    /// rejects forgeries, it does not require every zone to be signed.
    async fn resolve_validated(
        &self,
        name: &str,
        qtype: RecordType,
        block_private_rdata: bool,
        anchor: &Arc<TrustAnchors>,
    ) -> Result<ResolveOutcome, OdohError> {
        let qname = Name::from_str(name)
            .map_err(|e| OdohError::QueryBuild(format!("invalid query name: {e}")))?;
        let handle = OdohHandle {
            transport: self.transport.clone(),
        };
        let validating = DnssecDnsHandle::with_trust_anchor(handle, anchor.clone());
        let response = validating
            .lookup(Query::query(qname, qtype), DnsRequestOptions::default())
            .first_answer()
            .await
            .map_err(|e| OdohError::Validation(e.to_string()))?;

        if matches!(
            DnssecSummary::from_records(response.answers.iter()),
            DnssecSummary::Bogus
        ) {
            return Err(OdohError::Bogus);
        }
        outcome_from_parts(
            &response.answers,
            response.metadata.response_code,
            name,
            qtype,
            block_private_rdata,
        )
    }
}

/// Shape a response's answers + rcode into a [`ResolveOutcome`]. Shared by the
/// plain and validated paths. A non-NoError/NXDomain rcode (SERVFAIL/REFUSED)
/// is an upstream failure — fail closed, never retry over a less-private path.
///
/// Answers pass through the SAME sanity pipeline as the hickory arms
/// ([`crate::filter_answer_sanity`]: bailiwick containment, unrequested type,
/// identical-record dedup) before the opt-in rebinding-defence filter — the
/// oblivious transport must never serve an answer shape the standard path
/// would have filtered (AQ-64).
fn outcome_from_parts(
    answers: &[Record],
    response_code: ResponseCode,
    qname: &str,
    qtype: RecordType,
    block_private_rdata: bool,
) -> Result<ResolveOutcome, OdohError> {
    match response_code {
        ResponseCode::NoError => {
            let mut records = lookup_to_dns_records(answers);
            let mut dropped = filter_answer_sanity(&mut records, qname, qtype);
            if block_private_rdata {
                dropped += filter_private_rdata(&mut records);
            }
            Ok(ResolveOutcome {
                records,
                private_rdata_dropped: dropped,
                nxdomain: false,
            })
        }
        ResponseCode::NXDomain => Ok(ResolveOutcome {
            records: Vec::new(),
            private_rdata_dropped: 0,
            nxdomain: true,
        }),
        other => Err(OdohError::TargetRcode(other)),
    }
}

impl OdohTransport {
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

    /// Pick the oblivious relay for this query — random when
    /// `randomize_upstream_selection`, else the first. Spreading queries across
    /// independent relays (so no single relay sees all your traffic) is the
    /// whole point of configuring more than one.
    fn select_proxy(&self) -> &str {
        if self.randomize && self.proxy_urls.len() > 1 {
            let idx = (rand::random::<u32>() as usize) % self.proxy_urls.len();
            &self.proxy_urls[idx]
        } else {
            &self.proxy_urls[0]
        }
    }

    /// One oblivious round-trip: fetch/cached config → encrypt → relay POST →
    /// decrypt.
    ///
    /// Targets rotate their HPKE key periodically. If the **first** attempt hits
    /// a *stale-key* signal — the target rejecting our query with HTTP 400 (RFC
    /// 9230's rotation signal) or a response that won't decrypt — the cached
    /// config is dropped and the exchange is retried **once** with a freshly
    /// fetched config. Any other failure (other statuses, network, malformed
    /// response) fails closed immediately: a config refetch wouldn't help.
    /// After two attempts we give up — still fail-closed, never a less-private
    /// fallback.
    async fn exchange(&self, target: &OdohTarget, query_wire: &[u8]) -> Result<Bytes, OdohError> {
        // One relay for the whole exchange (both attempts) — a different relay
        // wouldn't change a key-rotation outcome, and keeping it stable avoids
        // fanning a single query across relays.
        let proxy = self.select_proxy();
        let mut last_err: Option<OdohError> = None;
        for attempt in 0..2u8 {
            let may_retry = attempt == 0;
            let config = self.config_for(target).await?;
            let query = ObliviousDoHMessagePlaintext::new(
                query_wire,
                query_padding(query_wire.len(), self.pad_queries),
            );
            // hpke 0.13 expects a rand_core-0.9 CSPRNG; hand it OsRng wrapped
            // in UnwrapErr (OsRng is fallible-only (TryRngCore) in rand_core
            // 0.9). Entropy health is probed first so an OS RNG failure maps
            // to a query-level error (fail closed) instead of a panic tearing
            // down the client's connection task; the wrapper's panic is then a
            // practically-unreachable backstop.
            let (omsg, secret) = {
                use rand_core::{OsRng, TryRngCore, UnwrapErr};
                OsRng
                    .try_fill_bytes(&mut [0u8; 1])
                    .map_err(|e| OdohError::Encrypt(format!("os rng unavailable: {e}")))?;
                let mut rng = UnwrapErr(OsRng);
                encrypt_query(&query, &config, &mut rng)
                    .map_err(|e| OdohError::Encrypt(e.to_string()))?
            };
            let body = compose(&omsg)
                .map_err(|e| OdohError::Compose(e.to_string()))?
                .to_vec();

            match self
                .http
                .post_oblivious(proxy, &target.target_host, &target.target_path, body)
                .await
            {
                Ok(resp_bytes) => {
                    let mut rb = Bytes::from(resp_bytes);
                    match parse::<ObliviousDoHMessage, _>(&mut rb) {
                        Ok(resp_msg) => match decrypt_response(&query, &resp_msg, secret) {
                            Ok(plain) => return Ok(plain.into_msg()),
                            // The response did not decrypt — possibly a rotated
                            // key. Drop the cached config and retry once.
                            Err(e) => {
                                last_err = Some(OdohError::Decrypt(e.to_string()));
                                if may_retry {
                                    target.config.store(None);
                                    continue;
                                }
                            }
                        },
                        // A malformed oblivious response is not a stale-key
                        // signal — fail closed, don't retry.
                        Err(e) => last_err = Some(OdohError::ResponseParse(e.to_string())),
                    }
                }
                // RFC 9230 key rotation: the target rejected our (stale-key)
                // query with HTTP 400. Only 400 is the stale-key signal —
                // other relay-side 4xx (403/429 auth or throttling) must not
                // trigger a config refetch per query, or a throttling relay
                // turns us into a `/.well-known` fetch loop against the
                // target. Other statuses fail closed.
                Err(OdohError::RelayStatus(code)) if may_retry && code == 400 => {
                    last_err = Some(OdohError::RelayStatus(code));
                    target.config.store(None);
                    continue;
                }
                // 5xx, network, config errors: a refetch won't help — fail closed.
                Err(e) => last_err = Some(e),
            }
            // Reached only on a non-retriable failure (or the second attempt):
            // stop looping and fail closed below.
            break;
        }
        Err(last_err.unwrap_or_else(|| OdohError::Decrypt("oblivious exchange failed".into())))
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

impl DnsHandle for OdohHandle {
    type Response = DnsResponseStream;
    type Runtime = TokioRuntimeProvider;

    // `is_verifying_dnssec` keeps the default `false`: this is the leaf
    // transport, not a validator. The wrapping `DnssecDnsHandle` is what
    // verifies; claiming otherwise here would mislead it.

    /// Send whatever query the validator hands us — the user's query OR a
    /// DNSKEY/DS chain lookup — obliviously, and return the decrypted response.
    /// The wrapping `DnssecDnsHandle` has already set the DO/CD/AD bits on
    /// `request`; we just transmit it.
    fn send(&self, request: DnsRequest) -> Self::Response {
        let transport = self.transport.clone();
        let fut = async move {
            let query_wire = request
                .to_bytes()
                .map_err(|e| NetError::Msg(format!("odoh: encode request: {e}")))?;
            let target = transport.select_target();
            let response_wire = transport
                .exchange(target, &query_wire)
                .await
                .map_err(|e| NetError::Msg(format!("odoh: {}: {e}", e.kind_label())))?;
            DnsResponse::from_buffer(response_wire.to_vec()).map_err(NetError::from)
        };
        DnsResponseStream::from(Box::pin(fut))
    }
}

impl std::fmt::Debug for OdohArm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Terse + secret-free: never print the HTTP client or cached configs.
        f.debug_struct("OdohArm")
            .field(
                "targets",
                &self
                    .transport
                    .targets
                    .iter()
                    .map(|t| &t.query_url)
                    .collect::<Vec<_>>(),
            )
            .field("proxy_urls", &self.transport.proxy_urls)
            .field("randomize", &self.transport.randomize)
            .field("dnssec", &self.trust_anchor.is_some())
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
        // Every redirect hop hands the client IP *and* the oblivious
        // ciphertext to another endpoint — the exposure set grows with each
        // hop. reqwest's default of 10 is far beyond anything legitimate
        // relay/target load-balancing needs; three matches the blocklist
        // loader's cap.
        .redirect(reqwest::redirect::Policy::limited(3))
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
/// Number of zero pad bytes to append to the oblivious query plaintext so its
/// length rounds up to the next 128-byte block (RFC 8467's recommended query
/// block size). Returns 0 when padding is off or the length already lands on a
/// block boundary. Quantising the plaintext length quantises the ciphertext
/// length, so an observer can no longer read the exact query size off the wire.
fn query_padding(msg_len: usize, pad: bool) -> usize {
    const BLOCK: usize = 128;
    if pad {
        (BLOCK - (msg_len % BLOCK)) % BLOCK
    } else {
        0
    }
}

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
