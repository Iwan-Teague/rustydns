//! End-to-end ODoH tests against an in-process mock target.
//!
//! The mock runs the **real** `odoh-rs` server side (HPKE keypair, `decrypt_query`
//! / `encrypt_response`), so the client's `encrypt_query` / `decrypt_response`
//! and the whole oblivious round-trip are exercised against genuine crypto —
//! entirely offline, no TLS server. What is *not* covered here (reqwest's HTTPS
//! transport and TLS-floor enforcement) is third-party code configured in
//! [`super::build_http_client`]; the rustydns-owned protocol logic is.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use hickory_proto::dnssec::crypto::EcdsaSigningKey;
use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, RRSIG};
use hickory_proto::dnssec::{Algorithm, DnssecSigner, PublicKeyBuf, SigningKey, TrustAnchors};
use hickory_proto::op::{DnsRequestOptions, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::rdata::opt::EdnsCode;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_resolver::net::xfer::{DnsHandle, FirstAnswer};
use odoh_rs::{
    ObliviousDoHConfig, ObliviousDoHConfigs, ObliviousDoHKeyPair, ObliviousDoHMessage,
    ObliviousDoHMessagePlaintext, ResponseNonce, compose, decrypt_query, encrypt_response, parse,
};
use time::OffsetDateTime;

use rustydns_core::record::RecordData;

use super::*;

/// How the mock target answers (or fails), so a test can drive every branch.
#[derive(Clone, Copy)]
enum MockMode {
    /// Answer the query with this A record (NoError).
    AnswerA(Ipv4Addr),
    /// Return NXDOMAIN — a valid "does not exist" answer.
    Nxdomain,
    /// Return SERVFAIL — a target failure that must fail the arm closed.
    ServFail,
    /// The relay/proxy hop itself errors (network failure → fail closed).
    RelayError,
    /// Return undecryptable garbage (→ fail closed, never surfaced).
    Garbage,
    /// Return a correctly encrypted envelope whose decrypted DNS plaintext
    /// carries a self-referential compression pointer as the answer owner
    /// name — decompression can never terminate, so the arm must fail
    /// closed in bounded work.
    PointerLoopAnswer,
    /// Rotate the HPKE key on the FIRST request and reject the (now stale-key)
    /// query with HTTP 400 (RFC 9230's rotation signal), like a real target at
    /// key rotation; answer with this A on the retry after the client refetches
    /// the config.
    RotateThenAnswer(Ipv4Addr),
    /// Always reject with the given status — `400` exercises the stale-key
    /// refetch + single retry then fail-closed (bounded, not an infinite loop);
    /// other relay-side 4xx must fail closed WITHOUT a config refetch.
    AlwaysReject(u16),
    /// Serve a pre-built (DNSSEC-signed) zone: answer each query with the
    /// records in `MockRelay::responses` for its qtype. Used by the DNSSEC tests.
    SignedZone,
}

/// Mutable target state, so a test can rotate the key mid-exchange.
struct MockState {
    keypair: ObliviousDoHKeyPair,
    configs: Vec<u8>,
    rotated: bool,
    /// Number of `/.well-known/odohconfigs` fetches served (test assertions).
    config_fetches: usize,
    /// Decrypted plaintext queries, most recent last (bounded so a long-lived
    /// arm under fuzz-like loops cannot grow unbounded). Lets tests inspect
    /// exactly what the target received — e.g. that the oblivious wire never
    /// carries an EDNS Client Subnet option.
    captured: Vec<Message>,
    /// The RAW HTTP bodies the relay/target hop received, most recent last
    /// (same bound as `captured`). Lets tests assert what the wire actually
    /// carried before any HPKE decryption — e.g. that the oblivious query is
    /// ciphertext and leaks no plaintext query name to the hop.
    captured_raw: Vec<Vec<u8>>,
}

/// In-process ODoH target + relay. Holds a real HPKE keypair and answers with
/// genuine `odoh-rs` server-side encryption.
pub(crate) struct MockRelay {
    state: std::sync::Mutex<MockState>,
    mode: MockMode,
    /// For `MockMode::SignedZone`: the records to return per query type (e.g.
    /// `A -> [A, RRSIG(A)]`, `DNSKEY -> [DNSKEY, RRSIG(DNSKEY)]`).
    responses: std::collections::HashMap<RecordType, Vec<Record>>,
}

/// Fresh HPKE keypair plus its serialised `ObliviousDoHConfigs` bytes.
fn fresh_keypair() -> (ObliviousDoHKeyPair, Vec<u8>) {
    // odoh-rs wants a rand_core-0.9 CSPRNG — OsRng via the UnwrapErr adapter
    // (same as the production path in `OdohTransport::exchange`).
    use rand_core::{OsRng, UnwrapErr};
    let mut rng = UnwrapErr(OsRng);
    let keypair = ObliviousDoHKeyPair::new(&mut rng);
    let config: ObliviousDoHConfig = keypair.public().clone().into();
    let configs = compose(&ObliviousDoHConfigs::from(vec![config]))
        .expect("compose ObliviousDoHConfigs")
        .to_vec();
    (keypair, configs)
}

impl MockRelay {
    fn new(mode: MockMode) -> Self {
        Self::with_responses(mode, std::collections::HashMap::new())
    }

    /// A signed-zone mock: every query is answered from `responses[qtype]`.
    fn signed(responses: std::collections::HashMap<RecordType, Vec<Record>>) -> Self {
        Self::with_responses(MockMode::SignedZone, responses)
    }

    fn with_responses(
        mode: MockMode,
        responses: std::collections::HashMap<RecordType, Vec<Record>>,
    ) -> Self {
        let (keypair, configs) = fresh_keypair();
        MockRelay {
            state: std::sync::Mutex::new(MockState {
                keypair,
                configs,
                rotated: false,
                config_fetches: 0,
                captured: Vec::new(),
                captured_raw: Vec::new(),
            }),
            mode,
            responses,
        }
    }

    /// Serve the target's currently-published `ObliviousDoHConfigs`.
    pub(super) fn fetch_configs(&self) -> Result<Vec<u8>, OdohError> {
        let mut st = self.state.lock().unwrap();
        st.config_fetches += 1;
        Ok(st.configs.clone())
    }

    /// Relay + target: decrypt the oblivious query, answer per [`MockMode`], and
    /// re-encrypt the response — or simulate a transport/crypto failure.
    pub(super) fn relay(
        &self,
        _target_host: &str,
        _target_path: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, OdohError> {
        match self.mode {
            MockMode::RelayError => {
                return Err(OdohError::Http("simulated proxy/network failure".into()));
            }
            MockMode::Garbage => return Ok(vec![0xde, 0xad, 0xbe, 0xef]),
            MockMode::AlwaysReject(code) => return Err(OdohError::RelayStatus(code)),
            MockMode::RotateThenAnswer(_) => {
                let mut st = self.state.lock().unwrap();
                if !st.rotated {
                    // First request: rotate the key, publish the new config, and
                    // reject the stale-key query the way a real target would
                    // (HTTP 400 — RFC 9230's rotation signal).
                    let (keypair, configs) = fresh_keypair();
                    st.keypair = keypair;
                    st.configs = configs;
                    st.rotated = true;
                    return Err(OdohError::RelayStatus(400));
                }
            }
            _ => {}
        }

        let mut st = self.state.lock().unwrap();
        let mut b = Bytes::copy_from_slice(body);
        let qmsg: ObliviousDoHMessage =
            parse(&mut b).map_err(|e| OdohError::Mock(e.to_string()))?;
        let (q_plain, secret) =
            decrypt_query(&qmsg, &st.keypair).map_err(|e| OdohError::Mock(e.to_string()))?;

        let query_msg = Message::from_bytes(&q_plain.clone().into_msg())
            .map_err(|e| OdohError::Mock(e.to_string()))?;
        {
            const CAPTURE_CAP: usize = 32;
            if st.captured.len() >= CAPTURE_CAP {
                st.captured.remove(0);
            }
            if st.captured_raw.len() >= CAPTURE_CAP {
                st.captured_raw.remove(0);
            }
            st.captured_raw.push(body.to_vec());
            st.captured.push(query_msg.clone());
        }
        let resp_wire = if matches!(self.mode, MockMode::SignedZone) {
            build_signed_response(&self.responses, &query_msg)?
        } else {
            build_mock_response(self.mode, &query_msg)?
        };

        let r_plain = ObliviousDoHMessagePlaintext::new(resp_wire, 0);
        let nonce: ResponseNonce = [0u8; 16];
        let rmsg = encrypt_response(&q_plain, &r_plain, secret, nonce)
            .map_err(|e| OdohError::Mock(e.to_string()))?;
        Ok(compose(&rmsg)
            .map_err(|e| OdohError::Mock(e.to_string()))?
            .to_vec())
    }
}

fn build_mock_response(mode: MockMode, query: &Message) -> Result<Vec<u8>, OdohError> {
    let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_available = true;
    let name: Option<Name> = query.queries.first().map(|q| q.name().clone());
    if let Some(q) = query.queries.first() {
        resp.queries.push(q.clone());
    }
    match mode {
        MockMode::AnswerA(ip) | MockMode::RotateThenAnswer(ip) => {
            resp.metadata.response_code = ResponseCode::NoError;
            if let Some(name) = name {
                resp.answers
                    .push(Record::from_rdata(name, 60, RData::A(A(ip))));
            }
        }
        MockMode::Nxdomain => resp.metadata.response_code = ResponseCode::NXDomain,
        MockMode::ServFail => resp.metadata.response_code = ResponseCode::ServFail,
        MockMode::PointerLoopAnswer => {
            // Handcrafted plaintext wire: header + question + one answer
            // whose owner NAME is a compression pointer pointing at
            // ITSELF. hickory's decoder forbids non-prior pointers on the
            // first hop (`PointerNotPriorToLabel`), so this can never
            // decompress — exactly the hostile-upstream shape the arm
            // must reject in bounded work.
            const QNAME: &[u8] = b"\x07example\x03com\x00";
            let mut raw: Vec<u8> = Vec::new();
            raw.extend_from_slice(&query.metadata.id.to_be_bytes());
            raw.extend_from_slice(&[0x81, 0x80]); // QR=1, RA=1
            raw.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QD=1 AN=1
            raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            raw.extend_from_slice(QNAME);
            raw.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
            let self_offset = (12 + QNAME.len() + 4) as u16;
            raw.extend_from_slice(&[
                0xC0 | (self_offset >> 8) as u8,
                self_offset as u8,
            ]);
            raw.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
            raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // ttl 60
            raw.extend_from_slice(&[0x00, 0x04, 203, 0, 113, 7]);
            return Ok(raw);
        }
        MockMode::RelayError | MockMode::Garbage | MockMode::AlwaysReject(_) => {
            unreachable!("handled before crypto")
        }
        MockMode::SignedZone => unreachable!("handled by build_signed_response"),
    }
    resp.to_bytes().map_err(|e| OdohError::Mock(e.to_string()))
}

/// Answer a query from a pre-built signed zone: return `responses[qtype]` (the
/// RRset + its RRSIG) as an authoritative NoError answer.
fn build_signed_response(
    responses: &std::collections::HashMap<RecordType, Vec<Record>>,
    query: &Message,
) -> Result<Vec<u8>, OdohError> {
    let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_available = true;
    resp.metadata.authoritative = true;
    resp.metadata.response_code = ResponseCode::NoError;
    if let Some(q) = query.queries.first() {
        resp.queries.push(q.clone());
        if let Some(records) = responses.get(&q.query_type()) {
            resp.answers.extend(records.iter().cloned());
        }
    }
    resp.to_bytes().map_err(|e| OdohError::Mock(e.to_string()))
}

/// Build an `OdohArm` wired to a mock target (no reqwest, no TLS).
fn arm_with_mock(mode: MockMode) -> OdohArm {
    arm_with_mock_opts(mode, false)
}

/// Lock the mock relay's mutable state for assertions.
fn mock_state_of(arm: &OdohArm) -> std::sync::MutexGuard<'_, MockState> {
    match &arm.transport.http {
        OdohHttp::Mock(m) => m.state.lock().unwrap(),
        _ => unreachable!("test arms always use the mock transport"),
    }
}

/// Clone out the decrypted queries the mock target received (guard dropped so
/// the arm stays usable).
fn captured_queries_of(arm: &OdohArm) -> Vec<Message> {
    mock_state_of(arm).captured.clone()
}

fn arm_with_mock_opts(mode: MockMode, pad_queries: bool) -> OdohArm {
    OdohArm {
        transport: mock_transport(
            mode,
            pad_queries,
            vec!["https://proxy.test/".to_string()],
            false,
        ),
        trust_anchor: None,
    }
}

/// Build a shared mock transport (single target, mock relay) for tests.
fn mock_transport(
    mode: MockMode,
    pad_queries: bool,
    proxy_urls: Vec<String>,
    randomize: bool,
) -> Arc<OdohTransport> {
    let target = OdohTarget::parse("https://target.test/dns-query").expect("parse target");
    Arc::new(OdohTransport {
        targets: vec![target],
        proxy_urls,
        http: OdohHttp::Mock(Arc::new(MockRelay::new(mode))),
        randomize,
        pad_queries,
    })
}

#[test]
fn odoh_target_parse_splits_host_path_and_configs() {
    let t = OdohTarget::parse("https://odoh.example/dns-query").unwrap();
    assert_eq!(t.target_host, "odoh.example");
    assert_eq!(t.target_path, "/dns-query");
    assert_eq!(
        t.configs_url,
        "https://odoh.example/.well-known/odohconfigs"
    );
}

#[test]
fn odoh_target_parse_keeps_explicit_port() {
    let t = OdohTarget::parse("https://odoh.example:8443/q").unwrap();
    assert_eq!(t.target_host, "odoh.example:8443");
    assert_eq!(t.target_path, "/q");
    assert_eq!(
        t.configs_url,
        "https://odoh.example:8443/.well-known/odohconfigs"
    );
}

#[test]
fn odoh_target_parse_brackets_ipv6_authority() {
    // The ?targethost= authority must keep the brackets on an IPv6 literal, or
    // the host:port is ambiguous and the proxy can't reach the target.
    let t = OdohTarget::parse("https://[2606:4700::1111]:8443/dns-query").unwrap();
    assert_eq!(t.target_host, "[2606:4700::1111]:8443");
}

#[test]
fn odoh_target_parse_rejects_non_https() {
    assert!(OdohTarget::parse("http://odoh.example/").is_err());
    assert!(OdohTarget::parse("quic://odoh.example/").is_err());
    assert!(OdohTarget::parse("not a url").is_err());
}

#[test]
fn query_padding_rounds_up_to_128_byte_blocks() {
    assert_eq!(query_padding(0, true), 0);
    assert_eq!(query_padding(1, true), 127);
    assert_eq!(query_padding(100, true), 28);
    assert_eq!(query_padding(128, true), 0);
    assert_eq!(query_padding(129, true), 127);
    // Off → never pads, regardless of length.
    assert_eq!(query_padding(1, false), 0);
    assert_eq!(query_padding(200, false), 0);
}

#[tokio::test]
async fn odoh_padded_query_still_round_trips() {
    // With upstream_padding on, the query plaintext is padded to a 128-byte
    // block; the target must still decrypt it and answer correctly (odoh-rs
    // strips the zero padding on the server side).
    let arm = arm_with_mock_opts(MockMode::AnswerA(Ipv4Addr::new(203, 0, 113, 11)), true);
    let outcome = arm
        .resolve("padded.example.", RecordType::A, false)
        .await
        .expect("padded oblivious round-trip should succeed");
    assert_eq!(outcome.records.len(), 1);
    match &outcome.records[0].data {
        RecordData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(203, 0, 113, 11)),
        other => panic!("expected an A record, got {other:?}"),
    }
}

#[tokio::test]
async fn odoh_round_trip_answers_a_record() {
    let arm = arm_with_mock(MockMode::AnswerA(Ipv4Addr::new(203, 0, 113, 7)));
    let outcome = arm
        .resolve("example.com.", RecordType::A, false)
        .await
        .expect("oblivious round-trip should succeed");
    assert!(!outcome.nxdomain);
    assert_eq!(outcome.records.len(), 1, "expected exactly one A record");
    match &outcome.records[0].data {
        RecordData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(203, 0, 113, 7)),
        other => panic!("expected an A record, got {other:?}"),
    }
}

#[tokio::test]
async fn odoh_nxdomain_sets_flag() {
    let arm = arm_with_mock(MockMode::Nxdomain);
    let outcome = arm
        .resolve("nope.example.", RecordType::A, false)
        .await
        .expect("NXDOMAIN is a valid answer, not a failure");
    assert!(outcome.records.is_empty());
    assert!(outcome.nxdomain, "NXDOMAIN must set the nxdomain flag");
}

#[tokio::test]
async fn odoh_target_servfail_is_an_error() {
    // A SERVFAIL from the target is an upstream failure — the caller fails
    // closed (never retries over a less-private path).
    let arm = arm_with_mock(MockMode::ServFail);
    let err = arm
        .resolve("example.com.", RecordType::A, false)
        .await
        .expect_err("target SERVFAIL must surface as an error");
    assert_eq!(err.kind_label(), "target_rcode");
}

#[tokio::test]
async fn odoh_relay_failure_is_an_error() {
    // A failed relay hop must error (→ SERVFAIL upstream), never silently fall
    // back to a non-oblivious path.
    let arm = arm_with_mock(MockMode::RelayError);
    let err = arm
        .resolve("example.com.", RecordType::A, false)
        .await
        .expect_err("relay failure must surface as an error");
    assert_eq!(err.kind_label(), "http");
}

#[tokio::test]
async fn odoh_garbage_response_is_an_error() {
    // An undecodable response must error out — we never hand back unverified
    // bytes from the proxy.
    let arm = arm_with_mock(MockMode::Garbage);
    let err = arm
        .resolve("example.com.", RecordType::A, false)
        .await
        .expect_err("garbage response must surface as an error");
    assert!(
        matches!(err.kind_label(), "response_parse" | "decrypt"),
        "unexpected error kind: {}",
        err.kind_label()
    );
}

#[tokio::test]
async fn odoh_compression_pointer_loop_fails_closed_in_bounded_work() {
    // Name-decompression safety: a hostile target answers with a correctly
    // encrypted envelope whose plaintext DNS message contains a
    // self-referential compression pointer as the answer owner name
    // (offset N pointing back to N). Decompression of such a name can
    // never terminate; hickory's strictly-prior pointer rule rejects it on
    // the first hop. The arm must surface that as a parse failure — never
    // serve, never hang, never allocate unboundedly — and do so promptly.
    let arm = arm_with_mock(MockMode::PointerLoopAnswer);
    let started = std::time::Instant::now();
    let err = arm
        .resolve("example.com.", RecordType::A, false)
        .await
        .expect_err("a decompression loop must fail closed");
    assert_eq!(err.kind_label(), "dns_parse", "the plaintext must fail DNS parsing, not transport or crypto");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "pointer-loop rejection exceeded the bounded-work budget"
    );
}

#[tokio::test]
async fn odoh_validated_path_rejects_an_expired_signature() {
    // A DIFFERENT fail-closed mode from the forged-answer case: the data is
    // bit-exact and signed by the CORRECT (trust-anchored) key — only the
    // RRSIG validity window has ended (signed 40 days ago with a 30-day
    // validity). Crypto verifies; TIME does not. The validator must still
    // mark it BOGUS and the arm must fail closed rather than serve
    // replayable stale signatures.
    let (responses, pubkey) = build_signed_zone_expiring_after(
        "secure.example.",
        Ipv4Addr::new(192, 0, 2, 53),
        time::Duration::days(40),
    );
    let arm = arm_with_signed_zone(responses, &pubkey);
    let err = arm
        .resolve("secure.example.", RecordType::A, false)
        .await
        .expect_err("an answer whose RRSIG has expired must fail closed");
    assert!(
        matches!(err.kind_label(), "bogus" | "validation"),
        "expected a DNSSEC failure, got {}",
        err.kind_label()
    );
}

#[tokio::test]
async fn odoh_private_rdata_filtered_when_enabled() {
    // The rebinding defence applies to ODoH default-arm answers just like the
    // hickory default arm: a private A is stripped and counted.
    let arm = arm_with_mock(MockMode::AnswerA(Ipv4Addr::new(192, 168, 1, 5)));
    let outcome = arm
        .resolve("intranet.example.", RecordType::A, true)
        .await
        .expect("resolve");
    assert!(
        outcome.records.is_empty(),
        "private A must be stripped by the rebinding defence"
    );
    assert_eq!(outcome.private_rdata_dropped, 1);
    assert!(!outcome.nxdomain);
}

#[tokio::test]
async fn odoh_config_is_cached_after_first_fetch() {
    // First resolve fetches + caches the target config; a second resolve reuses
    // it (the cache slot is populated). Both must answer.
    let arm = arm_with_mock(MockMode::AnswerA(Ipv4Addr::new(203, 0, 113, 9)));
    assert!(
        arm.transport.targets[0].config.load().is_none(),
        "cache starts empty"
    );
    arm.resolve("a.example.", RecordType::A, false)
        .await
        .expect("first resolve");
    assert!(
        arm.transport.targets[0].config.load().is_some(),
        "config must be cached after the first fetch"
    );
    arm.resolve("b.example.", RecordType::A, false)
        .await
        .expect("second resolve reuses cached config");
}

#[tokio::test]
async fn odoh_recovers_from_target_key_rotation() {
    // The target rotates its HPKE key on the first request and rejects the
    // stale-key query with a 4xx (RFC 9230). The arm must drop the cached
    // config, refetch the new one, and succeed on the retry.
    let arm = arm_with_mock(MockMode::RotateThenAnswer(Ipv4Addr::new(203, 0, 113, 22)));
    let outcome = arm
        .resolve("rotated.example.", RecordType::A, false)
        .await
        .expect("the arm must recover from a target key rotation");
    assert_eq!(outcome.records.len(), 1);
    match &outcome.records[0].data {
        RecordData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(203, 0, 113, 22)),
        other => panic!("expected an A record, got {other:?}"),
    }
}

#[tokio::test]
async fn odoh_bounded_retry_then_fails_closed() {
    // A target that ALWAYS rejects the stale-key way (HTTP 400) must not loop
    // forever: the arm refetches + retries exactly once, then fails closed.
    let arm = arm_with_mock(MockMode::AlwaysReject(400));
    let err = arm
        .resolve("rejected.example.", RecordType::A, false)
        .await
        .expect_err("a persistently-rejecting target must fail closed");
    assert_eq!(err.kind_label(), "relay_status");
}

#[tokio::test]
async fn odoh_relay_throttle_does_not_refetch_config() {
    // A relay-side 4xx that is NOT RFC 9230's stale-key signal (403/429 — auth
    // or throttling) must fail closed immediately WITHOUT a config refetch;
    // otherwise a throttling relay turns every query into a `/.well-known`
    // fetch against the target (self-amplifying fetch loop).
    let arm = arm_with_mock(MockMode::AlwaysReject(429));
    let err = arm
        .resolve("throttled.example.", RecordType::A, false)
        .await
        .expect_err("a 429-throttling relay must fail closed");
    assert_eq!(err.kind_label(), "relay_status");
    assert_eq!(
        mock_state_of(&arm).config_fetches,
        1,
        "exactly the initial config fetch — no retry refetch"
    );
}

#[tokio::test]
async fn odoh_validated_path_fails_closed_when_unvalidatable() {
    // Drive the *validated* resolve path (trust_anchor = Some) end to end. This
    // proves the whole plumbing: resolve_validated wraps the oblivious handle in
    // hickory's DnssecDnsHandle, the validator's chain lookups travel through our
    // handle (obliviously), the response comes back, and DnssecSummary is checked.
    //
    // The mock is not a real signed DNS hierarchy and the trust anchor is empty,
    // so the validator cannot establish a valid chain and the answer comes back
    // BOGUS — the arm MUST fail closed (never serve it, never fall back to a
    // less-private path). In production, a real chain to the real root anchor is
    // what distinguishes Secure / Insecure (served) from Bogus (rejected); that
    // distinction is hickory's validator's job and is confirmed at runtime.
    let arm = OdohArm {
        transport: mock_transport(
            MockMode::AnswerA(Ipv4Addr::new(203, 0, 113, 50)),
            false,
            vec!["https://proxy.test/".to_string()],
            false,
        ),
        trust_anchor: Some(Arc::new(TrustAnchors::empty())),
    };
    let err = arm
        .resolve("validate.example.", RecordType::A, false)
        .await
        .expect_err("an answer that fails DNSSEC validation must fail closed");
    assert!(
        matches!(err.kind_label(), "bogus" | "validation"),
        "expected a DNSSEC failure, got {}",
        err.kind_label()
    );
}

/// Build a throwaway DNSSEC-signed single zone (its own DNSKEY is the trust
/// anchor, so no parent chain is needed). Returns the per-qtype answer records
/// (A+RRSIG, DNSKEY+RRSIG) and the apex public key to seed the trust anchor.
fn build_signed_zone(apex: &str, ip: Ipv4Addr) -> (HashMap<RecordType, Vec<Record>>, PublicKeyBuf) {
    build_signed_zone_expiring_after(apex, ip, time::Duration::hours(1))
}

/// Like [`build_signed_zone`], but the signatures' inception is pushed back
/// by `inception_before_now`, so with the signer's fixed 30-day validity the
/// RRSIGs expire `inception_before_now - 30 days` from now (negative = still
/// valid, positive past 30 days = already expired).
fn build_signed_zone_expiring_after(
    apex: &str,
    ip: Ipv4Addr,
    inception_before_now: time::Duration,
) -> (HashMap<RecordType, Vec<Record>>, PublicKeyBuf) {
    let name = Name::from_ascii(apex).expect("apex name");
    // ECDSA P-256 KSK (zone-key + SEP via DNSKEY::from_key).
    let pkcs8 = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).expect("gen key");
    let key = EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256).expect("load key");
    let public_key = key.to_public_key().expect("public key");
    let dnskey = DNSKEY::from_key(&public_key);
    let signer = DnssecSigner::new(
        dnskey.clone(),
        Box::new(key),
        name.clone(),
        std::time::Duration::from_secs(30 * 24 * 3600),
    );
    // Inception an hour ago by default so the signature is valid "now".
    let inception = OffsetDateTime::now_utc() - inception_before_now;

    // A RRset + its RRSIG.
    let a_record = Record::from_rdata(name.clone(), 300, RData::A(A(ip)));
    let mut a_rrset = RecordSet::new(name.clone(), RecordType::A, 0);
    a_rrset.insert(a_record.clone(), 0);
    let a_rrsig = RRSIG::from_rrset(&a_rrset, DNSClass::IN, inception, &signer).expect("sign A");
    let a_rrsig_rec =
        Record::from_rdata(name.clone(), 300, RData::from(DNSSECRData::RRSIG(a_rrsig)));

    // DNSKEY RRset + its (self-)RRSIG.
    let dnskey_rec = Record::from_rdata(name.clone(), 300, RData::from(dnskey.clone()));
    let mut dnskey_rrset = RecordSet::new(name.clone(), RecordType::DNSKEY, 0);
    dnskey_rrset.insert(dnskey_rec.clone(), 0);
    let dnskey_rrsig =
        RRSIG::from_rrset(&dnskey_rrset, DNSClass::IN, inception, &signer).expect("sign DNSKEY");
    let dnskey_rrsig_rec = Record::from_rdata(
        name.clone(),
        300,
        RData::from(DNSSECRData::RRSIG(dnskey_rrsig)),
    );

    let mut responses = HashMap::new();
    responses.insert(RecordType::A, vec![a_record, a_rrsig_rec]);
    responses.insert(RecordType::DNSKEY, vec![dnskey_rec, dnskey_rrsig_rec]);
    (responses, public_key)
}

/// A validating ODoH arm whose trust anchor is the signed zone's apex key.
fn arm_with_signed_zone(
    responses: HashMap<RecordType, Vec<Record>>,
    public_key: &PublicKeyBuf,
) -> OdohArm {
    let mut anchor = TrustAnchors::empty();
    anchor.insert(public_key);
    let target = OdohTarget::parse("https://target.test/dns-query").expect("parse target");
    OdohArm {
        transport: Arc::new(OdohTransport {
            targets: vec![target],
            proxy_urls: vec!["https://proxy.test/".to_string()],
            http: OdohHttp::Mock(Arc::new(MockRelay::signed(responses))),
            randomize: false,
            pad_queries: false,
        }),
        trust_anchor: Some(Arc::new(anchor)),
    }
}

#[tokio::test]
async fn odoh_oblivious_query_carries_no_edns_client_subnet() {
    // The ECS-strip invariant re-applied to the oblivious arm: the plaintext
    // DNS message the TARGET decrypts must never carry an EDNS Client Subnet
    // option (RFC 7871) — on ODoH the target must not learn even a coarse
    // client network, that is the entire point of the transport. The mock
    // runs the real odoh-rs server side, so this inspects the exact bytes
    // the target would see after HPKE decryption.
    let arm = arm_with_mock_opts(MockMode::AnswerA(Ipv4Addr::new(203, 0, 113, 20)), false);
    arm.resolve("ecs.example.", RecordType::A, false)
        .await
        .expect("resolve over the oblivious arm");

    let captured = captured_queries_of(&arm);
    assert_eq!(captured.len(), 1, "the target saw exactly one query");
    if let Some(edns) = &captured[0].edns {
        // EDNS0 itself may be present; what must NEVER be present is the
        // Client Subnet option (code 8).
        assert!(
            edns.option(EdnsCode::Subnet).is_none(),
            "oblivious wire carried an EDNS Client Subnet option: {edns:?}"
        );
    }
    // No EDNS at all is equally fine — both shapes satisfy "no ECS".
}

#[tokio::test]
async fn odoh_query_ids_vary_per_query() {
    // Transaction-ID randomisation at the seam we own: the inner DNS message
    // id built by build_query_wire comes from rand::random(), so consecutive
    // oblivious queries must not share (or trivially cycle) ids — a
    // predictable id space would let an off-path attacker guess the id and
    // race a spoofed response. The plain/DoH/DoQ arms delegate wire-id
    // generation to hickory's exchange; this pins OUR construction.
    let arm = arm_with_mock_opts(MockMode::AnswerA(Ipv4Addr::new(203, 0, 113, 21)), false);
    for i in 0..10 {
        arm.resolve(&format!("txid-{i}.example."), RecordType::A, false)
            .await
            .expect("each query must resolve over the oblivious arm");
    }
    let captured = captured_queries_of(&arm);
    assert_eq!(captured.len(), 10, "the target saw every query");
    let distinct: std::collections::HashSet<u16> = captured.iter().map(|m| m.metadata.id).collect();
    assert!(
        distinct.len() > 1,
        "query ids were degenerate across {0} queries: {distinct:?}",
        captured.len()
    );
    // With 16-bit ids drawn randomly, all-equal or fully-sequential ids
    // across ten draws are astronomically unlikely unless generation is
    // deterministic; what we pin here is non-degeneracy, not cryptographic
    // proof of entropy.
}

#[tokio::test]
async fn odoh_separates_client_identity_from_the_target() {
    // RFC 9230's core property, pinned at the two observable layers:
    //
    // 1. RELAY-BLINDNESS — the HTTP body crossing the oblivious hop is the
    //    HPKE ciphertext (config id + encrypted plaintext), so the relay (and
    //    any passive observer on that leg) sees no plaintext query name.
    // 2. NO CLIENT-DERIVED DATA AT THE TARGET — the decrypted query the target
    //    receives carries only the DNS message; nothing in it identifies the
    //    client. IP separation is structural: the client's TCP connection
    //    terminates at the RELAY (`post_oblivious` posts exclusively to a
    //    `proxy_urls` entry with ?targethost=&targetpath=), and the RFC 9230
    //    response format carries no client-derived identifier back through
    //    the relay.
    let arm = arm_with_mock_opts(MockMode::AnswerA(Ipv4Addr::new(203, 0, 113, 30)), false);
    arm.resolve("identity-check.example.", RecordType::A, false)
        .await
        .expect("resolve over the oblivious arm");

    let st = mock_state_of(&arm);
    assert_eq!(st.captured.len(), 1, "the target saw exactly one query");
    assert_eq!(
        st.captured[0].queries[0].name().to_string(),
        "identity-check.example.",
        "the correct query reached the target"
    );

    assert_eq!(
        st.captured_raw.len(),
        1,
        "the oblivious hop saw exactly one request body"
    );
    let raw = &st.captured_raw[0];
    let needle = b"identity-check";
    assert!(
        !raw.windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle)),
        "the hop-bound body leaked the plaintext query name: {}",
        String::from_utf8_lossy(raw)
    );
}

#[tokio::test]
async fn odoh_validated_path_accepts_a_signed_answer() {
    // The capstone: a correctly DNSSEC-signed answer, validated by hickory's
    // validator running over our oblivious handle (the DNSKEY lookup also flows
    // through it), against a trust anchor we control — must validate Secure and
    // be served. This proves the Secure path end to end, offline.
    let (responses, pubkey) = build_signed_zone("secure.example.", Ipv4Addr::new(192, 0, 2, 53));
    let arm = arm_with_signed_zone(responses, &pubkey);
    let outcome = arm
        .resolve("secure.example.", RecordType::A, false)
        .await
        .expect("a correctly-signed answer must validate Secure and be served");
    assert_eq!(outcome.records.len(), 1);
    match &outcome.records[0].data {
        RecordData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(192, 0, 2, 53)),
        other => panic!("expected an A record, got {other:?}"),
    }
}

#[tokio::test]
async fn odoh_validated_answer_classifies_as_secure() {
    // The accepts test pins that a complete chain is served; this pins the
    // CLASSIFICATION itself: driving the same DnssecDnsHandle-over-OdohHandle
    // stack directly, the validated answer set must classify as Secure via
    // the same classifier production uses (DnssecSummary::from_records) —
    // i.e. the served answer is authenticated data, not merely "no error".
    let (responses, pubkey) = build_signed_zone("secure.example.", Ipv4Addr::new(192, 0, 2, 53));
    let mut anchor = TrustAnchors::empty();
    anchor.insert(&pubkey);
    let target = OdohTarget::parse("https://target.test/dns-query").expect("parse target");
    let handle = OdohHandle {
        transport: Arc::new(OdohTransport {
            targets: vec![target],
            proxy_urls: vec!["https://proxy.test/".to_string()],
            http: OdohHttp::Mock(Arc::new(MockRelay::signed(responses))),
            randomize: false,
            pad_queries: false,
        }),
    };
    let validating = DnssecDnsHandle::with_trust_anchor(handle, Arc::new(anchor));
    let query = Query::query(Name::from_ascii("secure.example.").unwrap(), RecordType::A);
    let response = validating
        .lookup(query, DnsRequestOptions::default())
        .first_answer()
        .await
        .expect("a complete DS->DNSKEY->RRSIG chain must validate");

    use hickory_proto::dnssec::DnssecSummary;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(
        matches!(
            DnssecSummary::from_records(response.answers.iter()),
            DnssecSummary::Secure
        ),
        "the validated answer must classify as Secure"
    );
    assert!(
        response
            .answers
            .iter()
            .any(|r| matches!(r.data, RData::DNSSEC(DNSSECRData::RRSIG(_)))),
        "the RRSIG chain material must travel with the answer"
    );
}

#[tokio::test]
async fn odoh_validated_path_rejects_a_forged_answer() {
    // Same signed zone, but the A record's address is swapped while keeping the
    // original (now-mismatched) RRSIG — a forgery. The validator must mark it
    // BOGUS and the arm must fail closed (never serve forged data).
    let (mut responses, pubkey) =
        build_signed_zone("secure.example.", Ipv4Addr::new(192, 0, 2, 53));
    let name = Name::from_ascii("secure.example.").unwrap();
    let orig_rrsig = responses[&RecordType::A][1].clone();
    responses.insert(
        RecordType::A,
        vec![
            Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::new(203, 0, 113, 99)))),
            orig_rrsig,
        ],
    );
    let arm = arm_with_signed_zone(responses, &pubkey);
    let err = arm
        .resolve("secure.example.", RecordType::A, false)
        .await
        .expect_err("a forged (signature-mismatched) answer must fail closed");
    assert!(
        matches!(err.kind_label(), "bogus" | "validation"),
        "expected a DNSSEC failure, got {}",
        err.kind_label()
    );
}

#[tokio::test]
async fn odoh_validated_path_rejects_an_untrusted_but_valid_signer() {
    // Distinct failure class from the forged-answer case: here NOTHING is
    // tampered — the answer is pristine and correctly self-signed by its own
    // apex key. But the operator's trust anchor names a DIFFERENT key, so the
    // chain of trust does not terminate at an anchor. The validator must mark
    // it BOGUS anyway (a valid signature is not enough; it must chain to
    // TRUST), and the arm must fail closed rather than serve well-signed data
    // from outside the trust boundary.
    let (responses, _real_pubkey_unused) =
        build_signed_zone("secure.example.", Ipv4Addr::new(192, 0, 2, 53));
    // A second, independently generated key becomes the sole anchor.
    let (_decoy_zone, decoy_pubkey) =
        build_signed_zone("decoy.example.", Ipv4Addr::new(192, 0, 2, 154));
    let arm = arm_with_signed_zone(responses, &decoy_pubkey);
    let err = arm
        .resolve("secure.example.", RecordType::A, false)
        .await
        .expect_err("an answer whose chain misses the trust anchor must fail closed");
    assert!(
        matches!(err.kind_label(), "bogus" | "validation"),
        "expected a DNSSEC failure, got {}",
        err.kind_label()
    );
}

#[tokio::test]
async fn odoh_missing_rrsig_breaks_the_chain_and_fails_closed() {
    // A third broken-chain class beside forgery and expiry: the RRSIG is
    // MISSING entirely. The answer records themselves are pristine (built by
    // the trusted signer), but the A RRset arrives with its signature link
    // absent — the validator has nothing to verify, and an unsigned answer in
    // a zone we expect to be signed must not be served as Secure.
    let (mut responses, pubkey) =
        build_signed_zone("secure.example.", Ipv4Addr::new(192, 0, 2, 53));
    if let Some(a_set) = responses.get_mut(&RecordType::A) {
        a_set.retain(|r| !matches!(r.data, RData::DNSSEC(DNSSECRData::RRSIG(_))));
    }
    assert!(
        responses[&RecordType::A]
            .iter()
            .all(|r| !matches!(r.data, RData::DNSSEC(DNSSECRData::RRSIG(_)))),
        "fixture should have stripped the A RRSIG"
    );
    let arm = arm_with_signed_zone(responses, &pubkey);
    let err = arm
        .resolve("secure.example.", RecordType::A, false)
        .await
        .expect_err("an unsigned answer in a signed zone must fail closed");
    assert!(
        matches!(err.kind_label(), "bogus" | "validation"),
        "expected a DNSSEC failure, got {}",
        err.kind_label()
    );
}

#[tokio::test]
async fn odoh_dns_handle_round_trips_a_query() {
    // The OdohHandle is what hickory's DNSSEC validator drives: a Query in,
    // encoded + sent obliviously, the decrypted DnsResponse back out. This is
    // the wiring the validated path depends on (the DNSSEC crypto on top is
    // hickory's). Exercise it directly via the DnsHandle trait.
    let transport = mock_transport(
        MockMode::AnswerA(Ipv4Addr::new(203, 0, 113, 40)),
        false,
        vec!["https://proxy.test/".to_string()],
        false,
    );
    let handle = OdohHandle { transport };
    let query = Query::query(Name::from_ascii("handle.example.").unwrap(), RecordType::A);
    let response = handle
        .lookup(query, DnsRequestOptions::default())
        .first_answer()
        .await
        .expect("the DnsHandle must round-trip a query obliviously");
    assert_eq!(response.answers.len(), 1, "expected one A record");
    match &response.answers[0].data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(203, 0, 113, 40)),
        other => panic!("expected an A record, got {other:?}"),
    }
}

#[tokio::test]
async fn odoh_round_trips_across_multiple_proxies() {
    // With several relays + randomized selection, queries still succeed — the
    // arm picks a relay per query and the round-trip works regardless of which.
    let arm = OdohArm {
        transport: mock_transport(
            MockMode::AnswerA(Ipv4Addr::new(203, 0, 113, 30)),
            false,
            vec![
                "https://relay-a.test/proxy".to_string(),
                "https://relay-b.test/proxy".to_string(),
                "https://relay-c.test/proxy".to_string(),
            ],
            true,
        ),
        trust_anchor: None,
    };
    for _ in 0..5 {
        let outcome = arm
            .resolve("multi.example.", RecordType::A, false)
            .await
            .expect("resolve across rotating relays");
        assert_eq!(outcome.records.len(), 1);
    }
}

/// Real-HTTP coverage for [`super::OdohHttp::read_capped`]. The mock transport
/// above bypasses the reqwest arm entirely, so the body-cap defence (the
/// "no unbounded memory" invariant on the relay-facing path) would otherwise
/// ship untested. Each test serves one handcrafted HTTP/1.1 response from a
/// loopback listener so `reqwest` produces a genuine `Response`.
mod http_cap {
    use tokio::io::AsyncWriteExt;

    /// Serve ONE response (raw HTTP/1.1 bytes) on a fresh loopback listener;
    /// returns the GET URL for a plain-HTTP reqwest client. The connection is
    /// held open after writing so the reader decides when to stop.
    async fn serve_once(response: &[u8]) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let response = response.to_vec();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Drain the request head (GET + headers) before answering.
            let mut buf = [0u8; 2048];
            loop {
                let n = tokio::io::AsyncReadExt::read(&mut sock, &mut buf)
                    .await
                    .unwrap();
                if n == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            sock.write_all(&response).await.unwrap();
            sock.flush().await.unwrap();
            // Hold the socket open; the test drops it when done.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        format!("http://{addr}/cap")
    }

    async fn get(url: &str) -> reqwest::Response {
        reqwest::get(url).await.expect("plain-HTTP GET succeeds")
    }

    #[tokio::test]
    async fn content_length_over_cap_rejected_before_body() {
        let url =
            serve_once(b"HTTP/1.1 200 OK\r\ncontent-length: 1048576\r\n\r\nshort-but-lying").await;
        let err = super::OdohHttp::read_capped(get(&url).await, 64 * 1024, "ODoH config")
            .await
            .expect_err("a lying content-length over the cap must be rejected");
        assert!(
            err.to_string().contains("content-length"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn chunked_body_over_cap_aborts_mid_stream() {
        // No content-length: reqwest must fall back to streaming chunks, and
        // read_capped must abort once the running total crosses the cap — not
        // buffer until the server finishes. The server never sends a
        // terminating chunk, so success here proves the abort is proactive.
        let mut raw = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nffff\r\n".to_vec();
        raw.extend_from_slice(&[0xffu8; 0xffff]);
        raw.extend_from_slice(b"\r\n"); // no terminating `0` chunk
        let url = serve_once(&raw).await;
        let err = super::OdohHttp::read_capped(get(&url).await, 32 * 1024, "oblivious")
            .await
            .expect_err("an over-cap chunked body must be rejected");
        assert!(
            err.to_string().contains("exceeds"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn body_under_cap_is_returned_intact() {
        const BODY: &[u8] = b"definitely-a-config-document";
        let mut raw =
            format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", BODY.len()).into_bytes();
        raw.extend_from_slice(BODY);
        let url = serve_once(&raw).await;
        let body = super::OdohHttp::read_capped(get(&url).await, 64 * 1024, "ODoH config")
            .await
            .expect("an under-cap body passes through untouched");
        assert_eq!(body, BODY);
    }
}

/// Real-TLS coverage for [`super::build_http_client`] — the reqwest client the
/// production arm uses (the mock transport above never touches it). Mirrors
/// lib.rs's `min_tls_version_floor_rejects_tls12_only_upstream` differential,
/// but at the reqwest layer: ONE TLS-1.2-only rustls listener, and only the
/// client's `min_tls_version` changes between halves. The same self-signed EC
/// P-256 `localhost` leaf is reused as served cert + injected trust root.
mod http_tls {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_rustls::TlsAcceptor;

    const FLOOR_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBpjCCAU2gAwIBAgIUH4msZODlyUITY4qNh4Zy3iQ6GmgwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDUzMTIyNTg1MVoYDzIxMjYwNTA3
MjI1ODUxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQi321SoibBr5yqX+f8XO1mPhaahr1568soaw6eFothmwpv2BKVytPt
M++E6xpBmIdD4mhTu3uvhg3wqibpkvYso3sweTAdBgNVHQ4EFgQUQMU/jc/PJ3gt
R+iCyuMVlkuMPUQwHwYDVR0jBBgwFoAUQMU/jc/PJ3gtR+iCyuMVlkuMPUQwFAYD
VR0RBA0wC4IJbG9jYWxob3N0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwCgYIKoZIzj0EAwIDRwAwRAIgGguAP9CRizUikjwkfgo8pEdRu/ZvI6cG
threFGzaaJECIHXHcR7aMNF5wT6anz3/VndM0s1gnQtyWBITOHKZ0LYN
-----END CERTIFICATE-----
";
    const FLOOR_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3eneNckGaJqvOLfi
3WH4EkMxC0+QnthrXihUDPWzdBWhRANCAAQi321SoibBr5yqX+f8XO1mPhaahr15
68soaw6eFothmwpv2BKVytPtM++E6xpBmIdD4mhTu3uvhg3wqibpkvYs
-----END PRIVATE KEY-----
";

    /// A TLS-**1.2-only** loopback server that answers a completed handshake
    /// with a minimal HTTP/1.1 200 — enough for reqwest to treat it as a valid
    /// origin when the client's floor admits TLS 1.2.
    async fn spawn_tls12_server() -> u16 {
        use rustls_pki_types::pem::PemObject;
        use rustls_pki_types::{CertificateDer, PrivateKeyDer};
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
        let cert_der =
            CertificateDer::from_pem_slice(FLOOR_CERT_PEM.as_bytes()).expect("cert parses");
        let key_der = PrivateKeyDer::from_pem_slice(FLOOR_KEY_PEM.as_bytes()).expect("key parses");
        let server_cfg =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .expect("server cert/key load");
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(stream).await {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        // Drain the request head before answering so hyper
                        // sees a well-formed request/response exchange.
                        let mut buf = [0u8; 2048];
                        loop {
                            match tls.read(&mut buf).await {
                                Ok(n) if n > 0 => {
                                    if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                                        break;
                                    }
                                }
                                _ => break,
                            }
                        }
                        let _ = tls
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                            .await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });
        port
    }

    fn odoh_http_client(
        min_tls: TlsVersion,
        roots: &[rustls_pki_types::CertificateDer<'static>],
    ) -> reqwest::Client {
        build_http_client(min_tls, Duration::from_secs(5), roots).expect("odoh http client builds")
    }

    #[tokio::test]
    async fn tls13_floor_refuses_a_tls12_only_origin_over_reqwest() {
        use rustls_pki_types::CertificateDer;
        use rustls_pki_types::pem::PemObject;
        let cert_der =
            CertificateDer::from_pem_slice(FLOOR_CERT_PEM.as_bytes()).expect("cert parses");
        let port = spawn_tls12_server().await;

        // Tls13 floor → the handshake against the 1.2-only origin MUST fail.
        let err = odoh_http_client(TlsVersion::Tls13, std::slice::from_ref(&cert_der))
            .get(format!("https://localhost:{port}/proxy"))
            .send()
            .await
            .expect_err("a TLS-1.3-floor client must refuse a TLS-1.2-only origin");

        // Tls12 floor → the SAME origin completes; only the floor changed.
        let resp = odoh_http_client(TlsVersion::Tls12, std::slice::from_ref(&cert_der))
            .get(format!("https://localhost:{port}/proxy"))
            .send()
            .await
            .expect("a TLS-1.2-floor client reaches the 1.2-only origin");
        assert_eq!(resp.status(), 200);
        assert!(
            !err.to_string().to_lowercase().contains("dns error"),
            "failure must be the TLS handshake, not name resolution: {err}"
        );
    }

    #[tokio::test]
    async fn https_only_client_refuses_plain_http_url() {
        let client = odoh_http_client(TlsVersion::Tls13, &[]);
        let err = client
            .get("http://127.0.0.1:9/cap")
            .send()
            .await
            .expect_err("https_only must reject plain-HTTP URLs before any I/O");
        let msg = err.to_string().to_lowercase();
        // reqwest enforces `https_only` while building the request, so the
        // rejection surfaces as a builder error — NOT a connect error (the
        // port is closed, so a client without the flag would report
        // "connection refused" instead).
        assert!(
            msg.contains("builder error") || msg.contains("scheme") || msg.contains("https"),
            "unexpected rejection reason: {err}"
        );
    }
}
