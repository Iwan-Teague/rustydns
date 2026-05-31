//! End-to-end ODoH tests against an in-process mock target.
//!
//! The mock runs the **real** `odoh-rs` server side (HPKE keypair, `decrypt_query`
//! / `encrypt_response`), so the client's `encrypt_query` / `decrypt_response`
//! and the whole oblivious round-trip are exercised against genuine crypto —
//! entirely offline, no TLS server. What is *not* covered here (reqwest's HTTPS
//! transport and TLS-floor enforcement) is third-party code configured in
//! [`super::build_http_client`]; the rustydns-owned protocol logic is.

use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use odoh_rs::{
    ObliviousDoHConfig, ObliviousDoHConfigs, ObliviousDoHKeyPair, ObliviousDoHMessage,
    ObliviousDoHMessagePlaintext, ResponseNonce, compose, decrypt_query, encrypt_response, parse,
};

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
    /// Rotate the HPKE key on the FIRST request and reject the (now stale-key)
    /// query with a 4xx, like a real target at key rotation; answer with this A
    /// on the retry after the client refetches the config.
    RotateThenAnswer(Ipv4Addr),
    /// Always reject with a 4xx — the arm must refetch + retry once, then fail
    /// closed (the retry is bounded, not an infinite loop).
    AlwaysReject,
}

/// Mutable target state, so a test can rotate the key mid-exchange.
struct MockState {
    keypair: ObliviousDoHKeyPair,
    configs: Vec<u8>,
    rotated: bool,
}

/// In-process ODoH target + relay. Holds a real HPKE keypair and answers with
/// genuine `odoh-rs` server-side encryption.
pub(crate) struct MockRelay {
    state: std::sync::Mutex<MockState>,
    mode: MockMode,
}

/// Fresh HPKE keypair plus its serialised `ObliviousDoHConfigs` bytes.
fn fresh_keypair() -> (ObliviousDoHKeyPair, Vec<u8>) {
    let mut rng = rand::rng();
    let keypair = ObliviousDoHKeyPair::new(&mut rng);
    let config: ObliviousDoHConfig = keypair.public().clone().into();
    let configs = compose(&ObliviousDoHConfigs::from(vec![config]))
        .expect("compose ObliviousDoHConfigs")
        .to_vec();
    (keypair, configs)
}

impl MockRelay {
    fn new(mode: MockMode) -> Self {
        let (keypair, configs) = fresh_keypair();
        MockRelay {
            state: std::sync::Mutex::new(MockState {
                keypair,
                configs,
                rotated: false,
            }),
            mode,
        }
    }

    /// Serve the target's currently-published `ObliviousDoHConfigs`.
    pub(super) fn fetch_configs(&self) -> Result<Vec<u8>, OdohError> {
        Ok(self.state.lock().unwrap().configs.clone())
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
            MockMode::AlwaysReject => return Err(OdohError::RelayStatus(401)),
            MockMode::RotateThenAnswer(_) => {
                let mut st = self.state.lock().unwrap();
                if !st.rotated {
                    // First request: rotate the key, publish the new config, and
                    // reject the stale-key query the way a real target would.
                    let (keypair, configs) = fresh_keypair();
                    st.keypair = keypair;
                    st.configs = configs;
                    st.rotated = true;
                    return Err(OdohError::RelayStatus(401));
                }
            }
            _ => {}
        }

        let st = self.state.lock().unwrap();
        let mut b = Bytes::copy_from_slice(body);
        let qmsg: ObliviousDoHMessage =
            parse(&mut b).map_err(|e| OdohError::Mock(e.to_string()))?;
        let (q_plain, secret) =
            decrypt_query(&qmsg, &st.keypair).map_err(|e| OdohError::Mock(e.to_string()))?;

        let query_msg = Message::from_bytes(&q_plain.clone().into_msg())
            .map_err(|e| OdohError::Mock(e.to_string()))?;
        let resp_wire = build_mock_response(self.mode, &query_msg)?;

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
        MockMode::RelayError | MockMode::Garbage | MockMode::AlwaysReject => {
            unreachable!("handled before crypto")
        }
    }
    resp.to_bytes().map_err(|e| OdohError::Mock(e.to_string()))
}

/// Build an `OdohArm` wired to a mock target (no reqwest, no TLS).
fn arm_with_mock(mode: MockMode) -> OdohArm {
    arm_with_mock_opts(mode, false)
}

fn arm_with_mock_opts(mode: MockMode, pad_queries: bool) -> OdohArm {
    let target = OdohTarget::parse("https://target.test/dns-query").expect("parse target");
    OdohArm {
        targets: vec![target],
        proxy_url: "https://proxy.test/".to_string(),
        http: OdohHttp::Mock(Arc::new(MockRelay::new(mode))),
        randomize: false,
        pad_queries,
    }
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
    assert!(arm.targets[0].config.load().is_none(), "cache starts empty");
    arm.resolve("a.example.", RecordType::A, false)
        .await
        .expect("first resolve");
    assert!(
        arm.targets[0].config.load().is_some(),
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
    // A target that ALWAYS rejects with a 4xx must not loop forever: the arm
    // refetches + retries exactly once, then fails closed.
    let arm = arm_with_mock(MockMode::AlwaysReject);
    let err = arm
        .resolve("rejected.example.", RecordType::A, false)
        .await
        .expect_err("a persistently-rejecting target must fail closed");
    assert_eq!(err.kind_label(), "relay_status");
}
