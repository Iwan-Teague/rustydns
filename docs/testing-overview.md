# Test Suite Overview

How rustydns is tested, what each layer covers, and how to read failures.

## Layers

| Layer | Location | Runs against | Speed |
|---|---|---|---|
| Unit | `src/**` `#[cfg(test)]` | library internals | ms |
| Library integration | `tests/upstream_e2e.rs` | resolver + mock upstreams | ~10s |
| Binary e2e | `crates/rustydnsd/tests/e2e_binary.rs` | spawned release-mode daemon over real sockets | ~10s |
| User journey | `crates/rustydnsd/tests/user_journey.rs` | shipped configs + spawned binary | ~5s |
| CLI contract | `crates/rustydnsd/tests/cli_contract.rs`, `startup_warnings.rs`, `print_config.rs` | binary flags & output | <1s |

## Binary e2e inventory (`e2e_binary.rs`)

Each test spawns the real binary on ephemeral ports with an offline stub
upstream unless noted. Teardown kills the child and aborts stub tasks.

| Test | Pins |
|---|---|
| `binary_end_to_end_resolves_a_query_over_real_udp` | baseline UDP resolution |
| `binary_e2e_blocklist_blocks_domain_before_upstream` | NXDOMAIN enforcement; blocked names never forwarded |
| `binary_e2e_malformed_packets_never_crash_or_poison` | garbage/truncated/bomb datagrams: no answers, no crash |
| `binary_e2e_sighup_picks_up_blocklist_change_live` | SIGHUP activates new block rules without restart |
| `binary_e2e_operator_endpoints_health_metrics_queries` | /health readiness, counter deltas (+3 exact), /queries privacy (hashes only), refused ANY counted |
| `binary_e2e_resolves_over_tcp_with_length_framing` | RFC 1035 TCP framing end-to-end |
| `binary_e2e_dot_tls_handshake_and_resolution` | DoT handshake (CA trust, SAN) + framed resolution |
| `binary_e2e_doq_quic_stream_resolution_with_ca_trust` | DoQ QUIC handshake + RFC 9250 stream framing + connection reuse |
| `binary_e2e_doh_post_resolves_over_http_seam` | RFC 8484 POST contract |
| `binary_e2e_doh_get_resolves_via_base64url_param` | RFC 8484 GET contract |
| `binary_e2e_doh_wrong_content_type_is_415` | media-type gate + Accept advertisement |
| `binary_e2e_edns_version_mismatch_answers_badvers` | BADVERS encoding asserted at wire-field level |
| `binary_e2e_out_of_bailiwick_answer_is_dropped_not_served` | CNAME-riding out-of-zone answer dropped fail-closed |
| `binary_e2e_spoofed_case_responses_fail_closed` | 0x20-mismatched replies rejected (SERVFAIL, never served) |
| `binary_e2e_upstream_privacy_no_ecs_no_identity_exact_qname` | no ECS/Cookie upstream, exact QNAME, 0x20 randomization, daemon-originated source |

## User journeys (`user_journey.rs`)

Operator-facing flows using the SHIPPED config templates:

1. `quickstart_example_config_verbatim_validates_and_resolves` — the example
   passes `--validate-config` byte-for-byte, then resolves after only three
   documented CI substitutions (privileged port, external network, remote fetch).
2. `ad_block_out_of_the_box_doubleclick_blocked_google_resolves` — one Pi-hole
   file blocks doubleclick.net while google.com resolves; upstream counter proves
   selectivity; ring attribution distinguishes blocklist vs resolver entries.
3. `config_error_ux_names_the_offender_and_exits_nonzero` / 
   `invalid_existing_config_error_names_file_and_hints` — typoed keys and bad
   addresses produce named-key, line-attributed, actionable errors (never bare dumps).
4. `missing_config_error_is_actionable` / `world_readable_config_is_rejected_with_actionable_error` —
   missing files name the default path + `--config`; world-readable files exit 1
   naming the risk and the chmod fix.
5. `blocklist_partial_failure_retains_last_good_entries` — deleting one local
   source keeps its domains blocked (last-good retention); nothing leaks upstream.
6. `docker_config_journey_resolves_over_doh` — the CONTAINER template works at
   runtime: wildcard binds substituted to ephemeral, DoH POST resolves, posture
   anchors (fail-closed/TLS floor/block_response/metrics-loopback) drift-guarded.

## Verification methodology

Every security fix lands with a discriminating test verified by
mutation: the production guard is temporarily reverted, the test must
FAIL, then production is restored and the battery must go green.
Cycle numbers (#1–#122) referenced in commit messages record this
protocol. Non-discriminating results (e.g. #106 strategy-swap,
#49 skip-list redundancy) are documented as attribution findings — they
identify which layer actually carries each property.

## Known flakes

None currently. If an e2e times out under parallel suite load, rerun in
isolation before investigating; all network waits carry explicit bounds
so hangs cannot occur.
