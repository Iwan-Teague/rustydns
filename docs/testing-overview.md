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
| `binary_e2e_absurd_upstream_ttl_is_clamped` | absurd upstream TTL clamped to ceiling |
| `binary_e2e_any_qtype_refused_rfc8482` | RFC 8482 ANY-refusal with upstream isolation |
| `binary_e2e_authority_cname_chain_resolution` | CNAME chain chased to terminal A record |
| `binary_e2e_authority_precedes_blocklist_for_same_name` | authority wins over blocklist for same name |
| `binary_e2e_authority_serves_over_doh_transport` | mesh-zone record served over DoH transport |
| `binary_e2e_authority_serves_txt_records` | TXT/SPF records served from authority |
| `binary_e2e_authority_static_record_served_with_aa_flag` | static A record with AA flag |
| `binary_e2e_blocklist_blocks_domain_before_upstream` | NXDOMAIN enforcement; blocked names never forwarded |
| `binary_e2e_cache_entry_expires_and_reforwards` | cache expiry triggers re-forward after TTL floor |
| `binary_e2e_concurrent_multi_client_resolution` | four independent sockets query different names concurrently |
| `binary_e2e_conditional_forwarding_routes_by_zone` | zone-matched queries hit routed upstream only |
| `binary_e2e_default_logging_never_leaks_client_or_query_name` | privacy capstone: no qname/IP in logs at info level |
| `binary_e2e_doh_get_resolves_via_base64url_param` | RFC 8484 GET contract via base64url parameter |
| `binary_e2e_doh_post_resolves_over_http_seam` | RFC 8484 POST contract over HTTP seam |
| `binary_e2e_doh_wrong_content_type_is_415` | media-type gate returns 415 + Accept header |
| `binary_e2e_doq_quic_stream_resolution_with_ca_trust` | DoQ QUIC handshake + RFC 9250 stream framing + reuse |
| `binary_e2e_dot_rejects_wrong_san_dial` | TLS handshake fails on wrong SAN (cert validation enforced) |
| `binary_e2e_dot_tls_handshake_and_resolution` | DoT handshake (CA trust, SAN) + framed resolution + session reuse |
| `binary_e2e_edns_version_mismatch_answers_badvers` | BADVERS encoding asserted at wire-field level |
| `binary_e2e_in_zone_nodata_is_noerror_not_nxdomain` | NODATA vs NXDOMAIN vs upstream fall-through |
| `binary_e2e_longest_prefix_route_wins_regardless_of_declaration_order` | longest-prefix route matching wins over declaration order |
| `binary_e2e_malformed_packets_never_crash_or_poison` | garbage/truncated/bomb datagrams: no answers, no crash |
| `binary_e2e_max_label_length_resolves` | 63-byte single label survives wire round-trip |
| `binary_e2e_maximum_length_domain_name_resolves` | ~250-byte QNAME survives wire round-trip |
| `binary_e2e_multi_upstream_queries_distribute_across_providers` | serial dispatch distributes queries across providers |
| `binary_e2e_multiple_static_records_and_nodata` | multiple authority records served; ghost names get NODATA |
| `binary_e2e_negative_responses_are_cached_then_expire` | negative caching: NXDOMAIN cached then expired |
| `binary_e2e_operator_endpoints_health_metrics_queries` | /health readiness, counter deltas, /queries privacy, ANY counted |
| `binary_e2e_out_of_bailiwick_answer_is_dropped_not_served` | CNAME-riding out-of-zone answer dropped fail-closed |
| `binary_e2e_regex_blocklist_blocks_matching_domains` | regex substring rules REFUSE matching domains |
| `binary_e2e_repeat_query_served_from_cache_without_upstream` | identical repeat served from cache without upstream traffic |
| `binary_e2e_resolves_over_tcp_with_length_framing` | RFC 1035 TCP framing end-to-end |
| `binary_e2e_safesearch_rewrites_google_over_udp` | SafeSearch CNAME rewrite; non-search domains untouched |
| `binary_e2e_serial_dispatch_still_fails_over_to_live_provider` | dead-first-provider failover under serial dispatch |
| `binary_e2e_sighup_picks_up_blocklist_change_live` | SIGHUP activates new block rules without restart |
| `binary_e2e_sighup_picks_up_policy_changes_live` | SIGHUP activates zones_allowed policy changes bidirectionally |
| `binary_e2e_sinkhole_mode_serves_operator_ip_for_blocked_domains` | sinkhole IP served instead of NXDOMAIN/stub answer |
| `binary_e2e_spoofed_case_responses_fail_closed` | 0x20-mismatched replies rejected (SERVFAIL, never served) |
| `binary_e2e_zero_question_count_gets_formerr` | QDCOUNT=0 must not hang or crash daemon |
| `binary_e2e_zone_apex_infrastructure_queries` | SOA/NS/A apex queries return authoritative NODATA |


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
