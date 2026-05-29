# Design: On-Disk Query Log (Roadmap 3.1) — IMPLEMENTED

## Context
Provide an opt-in, durable query log without violating strict privacy invariants.

## Decisions (as built)

1. **Format**: Line-delimited JSON (NDJSON), one object per query. The line is
   produced by `QueryLogEntry::to_json`, the *same* formatter the `/queries`
   endpoint uses, so the two can never drift.
2. **Permissions**: File created mode `0o600` (explicit `OpenOptions::mode`,
   plus the process umask `0o077` as a second line of defence). If an existing
   target has any group/other bit set (`mode & 0o077 != 0`), the writer
   **refuses to use it, logs an error, and disk logging stays disabled** — the
   daemon keeps serving DNS. (Earlier draft said "process aborts"; refusing
   while continuing to serve is the safer choice — a loose log-file mode must
   not take DNS down.)
3. **Anonymization (Mandatory, not configurable)**:
   - `qname` is ALWAYS salted-hashed. The raw QNAME never reaches the writer —
     `QueryLogEntry` carries only the `u64` hash, so there is no code path that
     could write plaintext.
   - Client IPs are ALWAYS anonymized (/16 IPv4, /64 IPv6). `log_client_ips`
     does **not** apply to the on-disk log.
4. **Rotation & Bounds**:
   - Size-based rotation (target low-power devices like Pi Zero).
   - `query_log_max_file_bytes` (default 10 MiB, range 4096 .. 1 GiB) and
     `query_log_max_files` (default 5, min 1). Oldest deleted automatically.
   - Total footprint ≈ `max_file_bytes × max_files`.
5. **I/O Strategy**:
   - Dedicated Tokio background task (`query_log_disk::Writer`).
   - Reads from a bounded `mpsc` channel (capacity 8192) fed by `QueryLog`.
   - Non-blocking `try_send` on the producer: a full channel drops from the
     disk stream (counted in `rustydns_query_log_disk_dropped_total`) rather
     than stalling the DNS hot path.
   - Buffered writes flushed once per drained batch.

## Code
- `crates/rustydnsd/src/query_log_disk.rs` — writer task + rotation + perm check.
- `crates/rustydnsd/src/query_log.rs` — `with_disk_sink`, fan-out in `record`.
- Config: `PrivacyConfig::{query_log_disk_path, query_log_max_file_bytes,
  query_log_max_files}` + validation in `validate_config`.
- Metrics: `rustydns_query_log_disk_{written,dropped,io_errors,rotations}_total`.
