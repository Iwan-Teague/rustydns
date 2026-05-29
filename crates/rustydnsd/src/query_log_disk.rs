#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! On-disk query-log writer (roadmap 3.1).
//!
//! Opt-in, durable, privacy-safe query log. Enabled by
//! `privacy.query_log_to_disk = true` + `privacy.query_log_disk_path`.
//!
//! # Privacy posture
//!
//! What reaches disk is exactly what the in-memory ring buffer holds and
//! what the `/queries` endpoint exposes: a [`QueryLogEntry`] rendered via
//! [`QueryLogEntry::to_json`]. That carries only the **salted hash** of
//! the QNAME and the **anonymised** client (IPv4 `/16`, IPv6 `/64`). The
//! raw QNAME and full client IP never enter this module — there is no
//! code path here that could write them, by construction. The
//! `privacy.log_client_ips` escape hatch does **not** apply to the
//! on-disk log; it is always anonymised.
//!
//! # File permissions
//!
//! The active file is created mode `0600`. Before opening an existing
//! target, its mode is checked: if any group/other permission bit is set
//! (`mode & 0o077 != 0`), the writer refuses to use it, logs an error,
//! and disk logging stays **disabled** — the daemon keeps serving DNS.
//! Refusing to write to a readable file is the privacy-safe failure mode;
//! crashing the resolver because a log file has loose permissions is not.
//!
//! # I/O strategy
//!
//! A dedicated Tokio task drains a bounded `mpsc` channel fed by
//! [`QueryLog`](crate::query_log::QueryLog). Writes are buffered and
//! flushed once per drained batch, keeping disk I/O off the DNS hot path.
//! If the channel fills (writer behind, e.g. slow SD card on a Pi), the
//! producer drops entries from the disk stream rather than blocking the
//! resolver — counted in `rustydns_query_log_disk_dropped_total`.
//!
//! # Rotation
//!
//! Size-based. When the active file reaches `max_file_bytes`, it is
//! rotated: `path.{n}` → `path.{n+1}` (oldest beyond `max_files`
//! deleted), `path` → `path.1`, and a fresh `path` is opened. Tuned for
//! low-power devices — bounded total footprint, no time-based cron.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::metrics::Metrics;
use crate::query_log::QueryLogEntry;
use std::sync::Arc;

/// Channel depth between the DNS path and the disk writer. ~8k entries of
/// ~96 bytes each ≈ 768 KiB worst case — bounded, and large enough to
/// absorb bursts while a slow disk catches up.
const CHANNEL_CAPACITY: usize = 8192;

/// Handle returned by [`spawn`] when disk logging started successfully.
pub struct DiskLogHandle {
    /// Producer side handed to `QueryLog::with_disk_sink`.
    pub sender: mpsc::Sender<QueryLogEntry>,
}

/// Start the on-disk query-log writer.
///
/// Returns `Some(DiskLogHandle)` when the target file was opened (or
/// created) with safe permissions and the writer task spawned. Returns
/// `None` when disk logging could not be started safely — the caller
/// continues with the in-memory ring buffer only. Never panics; never
/// aborts the daemon.
pub fn spawn(
    path: impl Into<PathBuf>,
    max_file_bytes: u64,
    max_files: usize,
    metrics: Arc<Metrics>,
    shutdown: CancellationToken,
) -> Option<DiskLogHandle> {
    let path = path.into();

    // Permission preflight on an existing target.
    if let Err(reason) = check_existing_permissions(&path) {
        error!(
            path = %path.display(),
            reason = %reason,
            "refusing to write the on-disk query log — permissions are not 0600; \
             disk query logging is DISABLED (the in-memory ring buffer is unaffected)"
        );
        return None;
    }

    // Open (create if absent) the active file in append mode, mode 0600.
    let initial = match open_append_0600(&path) {
        Ok(f) => f,
        Err(e) => {
            error!(
                path = %path.display(),
                error = %e,
                "failed to open the on-disk query log; disk query logging is DISABLED"
            );
            return None;
        }
    };
    let initial_size = initial.metadata().map(|m| m.len()).unwrap_or(0);

    let (tx, rx) = mpsc::channel::<QueryLogEntry>(CHANNEL_CAPACITY);

    info!(
        path = %path.display(),
        max_file_bytes,
        max_files,
        "on-disk query log enabled (NDJSON, mode 0600, salted-hashed qnames, anonymised clients)"
    );

    let writer = Writer {
        path,
        max_file_bytes,
        max_files,
        cur_size: initial_size,
        out: BufWriter::new(tokio::fs::File::from_std(initial)),
        metrics,
    };
    tokio::spawn(writer.run(rx, shutdown));

    Some(DiskLogHandle { sender: tx })
}

/// Refuse the target if it already exists with any group/other
/// permission bit set. A non-existent target is fine (we create it 0600).
fn check_existing_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(format!("existing file mode is {mode:o}, want 0600"));
                }
                Ok(())
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("cannot stat target: {e}")),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Open `path` for append, creating it mode 0600 if absent. On unix the
/// mode is set explicitly; the process umask (0o077) is a second line of
/// defence.
fn open_append_0600(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

struct Writer {
    path: PathBuf,
    max_file_bytes: u64,
    max_files: usize,
    cur_size: u64,
    out: BufWriter<tokio::fs::File>,
    metrics: Arc<Metrics>,
}

impl Writer {
    async fn run(mut self, mut rx: mpsc::Receiver<QueryLogEntry>, shutdown: CancellationToken) {
        loop {
            tokio::select! {
                maybe = rx.recv() => {
                    match maybe {
                        Some(entry) => {
                            self.write_entry(&entry).await;
                            // Drain any further ready entries to amortise
                            // the flush across the batch.
                            while let Ok(entry) = rx.try_recv() {
                                self.write_entry(&entry).await;
                            }
                            self.flush().await;
                        }
                        // All senders dropped — nothing more will arrive.
                        None => break,
                    }
                }
                _ = shutdown.cancelled() => {
                    // Drain whatever is already queued, then stop.
                    while let Ok(entry) = rx.try_recv() {
                        self.write_entry(&entry).await;
                    }
                    self.flush().await;
                    break;
                }
            }
        }
        self.flush().await;
    }

    async fn write_entry(&mut self, entry: &QueryLogEntry) {
        let mut line = entry.to_json();
        line.push('\n');
        let bytes = line.as_bytes();

        // Rotate before the write would push us past the cap, so a single
        // large-ish line never blows the bound by more than one line.
        if self.cur_size + bytes.len() as u64 > self.max_file_bytes && self.cur_size > 0 {
            self.rotate().await;
        }

        match self.out.write_all(bytes).await {
            Ok(()) => {
                self.cur_size += bytes.len() as u64;
                self.metrics.inc_query_log_disk_written();
            }
            Err(e) => {
                self.metrics.inc_query_log_disk_io_errors();
                warn!(error = %e, path = %self.path.display(), "query-log disk write failed");
            }
        }
    }

    async fn flush(&mut self) {
        if let Err(e) = self.out.flush().await {
            self.metrics.inc_query_log_disk_io_errors();
            warn!(error = %e, path = %self.path.display(), "query-log disk flush failed");
        }
    }

    /// Flush and close the active file, shift the numbered backups, then
    /// reopen a fresh active file (mode 0600). On any I/O error we keep
    /// writing to the current file rather than losing the stream.
    async fn rotate(&mut self) {
        if let Err(e) = self.out.flush().await {
            warn!(error = %e, "flush before rotation failed; skipping rotation this round");
            return;
        }

        // Delete the oldest, then shift .{n} -> .{n+1} down to base -> .1.
        // With max_files = N we keep base + .1 .. .{N-1}.
        let oldest = self.numbered(self.max_files.saturating_sub(1));
        let _ = std::fs::remove_file(&oldest); // ok if absent

        for n in (1..self.max_files.saturating_sub(1)).rev() {
            let from = self.numbered(n);
            let to = self.numbered(n + 1);
            if from.exists()
                && let Err(e) = std::fs::rename(&from, &to)
            {
                warn!(error = %e, from = %from.display(), "query-log rotation rename failed");
            }
        }

        if self.max_files >= 2 {
            let dot1 = self.numbered(1);
            if let Err(e) = std::fs::rename(&self.path, &dot1) {
                warn!(error = %e, "query-log base rename failed; skipping rotation this round");
                return;
            }
        } else {
            // max_files == 1: no history kept — truncate the active file.
            let _ = std::fs::remove_file(&self.path);
        }

        match open_append_0600(&self.path) {
            Ok(f) => {
                self.out = BufWriter::new(tokio::fs::File::from_std(f));
                self.cur_size = 0;
                self.metrics.inc_query_log_disk_rotations();
            }
            Err(e) => {
                error!(error = %e, path = %self.path.display(),
                    "failed to reopen query log after rotation; disk logging will error until restart");
            }
        }
    }

    /// `path.{n}` — the n-th rotated backup file name.
    fn numbered(&self, n: usize) -> PathBuf {
        let mut s = self.path.clone().into_os_string();
        s.push(format!(".{n}"));
        PathBuf::from(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query_log::{QueryLog, ServedBy};
    use rustydns_core::client::ClientId;
    use std::net::{IpAddr, Ipv4Addr};

    fn client() -> ClientId {
        ClientId::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 9)))
    }

    async fn read_lines(path: &Path) -> Vec<String> {
        let s = tokio::fs::read_to_string(path).await.unwrap_or_default();
        s.lines().map(str::to_string).collect()
    }

    #[tokio::test]
    async fn writes_ndjson_with_hashed_qname_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queries.ndjson");
        let metrics = Arc::new(Metrics::new().unwrap());
        let shutdown = CancellationToken::new();

        let handle = spawn(&path, 1 << 20, 3, metrics.clone(), shutdown.clone()).unwrap();
        let log = QueryLog::with_disk_sink(
            16,
            handle.sender.clone(),
            metrics.query_log_disk_dropped_counter(),
        );

        log.record(&client(), "secret.example.com.", "A", 0, ServedBy::Resolver);
        log.record(
            &client(),
            "tracker.ads.net.",
            "AAAA",
            3,
            ServedBy::Blocklist,
        );

        // Drop the producer so the writer sees the channel close, then
        // cancel to force a final flush.
        drop(log);
        drop(handle);
        shutdown.cancel();
        // Give the writer task a moment to drain + flush.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let lines = read_lines(&path).await;
        assert_eq!(lines.len(), 2, "expected two NDJSON lines, got: {lines:?}");
        for line in &lines {
            // Raw qname must never appear.
            assert!(!line.contains("secret"), "raw qname leaked: {line}");
            assert!(!line.contains("tracker"), "raw qname leaked: {line}");
            assert!(!line.contains("example.com"), "raw qname leaked: {line}");
            // Full client IP must never appear; anonymised /16 only.
            assert!(!line.contains("192.168.5.9"), "full IP leaked: {line}");
            assert!(line.contains("192.168.0.0"), "expected anon /16: {line}");
            assert!(line.contains("qname_hash"), "missing hash field: {line}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn refuses_group_readable_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("loose.ndjson");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let metrics = Arc::new(Metrics::new().unwrap());
        let shutdown = CancellationToken::new();
        let handle = spawn(&path, 1 << 20, 3, metrics, shutdown);
        assert!(handle.is_none(), "must refuse a group-readable target");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn creates_file_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.ndjson");
        let metrics = Arc::new(Metrics::new().unwrap());
        let shutdown = CancellationToken::new();

        let handle = spawn(&path, 1 << 20, 3, metrics.clone(), shutdown.clone()).unwrap();
        let log = QueryLog::with_disk_sink(
            4,
            handle.sender.clone(),
            metrics.query_log_disk_dropped_counter(),
        );
        log.record(&client(), "a.example.", "A", 0, ServedBy::Resolver);
        drop(log);
        drop(handle);
        shutdown.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "active file must be mode 0600, got {mode:o}");
    }

    #[tokio::test]
    async fn rotation_bounds_file_count() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rot.ndjson");
        let metrics = Arc::new(Metrics::new().unwrap());
        let shutdown = CancellationToken::new();

        // Tiny cap (4096 is the validated minimum) + max_files=3 so a
        // burst of writes forces several rotations.
        let handle = spawn(&path, 4096, 3, metrics.clone(), shutdown.clone()).unwrap();
        let log = QueryLog::with_disk_sink(
            8,
            handle.sender.clone(),
            metrics.query_log_disk_dropped_counter(),
        );
        for i in 0..2000 {
            let q = format!("host-{i}.example.com.");
            log.record(&client(), &q, "A", 0, ServedBy::Resolver);
        }
        drop(log);
        drop(handle);
        shutdown.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // base + .1 + .2 may exist; .3 (== max_files) must NOT.
        let dot3 = {
            let mut s = path.clone().into_os_string();
            s.push(".3");
            PathBuf::from(s)
        };
        assert!(
            !dot3.exists(),
            "retention exceeded max_files: .3 should not exist"
        );
    }
}
