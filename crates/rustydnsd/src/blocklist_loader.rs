#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::Client;
use reqwest::redirect::Policy as RedirectPolicy;
use tracing::{info, warn};

use rustydns_blocklist::{BlocklistEngine, BlocklistSource};
use rustydns_core::RustyDnsError;
use rustydns_core::config::{BlocklistConfig, redact_url_credentials};

/// Summary of a blocklist reload attempt.
#[derive(Debug, Clone, Copy)]
pub struct LoadSummary {
    /// Total number of sources considered (local + remote).
    pub total_sources: usize,
    /// Number of sources successfully loaded.
    pub loaded_sources: usize,
    /// Number of sources that failed to load.
    pub failed_sources: usize,
}

/// Fetches and reloads blocklist sources into a [`BlocklistEngine`].
#[derive(Clone)]
pub struct BlocklistLoader {
    config: Arc<BlocklistConfig>,
    client: Client,
    /// Last successfully-read content per source (url or path), retained so
    /// a FAILED refresh falls back to it instead of silently dropping that
    /// source's entries from the active list. Bounded: one entry per
    /// configured source, each capped by `max_fetch_bytes`.
    last_good: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
}

impl BlocklistLoader {
    /// Create a new loader with an HTTP client configured from the blocklist config.
    pub fn new(config: Arc<BlocklistConfig>) -> Result<Self, RustyDnsError> {
        let timeout = Duration::from_millis(config.fetch_timeout_ms);
        let client = Client::builder()
            .timeout(timeout)
            // Set a stable, identifiable User-Agent so blocklist
            // hosts can attribute traffic to rustydnsd (helps them
            // shape rate limits and reach out about abuse). Includes
            // the package version so a misbehaving release can be
            // identified server-side without a packet capture.
            .user_agent(concat!(
                "rustydnsd/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/Iwan-Teague/rustydns)"
            ))
            // Defence in depth: validate_config already rejects http://
            // sources, but if a future caller bypasses validation (or
            // a redirect lands on http://), `https_only(true)` makes
            // reqwest itself refuse plaintext at request time. The
            // AGENTS.md privacy invariant "HTTPS-only blocklist
            // sources" is then enforced in two places, not one.
            .https_only(true)
            // Same floor as the upstream resolver and ODoH clients: source
            // URLs may embed access tokens, and there is no reason to let a
            // CDN negotiate TLS 1.2 when every major provider speaks 1.3.
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            // reqwest's default of 10 redirects gives a 3xx-chain
            // operator far too much rope. Three hops covers normal
            // host-rename / CDN-edge patterns (e.g. raw.githubusercontent
            // → ...cdn.github.com → ...blob) without letting a
            // misconfigured (or hostile) endpoint walk the loader
            // through an unbounded chain.
            .redirect(RedirectPolicy::limited(3))
            .build()
            .map_err(|e| RustyDnsError::Blocklist(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            config,
            client,
            last_good: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    /// Reload all configured sources. Leaves existing state untouched if
    /// nothing loads. Also reloads every `[[blocklist.groups]]` set (TODO 8.6);
    /// a group that fails to load keeps its previous state and is warned, and
    /// does not affect the returned (default-blocklist) summary.
    pub async fn reload(&self, engine: &BlocklistEngine) -> Result<LoadSummary, RustyDnsError> {
        // --- Global (default) blocklist ---
        let (sources, failed_sources) = self
            .gather(
                &self.config.local_files,
                &self.config.sources,
                &self.config.trusted_rpz_sources,
            )
            .await;

        let loaded_sources = sources.len();
        let summary = LoadSummary {
            total_sources: loaded_sources + failed_sources,
            loaded_sources,
            failed_sources,
        };

        if sources.is_empty() {
            warn!(
                total = summary.total_sources,
                failed = summary.failed_sources,
                "no blocklist sources loaded; keeping existing state"
            );
        } else {
            let refs: Vec<(&str, BlocklistSource)> =
                sources.iter().map(|(s, t)| (s.as_str(), *t)).collect();
            engine.load_many_with_trust(&refs);
            info!(
                loaded = summary.loaded_sources,
                failed = summary.failed_sources,
                "blocklist reload complete"
            );
        }

        // --- Per-client groups (TODO 8.6) ---
        for group in &self.config.groups {
            let (gsrc, gfailed) = self
                .gather(
                    &group.local_files,
                    &group.sources,
                    &group.trusted_rpz_sources,
                )
                .await;
            if gsrc.is_empty() {
                warn!(
                    group = %group.name,
                    failed = gfailed,
                    "no sources loaded for blocklist group; keeping existing group state"
                );
                continue;
            }
            let grefs: Vec<(&str, BlocklistSource)> =
                gsrc.iter().map(|(s, t)| (s.as_str(), *t)).collect();
            // Merge the GLOBAL allowlist into each group so "never block"
            // decisions apply universally. Without this, a group's own
            // sources could override the operator's global exemptions.
            let mut group_allow = self.config.allowlist.clone();
            group_allow.extend(group.allowlist.iter().cloned());
            engine.load_group(&group.name, &grefs, &group_allow);
            info!(
                group = %group.name,
                loaded = gsrc.len(),
                failed = gfailed,
                "blocklist group reload complete"
            );
        }

        Ok(summary)
    }

    /// Fetch a set of local + remote sources, returning the loaded contents
    /// (each tagged trusted/untrusted) and the count that failed.
    async fn gather(
        &self,
        local_files: &[std::path::PathBuf],
        remote: &[String],
        trusted_rpz: &[String],
    ) -> (Vec<(String, BlocklistSource)>, usize) {
        let mut sources: Vec<(String, BlocklistSource)> = Vec::new();
        let mut failed = 0usize;

        for path in local_files {
            match self.read_local(path).await {
                Ok(content) => {
                    self.remember_last_good(&path.display().to_string(), &content);
                    sources.push((content, BlocklistSource::Trusted));
                }
                Err(e) => {
                    // FAIL-CLOSED per source: a vanished/unreadable file
                    // falls back to its LAST GOOD content so previously
                    // blocked domains stay blocked. Only a source with no
                    // history is dropped.
                    if let Some(last) = self.last_good_content(&path.display().to_string()) {
                        warn!(path = %path.display(), error = %e,
                              "local blocklist unreadable - using last good content");
                        sources.push((last, BlocklistSource::Trusted));
                    } else {
                        failed += 1;
                        warn!(path = %path.display(), error = %e, "failed to read local blocklist");
                    }
                }
            }
        }
        // Concurrent fetches, BOUNDED. Startup and SIGHUP block on this
        // round, so serial awaiting would multiply one slow/dead source's
        // timeout by the source count — while fully unbounded concurrency
        // (join_all) multiplies PEAK MEMORY instead: every in-flight body
        // buffers up to max_fetch_bytes at once. A small window keeps
        // typical multi-source reloads fast without meaningfully raising
        // the resident footprint on Pi-class targets (512 MiB total, 30 MiB
        // idle-RSS goal).
        const MAX_CONCURRENT_FETCHES: usize = 4;

        let mut results: Vec<(
            usize,
            String,
            BlocklistSource,
            Result<String, RustyDnsError>,
        )> = futures_util::stream::iter(remote.iter().cloned().enumerate())
            .map(|(idx, url)| {
                let trust = if trusted_rpz.iter().any(|t| t.as_str() == url.as_str()) {
                    BlocklistSource::Trusted
                } else {
                    BlocklistSource::Untrusted
                };
                async move {
                    let res = self.fetch_remote(&url).await;
                    (idx, url, trust, res)
                }
            })
            .buffer_unordered(MAX_CONCURRENT_FETCHES)
            .collect()
            .await;

        // Restore source-list order so summaries and engine unions stay
        // deterministic run-to-run despite completion-order delivery.
        results.sort_by_key(|(idx, _, _, _)| *idx);

        for (_, url, trust, res) in &results {
            match res {
                Ok(content) => {
                    self.remember_last_good(url, content);
                    sources.push((content.clone(), *trust));
                }
                Err(e) => {
                    // FAIL-CLOSED per source: a failed fetch falls back to
                    // this URL's LAST GOOD content so its entries remain
                    // actively blocked instead of silently vanishing from
                    // the rebuilt list.
                    if let Some(last) = self.last_good_content(url) {
                        warn!(
                            url = %redact_url_credentials(url),
                            error = %e,
                            "blocklist fetch failed - using last good content"
                        );
                        sources.push((last, *trust));
                    } else {
                        failed += 1;
                        // PRIVACY: source URLs may embed tokens; the error text
                        // already carries a redacted form of the URL.
                        warn!(
                            url = %redact_url_credentials(url),
                            error = %e,
                            "failed to fetch blocklist source"
                        );
                    }
                }
            }
        }
        (sources, failed)
    }

    /// Store/refresh the last good content for a source key.
    fn remember_last_good(&self, key: &str, content: &str) {
        self.last_good
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key.to_string(), content.to_string());
    }

    /// Retained content for a source, WITHOUT consuming it. Sustained
    /// outages must keep falling back on every failed round - consuming
    /// the entry would resume under-blocking after a single grace reload.
    /// The map is bounded by the number of distinct configured sources;
    /// entries for sources later removed from config linger until process
    /// restart (tiny, and cleared by the next success).
    fn last_good_content(&self, key: &str) -> Option<String> {
        self.last_good
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(key)
            .cloned()
    }

    async fn read_local(&self, path: &Path) -> Result<String, RustyDnsError> {
        // Spawn-blocking: local file I/O can block indefinitely on NFS mounts,
        // FIFOs, or hung network filesystems. Moving it off the tokio runtime
        // thread prevents stalling ALL async tasks (including DNS query
        // processing) while the read completes or times out.
        let cap = self.config.max_fetch_bytes;
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let file = std::fs::File::open(&path)
                .map_err(|e| RustyDnsError::Blocklist(format!("failed to read {path:?}: {e}")))?;
            let mut limited = file.take(cap.saturating_add(1));
            let mut bytes = Vec::new();
            limited
                .read_to_end(&mut bytes)
                .map_err(|e| RustyDnsError::Blocklist(format!("failed to read {path:?}: {e}")))?;
            if bytes.len() as u64 > cap {
                return Err(RustyDnsError::Blocklist(format!(
                    "local blocklist {path:?} exceeds max_fetch_bytes ({len} > {cap})",
                    len = bytes.len(),
                )));
            }
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        })
        .await
        .map_err(|e| RustyDnsError::Blocklist(format!("spawn_blocking join error: {e}")))?
    }

    async fn fetch_remote(&self, url: &str) -> Result<String, RustyDnsError> {
        // PRIVACY: source URLs may embed credential query parameters. Every
        // error message below embeds the URL, and errors surface at warn
        // level — emit only the redacted form.
        let url_disp = redact_url_credentials(url);
        let response =
            self.client.get(url).send().await.map_err(|e| {
                RustyDnsError::Blocklist(format!("fetch failed for {url_disp}: {e}"))
            })?;

        if !response.status().is_success() {
            return Err(RustyDnsError::Blocklist(format!(
                "fetch failed for {url_disp}: HTTP {}",
                response.status()
            )));
        }

        read_body_capped(&url_disp, response, self.config.max_fetch_bytes).await
    }
}

/// Drain a successful blocklist-fetch response under the configured byte cap:
/// content-length precheck first, then a chunked streaming read that aborts
/// as soon as the running total would exceed `cap`. A hostile or compromised
/// CDN cannot stream unbounded bytes into memory before parsing ("no
/// unbounded memory" invariant). Split out of [`BlocklistLoader::fetch_remote`]
/// so it can be driven directly against a plain-HTTP loopback server in tests
/// (the production client is `https_only` and refuses such URLs).
async fn read_body_capped(
    url_disp: &str,
    response: reqwest::Response,
    cap: u64,
) -> Result<String, RustyDnsError> {
    if let Some(len) = response.content_length()
        && len > cap
    {
        return Err(RustyDnsError::Blocklist(format!(
            "fetch failed for {url_disp}: content-length {len} exceeds max_fetch_bytes {cap}"
        )));
    }

    let mut body: Vec<u8> = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|e| RustyDnsError::Blocklist(format!("fetch failed for {url_disp}: {e}")))?;
        if (body.len() + chunk.len()) as u64 > cap {
            return Err(RustyDnsError::Blocklist(format!(
                "fetch failed for {url_disp}: response exceeds max_fetch_bytes {cap}"
            )));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(String::from_utf8_lossy(&body).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn loader_with_cap(cap: u64) -> BlocklistLoader {
        let cfg = rustydns_core::config::BlocklistConfig {
            max_fetch_bytes: cap,
            ..rustydns_core::config::BlocklistConfig::default()
        };
        BlocklistLoader::new(Arc::new(cfg)).expect("loader builds")
    }

    #[tokio::test]
    async fn gather_falls_back_to_last_good_across_consecutive_failures() {
        // PEEK-vs-CONSUME teeth (loader-unit layer): a source that keeps
        // failing must keep contributing its LAST GOOD content on every
        // round. Consume-on-use semantics would drop it after the FIRST
        // grace reload - silently resuming under-blocking exactly when
        // operators still assume protection. The daemon's 60s SIGHUP
        // fetch-spacing makes this untestable at the binary layer; here we
        // drive gather directly with no spacing.
        let dir = tempfile::TempDir::new().unwrap();
        let file_a = dir.path().join("a.hosts");
        let file_b = dir.path().join("b.hosts");
        std::fs::write(&file_a, "alpha-from-a.test\n").unwrap();
        std::fs::write(&file_b, "beta-from-b.test\n").unwrap();

        let cfg = rustydns_core::config::BlocklistConfig {
            local_files: vec![file_a.clone(), file_b.clone()],
            max_fetch_bytes: 1024 * 1024,
            ..Default::default()
        };
        let loader = BlocklistLoader::new(Arc::new(cfg)).expect("loader builds");

        let names = |srcs: &[(String, BlocklistSource)]| -> Vec<String> {
            srcs.iter().map(|(c, _)| c.clone()).collect()
        };

        // Round 1: both readable.
        let (r1, failed1) = loader
            .gather(&[file_a.clone(), file_b.clone()], &[], &[])
            .await;
        assert_eq!(failed1, 0);
        // SEED pin: successful rounds must populate retention for BOTH
        // sources - without this, the later failure fallback has nothing
        // to fall back TO.
        {
            let map = loader.last_good.lock().unwrap();
            assert_eq!(
                map.len(),
                2,
                "both sources must be seeded after a clean round: {map:?}"
            );
            assert!(map.contains_key(file_a.to_string_lossy().as_ref()));
            assert!(map.contains_key(file_b.to_string_lossy().as_ref()));
        }
        let n1 = names(&r1);
        assert!(n1.iter().any(|c| c.contains("alpha-from-a")));
        assert!(n1.iter().any(|c| c.contains("beta-from-b")));

        // Round 2+3: BOTH files now gone. Every subsequent round must
        // still return both retained contents.
        std::fs::remove_file(&file_a).unwrap();
        std::fs::remove_file(&file_b).unwrap();
        for round in 2..=3 {
            let (rn, failedn) = loader
                .gather(&[file_a.clone(), file_b.clone()], &[], &[])
                .await;
            assert_eq!(
                failedn, 0,
                "retained sources must not be counted as hard failures"
            );
            let nn = names(&rn);
            assert!(
                nn.iter().any(|c| c.contains("alpha-from-a")),
                "round {round}: alpha retention lost"
            );
            assert!(
                nn.iter().any(|c| c.contains("beta-from-b")),
                "round {round}: beta retention lost (consume-on-use regression?)"
            );
        }
    }

    #[tokio::test]
    async fn read_local_accepts_file_under_cap() {
        let dir = std::env::temp_dir().join(format!("rustydns-bl-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let path = dir.join("under.cap");
        std::fs::write(&path, "ads.example.com\ntrackers.example.org\n").expect("write");

        let loader = loader_with_cap(1024);
        let content = loader
            .read_local(&path)
            .await
            .expect("under-cap file reads");
        assert!(content.contains("ads.example.com"));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn read_local_rejects_file_over_cap_without_fully_buffering() {
        let dir = std::env::temp_dir().join(format!("rustydns-bl-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let path = dir.join("over.cap");
        // One byte beyond the cap is enough to be rejected; the take()-based
        // read never buffers more than cap+1 regardless of the file size.
        let big = vec![b'a'; 4096];
        std::fs::write(&path, &big).expect("write");

        let loader = loader_with_cap(1024);
        let err = loader
            .read_local(&path)
            .await
            .expect_err("over-cap local file must be rejected");
        assert!(err.to_string().contains("max_fetch_bytes"));

        let _ = std::fs::remove_file(&path);
    }

    // -- read_body_capped: real-HTTP coverage of the remote streaming cap --
    //
    // The production client is https_only, so these drive a plain loopback
    // HTTP server and hand `read_body_capped` the genuine reqwest::Response.
    // Same shape as the ODoH read_capped tests.

    /// Serve ONE handcrafted response on a fresh loopback listener; returns
    /// the URL to GET. Drains the request head first so hyper sees a complete
    /// request before we answer, then holds the socket open (5 s) so streamed
    /// bodies are not RST mid-read.
    async fn serve_once(response: &[u8]) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let owned = response.to_vec();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(n) if n > 0 => {
                            if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                let _ = sock.write_all(&owned).await;
                let _ = sock.flush().await;
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
        format!("http://{addr}/list.txt")
    }

    #[tokio::test]
    async fn remote_body_content_length_over_cap_rejected_before_read() {
        // Lying-but-large content-length header must abort before any body
        // bytes are pulled.
        let url = serve_once(
            b"HTTP/1.1 200 OK\r\ncontent-length: 99999999\r\ncontent-type: text/plain\r\n\r\nsmall",
        )
        .await;
        let resp = reqwest::get(&url).await.expect("request");
        let err = read_body_capped(&url, resp, 1024)
            .await
            .expect_err("over-cap content-length must be rejected");
        assert!(err.to_string().contains("content-length"), "{err}");
    }

    #[tokio::test]
    async fn remote_body_streaming_over_cap_aborts_mid_stream() {
        // Chunked encoding (no content-length): one oversized chunk must trip
        // the running-total check even though the terminating chunk never
        // arrives — the cap aborts proactively, it does not wait for EOF.
        let chunk_data = vec![b'a'; 4096];
        let mut raw = Vec::new();
        raw.extend_from_slice(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n");
        raw.extend_from_slice(format!("{:x}\r\n", chunk_data.len()).as_bytes());
        raw.extend_from_slice(&chunk_data);
        raw.extend_from_slice(b"\r\n"); // no terminating 0-chunk on purpose

        let url = serve_once(&raw).await;
        let resp = reqwest::get(&url).await.expect("request");
        let err = read_body_capped(&url, resp, 1024)
            .await
            .expect_err("over-cap stream must be rejected");
        assert!(
            err.to_string().contains("response exceeds max_fetch_bytes"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn remote_body_under_cap_is_returned_intact() {
        let url = serve_once(
            b"HTTP/1.1 200 OK\r\ncontent-length: 15\r\ncontent-type: text/plain\r\n\r\nads.example.com",
        )
        .await;
        let resp = reqwest::get(&url).await.expect("request");
        let body = read_body_capped(&url, resp, 1024)
            .await
            .expect("under-cap ok");
        assert_eq!(body, "ads.example.com");
    }
}
