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
use rustydns_core::config::BlocklistConfig;

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
            // reqwest's default of 10 redirects gives a 3xx-chain
            // operator far too much rope. Three hops covers normal
            // host-rename / CDN-edge patterns (e.g. raw.githubusercontent
            // → ...cdn.github.com → ...blob) without letting a
            // misconfigured (or hostile) endpoint walk the loader
            // through an unbounded chain.
            .redirect(RedirectPolicy::limited(3))
            .build()
            .map_err(|e| RustyDnsError::Blocklist(format!("failed to build HTTP client: {e}")))?;

        Ok(Self { config, client })
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
            engine.load_group(&group.name, &grefs, &group.allowlist);
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
            match self.read_local(path) {
                Ok(content) => sources.push((content, BlocklistSource::Trusted)),
                Err(e) => {
                    failed += 1;
                    warn!(path = %path.display(), error = %e, "failed to read local blocklist");
                }
            }
        }
        for url in remote {
            let trust = if trusted_rpz.iter().any(|t| t == url) {
                BlocklistSource::Trusted
            } else {
                BlocklistSource::Untrusted
            };
            match self.fetch_remote(url).await {
                Ok(content) => sources.push((content, trust)),
                Err(e) => {
                    failed += 1;
                    warn!(url = %url, error = %e, "failed to fetch blocklist source");
                }
            }
        }
        (sources, failed)
    }

    fn read_local(&self, path: &Path) -> Result<String, RustyDnsError> {
        // Stream the file under the same byte cap as remote fetches — the
        // bounded-fetch invariant shouldn't depend on who owns the file, and
        // this avoids buffering an oversized file fully into memory before
        // noticing it's oversized.
        use std::io::Read;
        let file = std::fs::File::open(path)
            .map_err(|e| RustyDnsError::Blocklist(format!("failed to read {path:?}: {e}")))?;
        let cap = self.config.max_fetch_bytes;
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
    }

    async fn fetch_remote(&self, url: &str) -> Result<String, RustyDnsError> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| RustyDnsError::Blocklist(format!("fetch failed for {url}: {e}")))?;

        if !response.status().is_success() {
            return Err(RustyDnsError::Blocklist(format!(
                "fetch failed for {url}: HTTP {}",
                response.status()
            )));
        }

        if let Some(len) = response.content_length()
            && len > self.config.max_fetch_bytes
        {
            return Err(RustyDnsError::Blocklist(format!(
                "fetch failed for {url}: content-length {len} exceeds max_fetch_bytes {}",
                self.config.max_fetch_bytes
            )));
        }

        let mut body: Vec<u8> = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .map_err(|e| RustyDnsError::Blocklist(format!("fetch failed for {url}: {e}")))?;
            if (body.len() + chunk.len()) as u64 > self.config.max_fetch_bytes {
                return Err(RustyDnsError::Blocklist(format!(
                    "fetch failed for {url}: response exceeds max_fetch_bytes {}",
                    self.config.max_fetch_bytes
                )));
            }
            body.extend_from_slice(&chunk);
        }

        Ok(String::from_utf8_lossy(&body).into_owned())
    }
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

    #[test]
    fn read_local_accepts_file_under_cap() {
        let dir = std::env::temp_dir().join(format!("rustydns-bl-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let path = dir.join("under.cap");
        std::fs::write(&path, "ads.example.com\ntrackers.example.org\n").expect("write");

        let loader = loader_with_cap(1024);
        let content = loader.read_local(&path).expect("under-cap file reads");
        assert!(content.contains("ads.example.com"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_local_rejects_file_over_cap_without_fully_buffering() {
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
            .expect_err("over-cap local file must be rejected");
        assert!(err.to_string().contains("max_fetch_bytes"));

        let _ = std::fs::remove_file(&path);
    }
}
