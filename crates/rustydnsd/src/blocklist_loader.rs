#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::Client;
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
            .build()
            .map_err(|e| RustyDnsError::Blocklist(format!("failed to build HTTP client: {e}")))?;

        Ok(Self { config, client })
    }

    /// Reload all configured sources. Leaves existing state untouched if nothing loads.
    pub async fn reload(&self, engine: &BlocklistEngine) -> Result<LoadSummary, RustyDnsError> {
        let mut sources: Vec<(String, BlocklistSource)> = Vec::new();
        let mut failed_sources = 0usize;

        for path in &self.config.local_files {
            match self.read_local(path) {
                Ok(content) => sources.push((content, BlocklistSource::Trusted)),
                Err(e) => {
                    failed_sources += 1;
                    warn!(path = %path.display(), error = %e, "failed to read local blocklist");
                }
            }
        }

        for url in &self.config.sources {
            let trust = if self.config.trusted_rpz_sources.iter().any(|t| t == url) {
                BlocklistSource::Trusted
            } else {
                BlocklistSource::Untrusted
            };

            match self.fetch_remote(url).await {
                Ok(content) => sources.push((content, trust)),
                Err(e) => {
                    failed_sources += 1;
                    warn!(url = %url, error = %e, "failed to fetch blocklist source");
                }
            }
        }

        let loaded_sources = sources.len();
        let total_sources = loaded_sources + failed_sources;
        let summary = LoadSummary {
            total_sources,
            loaded_sources,
            failed_sources,
        };

        if sources.is_empty() {
            warn!(
                total = summary.total_sources,
                failed = summary.failed_sources,
                "no blocklist sources loaded; keeping existing state"
            );
            return Ok(summary);
        }

        let refs: Vec<(&str, BlocklistSource)> = sources
            .iter()
            .map(|(s, trust): &(String, BlocklistSource)| (s.as_str(), *trust))
            .collect();
        engine.load_many_with_trust(&refs);

        info!(
            loaded = summary.loaded_sources,
            failed = summary.failed_sources,
            "blocklist reload complete"
        );

        Ok(summary)
    }

    fn read_local(&self, path: &Path) -> Result<String, RustyDnsError> {
        let bytes = std::fs::read(path)
            .map_err(|e| RustyDnsError::Blocklist(format!("failed to read {path:?}: {e}")))?;
        if bytes.len() as u64 > self.config.max_fetch_bytes {
            return Err(RustyDnsError::Blocklist(format!(
                "local blocklist {path:?} exceeds max_fetch_bytes ({} > {})",
                bytes.len(),
                self.config.max_fetch_bytes
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

        if let Some(len) = response.content_length() {
            if len > self.config.max_fetch_bytes {
                return Err(RustyDnsError::Blocklist(format!(
                    "fetch failed for {url}: content-length {len} exceeds max_fetch_bytes {}",
                    self.config.max_fetch_bytes
                )));
            }
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
