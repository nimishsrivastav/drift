//! Static capability-drift analyzer service. The analysis itself lives in the library.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use drift_proto::v1::analyzer_server::{Analyzer, AnalyzerServer};
use drift_proto::v1::{AnalyzeResponse, ArtifactPair, Ecosystem, InfoRequest, InfoResponse};
use static_rs::Config;
use tokio::sync::Semaphore;
use tonic::{Request, Response, Status, transport::Server};

const NAME: &str = "static-rs";
const DEFAULT_LISTEN: &str = "0.0.0.0:50051";
const DEFAULT_ARTIFACTS: &str = "/artifacts";
/// Each analysis unpacks two versions into the temporary directory, so this bounds its use.
const DEFAULT_CONCURRENCY: usize = 2;

struct Service {
    config: Arc<Config>,
    permits: Arc<Semaphore>,
}

impl Service {
    fn new(config: Config, concurrency: usize) -> Self {
        Self {
            config: Arc::new(config),
            permits: Arc::new(Semaphore::new(concurrency.max(1))),
        }
    }
}

#[tonic::async_trait]
impl Analyzer for Service {
    async fn analyze(
        &self,
        request: Request<ArtifactPair>,
    ) -> Result<Response<AnalyzeResponse>, Status> {
        let pair = request.into_inner();
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| Status::unavailable("shutting down"))?;
        let config = Arc::clone(&self.config);
        let job = pair.job_id.clone();
        // Unpacking and hashing are blocking work.
        let response = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            static_rs::analyze(&pair, &config)
        })
        .await
        .map_err(|e| Status::internal(format!("analysis panicked: {e}")))?;
        tracing::info!(
            job = %job,
            findings = response.findings.len(),
            notes = response.errors.len(),
            duration_ms = response.duration_ms,
            "analyzed"
        );
        Ok(Response::new(response))
    }

    async fn info(&self, _: Request<InfoRequest>) -> Result<Response<InfoResponse>, Status> {
        Ok(Response::new(InfoResponse {
            name: NAME.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            ecosystems: vec![Ecosystem::Npm.into()],
        }))
    }
}

async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing the SIGTERM handler only fails at startup");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_ansi(false).init();

    let listen = std::env::var("DRIFT_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.to_owned());
    let addr = listen
        .parse()
        .with_context(|| format!("invalid DRIFT_LISTEN {listen:?}"))?;
    let artifacts =
        std::env::var("DRIFT_ARTIFACTS_ROOT").unwrap_or_else(|_| DEFAULT_ARTIFACTS.to_owned());
    let mut config = Config::new(&artifacts);
    config.tmp_dir = std::env::var_os("DRIFT_TMP_DIR").map(PathBuf::from);
    let concurrency = match std::env::var("DRIFT_MAX_CONCURRENT") {
        Ok(raw) => raw
            .parse()
            .with_context(|| format!("invalid DRIFT_MAX_CONCURRENT {raw:?}"))?,
        Err(_) => DEFAULT_CONCURRENCY,
    };

    tracing::info!(analyzer = NAME, %addr, %artifacts, concurrency, "serving");
    Server::builder()
        .add_service(AnalyzerServer::new(Service::new(config, concurrency)))
        .serve_with_shutdown(addr, shutdown_signal())
        .await
        .context("gRPC server failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Service {
        Service::new(Config::new("/nonexistent"), 1)
    }

    #[tokio::test]
    async fn info_names_this_analyzer() {
        let info = service()
            .info(Request::new(InfoRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(info.name, NAME);
        assert!(!info.version.is_empty());
        assert_eq!(info.ecosystems, vec![i32::from(Ecosystem::Npm)]);
    }

    #[tokio::test]
    async fn analyze_reports_request_problems_as_notes() {
        let response = service()
            .analyze(Request::new(ArtifactPair::default()))
            .await
            .unwrap()
            .into_inner();
        assert!(response.findings.is_empty());
        assert_eq!(response.errors, ["request has no new version"]);
    }
}
