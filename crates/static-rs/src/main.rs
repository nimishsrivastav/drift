//! Static capability-drift analyzer. M1 implements `Info` only; analysis arrives in M3 and M4.

use anyhow::Context;
use drift_proto::v1::analyzer_server::{Analyzer, AnalyzerServer};
use drift_proto::v1::{AnalyzeResponse, ArtifactPair, Ecosystem, InfoRequest, InfoResponse};
use tonic::{Request, Response, Status, transport::Server};

const NAME: &str = "static-rs";
const DEFAULT_LISTEN: &str = "0.0.0.0:50051";

#[derive(Default)]
struct Service;

#[tonic::async_trait]
impl Analyzer for Service {
    async fn analyze(&self, _: Request<ArtifactPair>) -> Result<Response<AnalyzeResponse>, Status> {
        Err(Status::unimplemented("analysis arrives in M3"))
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

    tracing::info!(analyzer = NAME, %addr, "serving");
    Server::builder()
        .add_service(AnalyzerServer::new(Service))
        .serve_with_shutdown(addr, shutdown_signal())
        .await
        .context("gRPC server failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn info_names_this_analyzer() {
        let info = Service
            .info(Request::new(InfoRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(info.name, NAME);
        assert!(!info.version.is_empty());
        assert_eq!(info.ecosystems, vec![i32::from(Ecosystem::Npm)]);
    }

    #[tokio::test]
    async fn analyze_is_not_implemented_yet() {
        let err = Service
            .analyze(Request::new(ArtifactPair::default()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }
}
