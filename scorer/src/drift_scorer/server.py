"""gRPC server for the scorer. M1 implements Analyzer.Info only; scoring arrives in M7."""

import logging
import os
import signal
from concurrent import futures
from types import FrameType

import grpc
from drift.v1 import drift_pb2, drift_pb2_grpc

from drift_scorer import __version__

NAME = "scorer"
DEFAULT_LISTEN = "0.0.0.0:50051"

logger = logging.getLogger(NAME)


class AnalyzerService(drift_pb2_grpc.AnalyzerServicer):
    def Info(
        self, request: drift_pb2.InfoRequest, context: grpc.ServicerContext
    ) -> drift_pb2.InfoResponse:
        return drift_pb2.InfoResponse(
            name=NAME, version=__version__, ecosystems=[drift_pb2.ECOSYSTEM_NPM]
        )


def serve(listen: str) -> None:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    drift_pb2_grpc.add_AnalyzerServicer_to_server(AnalyzerService(), server)
    # Scorer.Score stays unregistered until M7, so callers get UNIMPLEMENTED.
    if server.add_insecure_port(listen) == 0:
        raise RuntimeError(f"could not bind {listen}")
    server.start()
    logger.info("serving analyzer=%s addr=%s", NAME, listen)

    def stop(_signum: int, _frame: FrameType | None) -> None:
        server.stop(grace=5)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    server.wait_for_termination()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    serve(os.environ.get("DRIFT_LISTEN", DEFAULT_LISTEN))


if __name__ == "__main__":
    main()
