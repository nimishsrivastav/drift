from collections.abc import Iterator
from concurrent import futures

import grpc
import pytest
from drift.v1 import drift_pb2, drift_pb2_grpc
from drift_scorer.server import NAME, AnalyzerService


@pytest.fixture
def channel() -> Iterator[grpc.Channel]:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    drift_pb2_grpc.add_AnalyzerServicer_to_server(AnalyzerService(), server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    with grpc.insecure_channel(f"127.0.0.1:{port}") as chan:
        yield chan
    server.stop(grace=None)


def test_info_over_grpc(channel: grpc.Channel) -> None:
    info = drift_pb2_grpc.AnalyzerStub(channel).Info(drift_pb2.InfoRequest(), timeout=5)
    assert info.name == NAME
    assert info.version
    assert list(info.ecosystems) == [drift_pb2.ECOSYSTEM_NPM]


def test_analyze_is_not_implemented_yet(channel: grpc.Channel) -> None:
    with pytest.raises(grpc.RpcError) as err:
        drift_pb2_grpc.AnalyzerStub(channel).Analyze(drift_pb2.ArtifactPair(), timeout=5)
    assert err.value.code() == grpc.StatusCode.UNIMPLEMENTED
