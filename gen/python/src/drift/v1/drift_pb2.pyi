from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Ecosystem(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ECOSYSTEM_UNSPECIFIED: _ClassVar[Ecosystem]
    ECOSYSTEM_NPM: _ClassVar[Ecosystem]
    ECOSYSTEM_PYPI: _ClassVar[Ecosystem]
    ECOSYSTEM_CRATES: _ClassVar[Ecosystem]

class ExecContext(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EXEC_CONTEXT_UNSPECIFIED: _ClassVar[ExecContext]
    EXEC_CONTEXT_INSTALL: _ClassVar[ExecContext]
    EXEC_CONTEXT_IMPORT: _ClassVar[ExecContext]
    EXEC_CONTEXT_CALL: _ClassVar[ExecContext]

class Capability(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CAPABILITY_UNSPECIFIED: _ClassVar[Capability]
    CAPABILITY_NETWORK: _ClassVar[Capability]
    CAPABILITY_PROCESS_SPAWN: _ClassVar[Capability]
    CAPABILITY_FS_SENSITIVE_READ: _ClassVar[Capability]
    CAPABILITY_ENV_ACCESS: _ClassVar[Capability]
    CAPABILITY_DYNAMIC_CODE: _ClassVar[Capability]
    CAPABILITY_OBFUSCATION: _ClassVar[Capability]
    CAPABILITY_NATIVE_BINARY: _ClassVar[Capability]
    CAPABILITY_CRYPTO_WALLET: _ClassVar[Capability]
    CAPABILITY_INSTALL_HOOK: _ClassVar[Capability]

class Verdict(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VERDICT_UNSPECIFIED: _ClassVar[Verdict]
    VERDICT_BENIGN: _ClassVar[Verdict]
    VERDICT_REVIEW: _ClassVar[Verdict]
    VERDICT_SUSPICIOUS: _ClassVar[Verdict]
ECOSYSTEM_UNSPECIFIED: Ecosystem
ECOSYSTEM_NPM: Ecosystem
ECOSYSTEM_PYPI: Ecosystem
ECOSYSTEM_CRATES: Ecosystem
EXEC_CONTEXT_UNSPECIFIED: ExecContext
EXEC_CONTEXT_INSTALL: ExecContext
EXEC_CONTEXT_IMPORT: ExecContext
EXEC_CONTEXT_CALL: ExecContext
CAPABILITY_UNSPECIFIED: Capability
CAPABILITY_NETWORK: Capability
CAPABILITY_PROCESS_SPAWN: Capability
CAPABILITY_FS_SENSITIVE_READ: Capability
CAPABILITY_ENV_ACCESS: Capability
CAPABILITY_DYNAMIC_CODE: Capability
CAPABILITY_OBFUSCATION: Capability
CAPABILITY_NATIVE_BINARY: Capability
CAPABILITY_CRYPTO_WALLET: Capability
CAPABILITY_INSTALL_HOOK: Capability
VERDICT_UNSPECIFIED: Verdict
VERDICT_BENIGN: Verdict
VERDICT_REVIEW: Verdict
VERDICT_SUSPICIOUS: Verdict

class PackageVersion(_message.Message):
    __slots__ = ("ecosystem", "name", "version", "tarball_path", "tarball_sha256", "repo_path", "repo_ref")
    ECOSYSTEM_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    TARBALL_PATH_FIELD_NUMBER: _ClassVar[int]
    TARBALL_SHA256_FIELD_NUMBER: _ClassVar[int]
    REPO_PATH_FIELD_NUMBER: _ClassVar[int]
    REPO_REF_FIELD_NUMBER: _ClassVar[int]
    ecosystem: Ecosystem
    name: str
    version: str
    tarball_path: str
    tarball_sha256: str
    repo_path: str
    repo_ref: str
    def __init__(self, ecosystem: _Optional[_Union[Ecosystem, str]] = ..., name: _Optional[str] = ..., version: _Optional[str] = ..., tarball_path: _Optional[str] = ..., tarball_sha256: _Optional[str] = ..., repo_path: _Optional[str] = ..., repo_ref: _Optional[str] = ...) -> None: ...

class ArtifactPair(_message.Message):
    __slots__ = ("job_id", "old", "new", "parent_job_id", "depth")
    JOB_ID_FIELD_NUMBER: _ClassVar[int]
    OLD_FIELD_NUMBER: _ClassVar[int]
    NEW_FIELD_NUMBER: _ClassVar[int]
    PARENT_JOB_ID_FIELD_NUMBER: _ClassVar[int]
    DEPTH_FIELD_NUMBER: _ClassVar[int]
    job_id: str
    old: PackageVersion
    new: PackageVersion
    parent_job_id: str
    depth: int
    def __init__(self, job_id: _Optional[str] = ..., old: _Optional[_Union[PackageVersion, _Mapping]] = ..., new: _Optional[_Union[PackageVersion, _Mapping]] = ..., parent_job_id: _Optional[str] = ..., depth: _Optional[int] = ...) -> None: ...

class Evidence(_message.Message):
    __slots__ = ("file", "line", "snippet", "trace_event")
    FILE_FIELD_NUMBER: _ClassVar[int]
    LINE_FIELD_NUMBER: _ClassVar[int]
    SNIPPET_FIELD_NUMBER: _ClassVar[int]
    TRACE_EVENT_FIELD_NUMBER: _ClassVar[int]
    file: str
    line: int
    snippet: str
    trace_event: str
    def __init__(self, file: _Optional[str] = ..., line: _Optional[int] = ..., snippet: _Optional[str] = ..., trace_event: _Optional[str] = ...) -> None: ...

class DriftFinding(_message.Message):
    __slots__ = ("analyzer", "kind", "capability", "context", "evidence", "confidence", "attrs", "via_dependency")
    class AttrsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ANALYZER_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    ATTRS_FIELD_NUMBER: _ClassVar[int]
    VIA_DEPENDENCY_FIELD_NUMBER: _ClassVar[int]
    analyzer: str
    kind: str
    capability: Capability
    context: ExecContext
    evidence: _containers.RepeatedCompositeFieldContainer[Evidence]
    confidence: float
    attrs: _containers.ScalarMap[str, str]
    via_dependency: str
    def __init__(self, analyzer: _Optional[str] = ..., kind: _Optional[str] = ..., capability: _Optional[_Union[Capability, str]] = ..., context: _Optional[_Union[ExecContext, str]] = ..., evidence: _Optional[_Iterable[_Union[Evidence, _Mapping]]] = ..., confidence: _Optional[float] = ..., attrs: _Optional[_Mapping[str, str]] = ..., via_dependency: _Optional[str] = ...) -> None: ...

class AnalyzeResponse(_message.Message):
    __slots__ = ("findings", "errors", "duration_ms")
    FINDINGS_FIELD_NUMBER: _ClassVar[int]
    ERRORS_FIELD_NUMBER: _ClassVar[int]
    DURATION_MS_FIELD_NUMBER: _ClassVar[int]
    findings: _containers.RepeatedCompositeFieldContainer[DriftFinding]
    errors: _containers.RepeatedScalarFieldContainer[str]
    duration_ms: int
    def __init__(self, findings: _Optional[_Iterable[_Union[DriftFinding, _Mapping]]] = ..., errors: _Optional[_Iterable[str]] = ..., duration_ms: _Optional[int] = ...) -> None: ...

class InfoRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class InfoResponse(_message.Message):
    __slots__ = ("name", "version", "ecosystems")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    ECOSYSTEMS_FIELD_NUMBER: _ClassVar[int]
    name: str
    version: str
    ecosystems: _containers.RepeatedScalarFieldContainer[Ecosystem]
    def __init__(self, name: _Optional[str] = ..., version: _Optional[str] = ..., ecosystems: _Optional[_Iterable[_Union[Ecosystem, str]]] = ...) -> None: ...

class DriftReport(_message.Message):
    __slots__ = ("pair", "findings", "score", "verdict", "explanation", "fired_rules")
    PAIR_FIELD_NUMBER: _ClassVar[int]
    FINDINGS_FIELD_NUMBER: _ClassVar[int]
    SCORE_FIELD_NUMBER: _ClassVar[int]
    VERDICT_FIELD_NUMBER: _ClassVar[int]
    EXPLANATION_FIELD_NUMBER: _ClassVar[int]
    FIRED_RULES_FIELD_NUMBER: _ClassVar[int]
    pair: ArtifactPair
    findings: _containers.RepeatedCompositeFieldContainer[DriftFinding]
    score: float
    verdict: Verdict
    explanation: str
    fired_rules: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, pair: _Optional[_Union[ArtifactPair, _Mapping]] = ..., findings: _Optional[_Iterable[_Union[DriftFinding, _Mapping]]] = ..., score: _Optional[float] = ..., verdict: _Optional[_Union[Verdict, str]] = ..., explanation: _Optional[str] = ..., fired_rules: _Optional[_Iterable[str]] = ...) -> None: ...

class ScoreRequest(_message.Message):
    __slots__ = ("pair", "findings")
    PAIR_FIELD_NUMBER: _ClassVar[int]
    FINDINGS_FIELD_NUMBER: _ClassVar[int]
    pair: ArtifactPair
    findings: _containers.RepeatedCompositeFieldContainer[DriftFinding]
    def __init__(self, pair: _Optional[_Union[ArtifactPair, _Mapping]] = ..., findings: _Optional[_Iterable[_Union[DriftFinding, _Mapping]]] = ...) -> None: ...
