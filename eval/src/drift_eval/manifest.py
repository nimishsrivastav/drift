"""Schema and validator for the evaluation manifests in eval/manifests.

Manifests hold metadata and hashes only, never payload bytes (.claude/rules/samples.md).
Validate them with: python -m drift_eval.manifest eval/manifests
"""

from __future__ import annotations

import datetime
import re
import sys
from collections.abc import Hashable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, Self
from urllib.parse import urlsplit

import yaml
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

SCHEMA_VERSION = 1
MAX_FREE_TEXT = 500

_NPM_NAME = re.compile(r"^(@[A-Za-z0-9~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$")
# Long unbroken base64 or hex. Hashes have their own fields, so free text never needs one.
_ENCODED_BLOB = re.compile(r"[A-Za-z0-9+/=_-]{64,}")


class Ecosystem(StrEnum):
    NPM = "npm"
    PYPI = "pypi"
    CRATES = "crates"


class CaseType(StrEnum):
    UPDATE_COMPROMISE = "update_compromise"
    DEPENDENCY_INJECTION = "dependency_injection"
    CI_PIPELINE = "ci_pipeline"
    DESTRUCTIVE = "destructive"
    NEW_MALICIOUS_PACKAGE = "new_malicious_package"
    SYNTHETIC = "synthetic"
    HARD_NEGATIVE = "hard_negative"
    ROUTINE = "routine"


class PayloadContext(StrEnum):
    INSTALL = "install"
    IMPORT = "import"
    CALL = "call"


class Technique(StrEnum):
    EXFIL = "exfil"
    DROPPER = "dropper"
    MINER = "miner"
    WALLET = "wallet"
    WORM = "worm"


class Trait(StrEnum):
    """What makes a benign update look scary (PLAN.md section 3, hard negatives)."""

    BINARY_DOWNLOADER = "binary_downloader"
    NATIVE_BUILD = "native_build"
    PREPARE_HOOK = "prepare_hook"
    TELEMETRY = "telemetry"
    ENV_CONFIG = "env_config"
    NPMRC_READER = "npmrc_reader"
    BIG_REFACTOR = "big_refactor"
    BUNDLED_OUTPUT = "bundled_output"


REAL_POSITIVES = frozenset(
    {
        CaseType.UPDATE_COMPROMISE,
        CaseType.DEPENDENCY_INJECTION,
        CaseType.CI_PIPELINE,
        CaseType.DESTRUCTIVE,
        CaseType.NEW_MALICIOUS_PACKAGE,
    }
)
NEGATIVES = frozenset({CaseType.HARD_NEGATIVE, CaseType.ROUTINE})

# Which case types each manifest may hold. Files other than these are not manifests.
MANIFEST_CASE_TYPES: dict[str, frozenset[CaseType]] = {
    "positives.yaml": REAL_POSITIVES,
    "hard_negatives.yaml": frozenset({CaseType.HARD_NEGATIVE}),
    "routine.yaml": frozenset({CaseType.ROUTINE}),
    "synthetic.yaml": frozenset({CaseType.SYNTHETIC}),
}
REQUIRED_MANIFESTS = ("positives.yaml", "hard_negatives.yaml", "routine.yaml")


def _check_https(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("must be an https URL")
    if parts.username or parts.password:
        raise ValueError("must not contain credentials")
    return value


def _check_free_text(value: str) -> str:
    if len(value) > MAX_FREE_TEXT:
        raise ValueError(f"is over {MAX_FREE_TEXT} characters")
    if _ENCODED_BLOB.search(value):
        raise ValueError("contains a long encoded string, and manifests must hold no payload bytes")
    return value


HttpsUrl = Annotated[str, AfterValidator(_check_https)]
FreeText = Annotated[str, StringConstraints(min_length=1), AfterValidator(_check_free_text)]
Version = Annotated[str, StringConstraints(pattern=r"^[0-9A-Za-z][0-9A-Za-z.+_-]*$")]
Sha1 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Sha512 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$")]
# y/n, as PLAN.md and the handling rules write them. YAML's true/false are rejected.
YesNo = Literal["y", "n"]


class _Strict(BaseModel):
    """Rejects unknown fields, so that a typo can't silently drop data."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class TarballHashes(_Strict):
    """Expected hashes, as hex. Only record one that the cited source states, and never one
    computed from a sample: with none, leave them empty and say why in the note."""

    sha1: Sha1 | None = None
    sha256: Sha256 | None = None
    sha512: Sha512 | None = None
    source: HttpsUrl | None = None
    note: FreeText | None = None

    @property
    def has_hash(self) -> bool:
        return any((self.sha1, self.sha256, self.sha512))

    @model_validator(mode="after")
    def _hashes_are_accounted_for(self) -> Self:
        if self.has_hash and not self.source:
            raise ValueError("a hash needs the source that states it")
        if not self.has_hash and not self.note:
            raise ValueError("with no hash, note must say why")
        return self


class Pair(_Strict):
    """One version pair. Which fields apply depends on case_type."""

    ecosystem: Ecosystem
    package: str
    benign_version: Version | None = None
    target_version: Version
    case_type: CaseType
    payload_context: PayloadContext | None = None
    techniques: list[Technique] = Field(default_factory=list)
    provenance_present: YesNo | None = None
    incident_date: datetime.date | None = None
    source_urls: list[HttpsUrl] = Field(default_factory=list)
    benign_tarball: TarballHashes | None = None
    target_tarball: TarballHashes | None = None
    sample_available: YesNo
    traits: list[Trait] = Field(default_factory=list)
    rationale: FreeText | None = None
    notes: FreeText | None = None

    @property
    def label(self) -> str:
        return f"{self.package} {self.benign_version or '(new)'} -> {self.target_version}"

    @model_validator(mode="after")
    def _rules_for_case_type(self) -> Self:
        problems = [*self._version_problems(), *self._hash_problems()]
        if self.case_type in REAL_POSITIVES:
            problems += self._real_positive_problems()
        elif self.case_type in NEGATIVES:
            problems += self._negative_problems()
        elif self.payload_context is None:
            problems.append("synthetic needs payload_context")
        if self.case_type is not CaseType.HARD_NEGATIVE and self.traits:
            problems.append("only hard_negative may list traits")
        if self.ecosystem is Ecosystem.NPM and not _NPM_NAME.match(self.package):
            problems.append(f"invalid npm package name {self.package!r}")
        if self.incident_date and self.incident_date > datetime.datetime.now(datetime.UTC).date():
            problems.append("incident_date is in the future")
        if problems:
            raise ValueError("; ".join(problems))
        return self

    def _version_problems(self) -> list[str]:
        if self.case_type is CaseType.NEW_MALICIOUS_PACKAGE:
            return ["new_malicious_package has no benign_version"] if self.benign_version else []
        if not self.benign_version:
            return ["benign_version is required"]
        if self.benign_version == self.target_version:
            return ["benign_version and target_version are the same"]
        return []

    def _hash_problems(self) -> list[str]:
        problems = []
        if self.benign_version and not self.benign_tarball:
            problems.append("benign_tarball is required with a benign_version")
        if not self.benign_version and self.benign_tarball:
            problems.append("benign_tarball needs a benign_version")
        if self.case_type is not CaseType.SYNTHETIC and not self.target_tarball:
            problems.append("target_tarball is required")
        # A recovered file must be checked against a hash before use, which needs one to exist.
        target_hash = self.target_tarball is not None and self.target_tarball.has_hash
        if (
            self.case_type is not CaseType.SYNTHETIC
            and self.sample_available == "y"
            and not target_hash
        ):
            problems.append("sample_available: y needs a target_tarball hash to verify it against")
        return problems

    def _real_positive_problems(self) -> list[str]:
        problems = []
        if self.payload_context is None:
            problems.append("payload_context is required")
        # A destructive payload need not fit any of the technique tags.
        if not self.techniques and self.case_type is not CaseType.DESTRUCTIVE:
            problems.append("at least one technique is required")
        if self.incident_date is None:
            problems.append("incident_date is required")
        if not self.source_urls:
            problems.append("at least one source URL is required")
        return problems

    def _negative_problems(self) -> list[str]:
        problems = []
        if self.payload_context is not None or self.techniques or self.incident_date:
            problems.append("a negative has no payload_context, techniques or incident_date")
        if self.sample_available != "y":
            problems.append("a negative comes from the registry, so sample_available must be y")
        if self.provenance_present is None:
            problems.append("provenance_present is required, because the registry states it")
        for name, tarball in (("benign", self.benign_tarball), ("target", self.target_tarball)):
            if tarball is not None and not tarball.has_hash:
                problems.append(f"{name}_tarball needs a hash, because the registry publishes it")
        if self.case_type is CaseType.HARD_NEGATIVE:
            if not self.traits:
                problems.append("hard_negative needs at least one trait")
            if not self.rationale:
                problems.append("hard_negative needs a rationale")
            if not self.source_urls:
                problems.append("hard_negative needs at least one source URL")
        return problems


class Manifest(_Strict):
    schema_version: Literal[1]
    pairs: list[Pair]


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate keys, which PyYAML otherwise lets overwrite each other."""


def _construct_unique_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=True)
        if isinstance(key, Hashable):
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            seen.add(key)
    mapping: dict[Any, Any] = loader.construct_mapping(node, deep=True)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


@dataclass(frozen=True)
class Problem:
    """One thing wrong with a manifest."""

    file: str
    where: str
    message: str

    def __str__(self) -> str:
        return (
            f"{self.file}: {self.where}: {self.message}"
            if self.where
            else (f"{self.file}: {self.message}")
        )


def _describe(file: str, raw: Any, error: ValidationError) -> list[Problem]:
    problems = []
    for item in error.errors():
        location = item["loc"]
        where = ".".join(str(part) for part in location)
        # Name the pair as well as its index, which is easier to find in a long file.
        if len(location) >= 2 and location[0] == "pairs" and isinstance(raw, dict):
            pairs = raw.get("pairs")
            index = location[1]
            if isinstance(pairs, list) and isinstance(index, int) and index < len(pairs):
                entry = pairs[index]
                if isinstance(entry, dict):
                    where += f" ({entry.get('package')} {entry.get('target_version')})"
        problems.append(Problem(file, where, str(item["msg"]).removeprefix("Value error, ")))
    return problems


def load_manifest(path: Path) -> tuple[Manifest | None, list[Problem]]:
    """Reads one manifest, returning it or the problems that stopped it from loading."""
    file = path.name
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        return None, [Problem(file, "", f"cannot read: {error.strerror}")]
    except UnicodeDecodeError:
        return None, [Problem(file, "", "is not valid UTF-8")]
    try:
        # A SafeLoader subclass: it builds plain data and can't construct arbitrary objects.
        raw = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506
    except yaml.YAMLError as error:
        return None, [Problem(file, "", f"invalid YAML: {error}")]
    try:
        manifest = Manifest.model_validate(raw)
    except ValidationError as error:
        return None, _describe(file, raw, error)

    allowed = MANIFEST_CASE_TYPES[file]
    problems = [
        Problem(
            file, f"pairs.{index} ({pair.label})", f"case_type {pair.case_type} doesn't belong here"
        )
        for index, pair in enumerate(manifest.pairs)
        if pair.case_type not in allowed
    ]
    return manifest, problems


def _cross_file_problems(manifests: dict[str, Manifest]) -> list[Problem]:
    """Finds repeated pairs, and any version labeled both malicious and benign."""
    problems = []
    seen: dict[tuple[str, str, str | None, str], str] = {}
    malicious: dict[tuple[str, str, str], str] = {}
    for file, manifest in manifests.items():
        for pair in manifest.pairs:
            key = (pair.ecosystem, pair.package, pair.benign_version, pair.target_version)
            if key in seen:
                problems.append(Problem(file, pair.label, f"also listed in {seen[key]}"))
            seen.setdefault(key, file)
            if pair.case_type in REAL_POSITIVES:
                malicious[(pair.ecosystem, pair.package, pair.target_version)] = file

    for file, manifest in manifests.items():
        for pair in manifest.pairs:
            versions = {"benign_version": pair.benign_version}
            if pair.case_type in NEGATIVES:
                versions["target_version"] = pair.target_version
            for field, version in versions.items():
                source = malicious.get((pair.ecosystem, pair.package, version or ""))
                if source:
                    problems.append(
                        Problem(file, pair.label, f"{field} {version} is malicious in {source}")
                    )
    return problems


def validate_directory(directory: Path) -> tuple[dict[str, Manifest], list[Problem]]:
    """Validates every manifest in a directory, returning what loaded and all problems found."""
    manifests: dict[str, Manifest] = {}
    problems: list[Problem] = []
    for name in MANIFEST_CASE_TYPES:
        path = directory / name
        if not path.exists():
            if name in REQUIRED_MANIFESTS:
                problems.append(Problem(name, "", "is missing"))
            continue
        manifest, found = load_manifest(path)
        problems += found
        if manifest is not None:
            manifests[name] = manifest
    for path in sorted(directory.glob("*.y*ml")):
        if path.name not in MANIFEST_CASE_TYPES:
            problems.append(Problem(path.name, "", "is not a known manifest"))
    problems += _cross_file_problems(manifests)
    return manifests, problems


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python -m drift_eval.manifest <manifest directory>", file=sys.stderr)
        return 2
    manifests, problems = validate_directory(Path(argv[0]))
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print(f"{len(problems)} problem(s) found", file=sys.stderr)
        return 1
    for name, manifest in manifests.items():
        print(f"{name}: {len(manifest.pairs)} pairs")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
