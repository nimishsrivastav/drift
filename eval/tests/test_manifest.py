from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from drift_eval.manifest import (
    REQUIRED_MANIFESTS,
    load_manifest,
    main,
    validate_directory,
)

SHA512 = "a" * 128
REGISTRY = "https://registry.npmjs.org/demo/1.0.0"
ADVISORY = "https://example.com/advisory"


def registry_tarball() -> dict[str, Any]:
    return {"sha512": SHA512, "source": REGISTRY}


def positive(**overrides: Any) -> dict[str, Any]:
    pair: dict[str, Any] = {
        "ecosystem": "npm",
        "package": "demo",
        "benign_version": "1.0.0",
        "target_version": "1.0.1",
        "case_type": "update_compromise",
        "payload_context": "install",
        "techniques": ["exfil"],
        "provenance_present": "n",
        "incident_date": "2024-01-02",
        "source_urls": [ADVISORY],
        "benign_tarball": registry_tarball(),
        "target_tarball": {"note": "no source states a hash"},
        "sample_available": "n",
    }
    return {**pair, **overrides}


def routine(**overrides: Any) -> dict[str, Any]:
    pair: dict[str, Any] = {
        "ecosystem": "npm",
        "package": "other",
        "benign_version": "2.0.0",
        "target_version": "2.0.1",
        "case_type": "routine",
        "provenance_present": "n",
        "benign_tarball": registry_tarball(),
        "target_tarball": registry_tarball(),
        "sample_available": "y",
    }
    return {**pair, **overrides}


def hard_negative(**overrides: Any) -> dict[str, Any]:
    pair = routine(
        package="scary",
        case_type="hard_negative",
        traits=["binary_downloader"],
        rationale="Downloads a binary it declares, from its own release host.",
        source_urls=[ADVISORY],
    )
    return {**pair, **overrides}


def write_manifest(directory: Path, name: str, pairs: list[dict[str, Any]]) -> Path:
    path = directory / name
    path.write_text(yaml.safe_dump({"schema_version": 1, "pairs": pairs}), encoding="utf-8")
    return path


def problems_for(tmp_path: Path, name: str, pair: dict[str, Any]) -> list[str]:
    manifest, problems = load_manifest(write_manifest(tmp_path, name, [pair]))
    if problems:
        return [str(problem) for problem in problems]
    assert manifest is not None
    return []


@pytest.mark.parametrize(
    ("name", "pair"),
    [
        ("positives.yaml", positive()),
        ("positives.yaml", positive(target_tarball={"sha1": "b" * 40, "source": ADVISORY})),
        ("positives.yaml", positive(target_tarball={"sha256": "c" * 64, "source": ADVISORY})),
        (
            "positives.yaml",
            positive(sample_available="y", target_tarball={"sha512": SHA512, "source": ADVISORY}),
        ),
        ("positives.yaml", positive(package="@scope/demo", provenance_present=None)),
        ("positives.yaml", positive(case_type="destructive", techniques=[])),
        ("positives.yaml", positive(case_type="dependency_injection", payload_context="import")),
        ("positives.yaml", positive(case_type="ci_pipeline", provenance_present="y")),
        (
            "positives.yaml",
            positive(case_type="new_malicious_package", benign_version=None, benign_tarball=None),
        ),
        ("positives.yaml", positive(benign_tarball={"note": "predecessor is gone"})),
        ("routine.yaml", routine()),
        ("routine.yaml", routine(package="JSONStream")),
        ("hard_negatives.yaml", hard_negative()),
        ("hard_negatives.yaml", hard_negative(notes="Checked against the release notes.")),
        (
            "synthetic.yaml",
            {
                "ecosystem": "npm",
                "package": "fixture-base",
                "benign_version": "1.0.0",
                "target_version": "1.0.1-postinstall",
                "case_type": "synthetic",
                "payload_context": "install",
                "techniques": ["dropper"],
                "benign_tarball": {"note": "built from fixtures/"},
                "sample_available": "y",
            },
        ),
    ],
)
def test_valid_pairs(tmp_path: Path, name: str, pair: dict[str, Any]) -> None:
    assert problems_for(tmp_path, name, pair) == []


@pytest.mark.parametrize(
    ("name", "pair", "expected"),
    [
        # A typo must not silently drop data.
        ("positives.yaml", positive(sample_availble="n"), "Extra inputs"),
        # YAML reads an unquoted 1.10 as the float 1.1.
        ("positives.yaml", positive(target_version=1.10), "valid string"),
        ("positives.yaml", positive(package=True), "valid string"),
        ("positives.yaml", positive(target_version="1.0.1 "), "pattern"),
        ("positives.yaml", positive(target_version="../evil"), "pattern"),
        ("positives.yaml", positive(package="../evil"), "invalid npm package name"),
        ("positives.yaml", positive(ecosystem="maven"), "npm"),
        ("positives.yaml", positive(case_type="unknown"), "update_compromise"),
        ("positives.yaml", positive(payload_context="runtime"), "install"),
        ("positives.yaml", positive(techniques=["ransom"]), "exfil"),
        # y/n only, as the plan and the handling rules write them.
        ("positives.yaml", positive(sample_available=True), "'y' or 'n'"),
        ("positives.yaml", positive(provenance_present=False), "'y' or 'n'"),
        ("positives.yaml", positive(sample_available="yes"), "'y' or 'n'"),
        # Rules for real positives.
        ("positives.yaml", positive(payload_context=None), "payload_context is required"),
        ("positives.yaml", positive(techniques=[]), "at least one technique"),
        ("positives.yaml", positive(incident_date=None), "incident_date is required"),
        ("positives.yaml", positive(incident_date="2999-01-01"), "in the future"),
        ("positives.yaml", positive(incident_date="soon"), "date"),
        ("positives.yaml", positive(source_urls=[]), "at least one source URL"),
        ("positives.yaml", positive(benign_version=None), "benign_version is required"),
        ("positives.yaml", positive(target_version="1.0.0"), "are the same"),
        (
            "positives.yaml",
            positive(case_type="new_malicious_package"),
            "has no benign_version",
        ),
        ("positives.yaml", positive(target_tarball=None), "target_tarball is required"),
        ("positives.yaml", positive(benign_tarball=None), "benign_tarball is required"),
        ("positives.yaml", positive(traits=["telemetry"]), "only hard_negative"),
        # Hashes: cited, well formed, or explained.
        ("positives.yaml", positive(target_tarball={}), "note must say why"),
        (
            "positives.yaml",
            positive(target_tarball={"sha512": SHA512}),
            "needs the source",
        ),
        (
            "positives.yaml",
            positive(target_tarball={"sha512": "A" * 128, "source": ADVISORY}),
            "pattern",
        ),
        (
            "positives.yaml",
            positive(target_tarball={"sha512": "a" * 127, "source": ADVISORY}),
            "pattern",
        ),
        (
            "positives.yaml",
            positive(target_tarball={"sha256": "a" * 128, "source": ADVISORY}),
            "pattern",
        ),
        ("positives.yaml", positive(sample_available="y"), "to verify it against"),
        # URLs.
        ("positives.yaml", positive(source_urls=["http://example.com"]), "https URL"),
        ("positives.yaml", positive(source_urls=["file:///etc/passwd"]), "https URL"),
        ("positives.yaml", positive(source_urls=["https://u:p@example.com"]), "credentials"),
        # Manifests hold no payload bytes.
        ("positives.yaml", positive(notes="x" * 501), "over 500"),
        ("positives.yaml", positive(notes="payload " + "QUJD" * 20), "long encoded"),
        (
            "positives.yaml",
            positive(target_tarball={"note": "f" * 64}),
            "long encoded",
        ),
        # Rules for negatives.
        ("routine.yaml", routine(sample_available="n"), "must be y"),
        ("routine.yaml", routine(provenance_present=None), "provenance_present is required"),
        ("routine.yaml", routine(payload_context="call"), "a negative has no"),
        ("routine.yaml", routine(techniques=["exfil"]), "a negative has no"),
        ("routine.yaml", routine(incident_date="2024-01-01"), "a negative has no"),
        ("routine.yaml", routine(target_tarball={"note": "unknown"}), "needs a hash"),
        ("routine.yaml", routine(benign_tarball={"note": "unknown"}), "needs a hash"),
        ("hard_negatives.yaml", hard_negative(traits=[]), "at least one trait"),
        ("hard_negatives.yaml", hard_negative(traits=["bogus"]), "binary_downloader"),
        ("hard_negatives.yaml", hard_negative(rationale=None), "needs a rationale"),
        ("hard_negatives.yaml", hard_negative(source_urls=[]), "at least one source URL"),
        # Each file holds only its own kind of pair.
        ("positives.yaml", routine(), "doesn't belong here"),
        ("routine.yaml", positive(), "doesn't belong here"),
        ("routine.yaml", hard_negative(), "doesn't belong here"),
        ("hard_negatives.yaml", routine(), "doesn't belong here"),
    ],
)
def test_invalid_pairs(tmp_path: Path, name: str, pair: dict[str, Any], expected: str) -> None:
    problems = problems_for(tmp_path, name, pair)
    assert problems, "the pair was accepted"
    assert any(expected in problem for problem in problems), problems


HAND_WRITTEN = """\
schema_version: 1
pairs:
  - ecosystem: npm
    package: demo
    benign_version: "1.0.0"
    target_version: "1.0.1"
    case_type: update_compromise
    payload_context: install
    techniques: [exfil]
    provenance_present: {provenance}
    incident_date: 2024-01-02
    source_urls:
      - https://example.com/advisory
    benign_tarball:
      note: Unknown.
    target_tarball:
      note: Unknown.
    sample_available: {sample}
"""


# safe_dump quotes y and n, so the other tests can't show that the plain form people write works.
def test_hand_written_yaml(tmp_path: Path) -> None:
    path = tmp_path / "positives.yaml"
    path.write_text(HAND_WRITTEN.format(provenance="y", sample="n"), encoding="utf-8")
    manifest, problems = load_manifest(path)
    assert problems == []
    assert manifest is not None
    pair = manifest.pairs[0]
    assert (pair.provenance_present, pair.sample_available) == ("y", "n")
    assert pair.incident_date == datetime.date(2024, 1, 2)


@pytest.mark.parametrize("value", ["yes", "no", "true", "false", "on", "off"])
def test_hand_written_boolean_words_are_rejected(tmp_path: Path, value: str) -> None:
    path = tmp_path / "positives.yaml"
    path.write_text(HAND_WRITTEN.format(provenance="y", sample=value), encoding="utf-8")
    manifest, problems = load_manifest(path)
    assert manifest is None
    assert any("'y' or 'n'" in str(problem) for problem in problems), problems


def test_problem_names_the_pair(tmp_path: Path) -> None:
    problems = problems_for(tmp_path, "positives.yaml", positive(techniques=[]))
    assert "pairs.0 (demo 1.0.1)" in problems[0]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("schema_version: 2\npairs: []\n", "schema_version"),
        ("pairs: []\n", "schema_version"),
        ("schema_version: 1\n", "pairs"),
        ("schema_version: 1\npairs: []\nextra: 1\n", "Extra inputs"),
        ("- just\n- a list\n", "valid dictionary"),
        ("", "valid dictionary"),
        ("schema_version: [unclosed\n", "invalid YAML"),
        # PyYAML would otherwise keep only the last one.
        ("schema_version: 1\npairs: []\npairs: []\n", "duplicate key"),
        # Python-object tags must never construct anything.
        ("schema_version: !!python/object/apply:os.getcwd []\npairs: []\n", "invalid YAML"),
    ],
)
def test_malformed_files(tmp_path: Path, text: str, expected: str) -> None:
    path = tmp_path / "positives.yaml"
    path.write_text(text, encoding="utf-8")
    manifest, problems = load_manifest(path)
    assert manifest is None
    assert any(expected in str(problem) for problem in problems), problems


def test_not_utf8(tmp_path: Path) -> None:
    path = tmp_path / "positives.yaml"
    path.write_bytes(b"\xff\xfe")
    manifest, problems = load_manifest(path)
    assert manifest is None
    assert "not valid UTF-8" in str(problems[0])


def complete_directory(
    tmp_path: Path,
    *,
    positives: list[dict[str, Any]] | None = None,
    negatives: list[dict[str, Any]] | None = None,
    routines: list[dict[str, Any]] | None = None,
) -> Path:
    write_manifest(tmp_path, "positives.yaml", positives or [])
    write_manifest(tmp_path, "hard_negatives.yaml", negatives or [])
    write_manifest(tmp_path, "routine.yaml", routines or [])
    return tmp_path


def test_valid_directory(tmp_path: Path) -> None:
    complete_directory(
        tmp_path, positives=[positive()], negatives=[hard_negative()], routines=[routine()]
    )
    manifests, problems = validate_directory(tmp_path)
    assert problems == []
    assert {name: len(m.pairs) for name, m in manifests.items()} == {
        "positives.yaml": 1,
        "hard_negatives.yaml": 1,
        "routine.yaml": 1,
    }


@pytest.mark.parametrize("missing", REQUIRED_MANIFESTS)
def test_missing_manifest(tmp_path: Path, missing: str) -> None:
    complete_directory(tmp_path)
    (tmp_path / missing).unlink()
    _, problems = validate_directory(tmp_path)
    assert [str(problem) for problem in problems] == [f"{missing}: is missing"]


def test_unknown_yaml_file(tmp_path: Path) -> None:
    complete_directory(tmp_path)
    (tmp_path / "positive.yaml").write_text("pairs: []\n", encoding="utf-8")
    _, problems = validate_directory(tmp_path)
    assert "not a known manifest" in str(problems[0])


@pytest.mark.parametrize(
    ("negatives", "routines", "expected"),
    [
        # The malicious version must not be anywhere in a benign manifest.
        (
            [],
            [routine(package="demo", benign_version="0.9.0", target_version="1.0.1")],
            "target_version 1.0.1 is malicious in positives.yaml",
        ),
        (
            [hard_negative(package="demo", benign_version="0.9.0", target_version="1.0.1")],
            [],
            "target_version 1.0.1 is malicious in positives.yaml",
        ),
        # Nor as the supposedly clean side of a later pair.
        (
            [],
            [routine(package="demo", benign_version="1.0.1", target_version="1.0.2")],
            "benign_version 1.0.1 is malicious in positives.yaml",
        ),
    ],
)
def test_malicious_version_in_a_benign_manifest(
    tmp_path: Path,
    negatives: list[dict[str, Any]],
    routines: list[dict[str, Any]],
    expected: str,
) -> None:
    complete_directory(tmp_path, positives=[positive()], negatives=negatives, routines=routines)
    _, problems = validate_directory(tmp_path)
    assert any(expected in str(problem) for problem in problems), problems


def test_same_version_in_another_package_is_fine(tmp_path: Path) -> None:
    complete_directory(
        tmp_path,
        positives=[positive()],
        routines=[routine(package="unrelated", benign_version="1.0.0", target_version="1.0.1")],
    )
    _, problems = validate_directory(tmp_path)
    assert problems == []


def test_positive_with_malicious_predecessor(tmp_path: Path) -> None:
    complete_directory(
        tmp_path,
        positives=[
            positive(),
            positive(benign_version="1.0.1", target_version="1.0.2"),
        ],
    )
    _, problems = validate_directory(tmp_path)
    assert any("benign_version 1.0.1 is malicious" in str(problem) for problem in problems)


def test_repeated_pair(tmp_path: Path) -> None:
    complete_directory(tmp_path, routines=[routine(), routine()])
    _, problems = validate_directory(tmp_path)
    assert any("also listed in routine.yaml" in str(problem) for problem in problems)


def test_pair_repeated_across_files(tmp_path: Path) -> None:
    complete_directory(tmp_path, negatives=[hard_negative(package="other")], routines=[routine()])
    _, problems = validate_directory(tmp_path)
    assert any("also listed in hard_negatives.yaml" in str(problem) for problem in problems)


def test_problems_in_one_file_do_not_hide_others(tmp_path: Path) -> None:
    complete_directory(tmp_path)
    (tmp_path / "positives.yaml").write_text("not: [valid\n", encoding="utf-8")
    write_manifest(tmp_path, "routine.yaml", [routine(sample_available="n")])
    _, problems = validate_directory(tmp_path)
    files = {problem.file for problem in problems}
    assert files == {"positives.yaml", "routine.yaml"}


def test_main(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    complete_directory(tmp_path, routines=[routine()])
    assert main([str(tmp_path)]) == 0
    assert "routine.yaml: 1 pairs" in capsys.readouterr().out

    write_manifest(tmp_path, "routine.yaml", [routine(sample_available="n")])
    assert main([str(tmp_path)]) == 1
    assert "1 problem(s) found" in capsys.readouterr().err

    assert main([]) == 2


COMMITTED = Path(__file__).resolve().parents[1] / "manifests"


def test_committed_manifests_validate() -> None:
    manifests, problems = validate_directory(COMMITTED)
    assert [str(problem) for problem in problems] == []
    assert set(REQUIRED_MANIFESTS) <= set(manifests)


# PLAN.md M2: at least 10 npm incidents across different case types, 50 routine, 10 hard negatives.
def test_committed_manifests_meet_the_seed_targets() -> None:
    manifests, _ = validate_directory(COMMITTED)
    positives = manifests["positives.yaml"].pairs
    assert len({pair.package for pair in positives if pair.ecosystem == "npm"}) >= 10
    assert len({pair.case_type for pair in positives}) >= 4
    assert {pair.payload_context for pair in positives} == {"install", "import", "call"}
    assert len(manifests["routine.yaml"].pairs) >= 50
    assert len(manifests["hard_negatives.yaml"].pairs) >= 10
