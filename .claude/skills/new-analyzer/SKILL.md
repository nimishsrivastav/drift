---
name: new-analyzer
description: Scaffold a new drift analyzer service (service skeleton, registry entry, compose service, golden test). Use when adding an analyzer that implements the Analyzer gRPC contract.
argument-hint: "<name> <go|rust|python>"
---

# Scaffold an analyzer: $ARGUMENTS

Language roles are fixed by `CLAUDE.md`: Rust for anything that parses attacker-controlled bytes, Go for
metadata and registry I/O, Python for scoring and ML. If the requested language conflicts, stop and ask.

1. **Service skeleton.** Copy the closest existing analyzer:
   - Go: `analyzers/meta-go/`, added to `go.work`
   - Rust: `crates/trace-rs/`, picked up by the `crates/*` workspace glob
   - Python: `scorer/`, added to the uv workspace in the root `pyproject.toml`

   Implement `Analyzer.Info` (name, version, ecosystems) and `Analyzer.Analyze(ArtifactPair) -> AnalyzeResponse`.
   Never hand-edit `gen/`. Change `proto/` and run `just gen` instead, and never break the schema without a version bump.
2. **Registry entry.** Add `{name, endpoint}` to `orchestrator/config/analyzers.yaml`.
3. **Compose service.** Add a `Dockerfile` and a `deploy/docker-compose.yml` service on the internal network, with
   the tarball volume read-only.
4. **Golden test.** Add a test that runs `Analyze` on a pair from `fixtures/` and compares against a committed golden file.
5. **CI.** Add the component to the matrix in `.github/workflows/ci.yml`, and to Dependabot if it adds a new manifest.
6. **Verify.** `just gen && just build && just test && just lint`, then `just up` and confirm the orchestrator logs
   the new analyzer's `Info`.

Safety: analyzers only parse. They never execute package code, and archives are extracted only through `safe-unpack`.
