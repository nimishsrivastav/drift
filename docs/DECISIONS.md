# Design decisions

Non-obvious decisions, newest last. Format: date, decision, why.

## 2026-11-01: The sample guard requires one `docker run`, with the runtime set before the image

`guard-samples.sh` allows a command that references `eval/data/samples` only if the whole command is a single
`docker run` with no chaining or redirection, `--runtime=runsc` appears among docker's own options, and no
sandbox-weakening option is present.

Why: a plain substring check for `--runtime=runsc` would allow `docker run --runtime=runsc x; cat eval/data/samples/a.zip`
and `docker run img cat --runtime=runsc eval/data/samples/a.zip`. The hook is still a guard rail, not a security
boundary, because a shell command can build a path at runtime.

## 2026-11-01: Apache-2.0 licence

Why: permissive, widely accepted in security tooling, and includes a patent grant. Easy to change before the repo is public.

## 2026-11-01: Enum values are prefixed, unlike the draft schema in PLAN.md

`NPM` became `ECOSYSTEM_NPM`, `INSTALL` became `EXEC_CONTEXT_INSTALL`, and so on. Other `buf` STANDARD lint rules are
kept, except the service and RPC naming rules.

Why: protobuf enum values share the package scope, so unprefixed names like `INSTALL` and `CALL` collide easily, and this
is hard to change once analyzers depend on it. The excepted rules (`SERVICE_SUFFIX`, `RPC_REQUEST_STANDARD_NAME`,
`RPC_RESPONSE_STANDARD_NAME`, `RPC_REQUEST_RESPONSE_UNIQUE`) would force renaming the contract that `CLAUDE.md` fixes:
`Analyzer.Analyze(ArtifactPair) -> AnalyzeResponse`.

## 2026-11-01: `tonic-prost-build` instead of `tonic-build`

Why: since tonic 0.14, prost code generation lives in `tonic-prost-build`. `tonic-build` alone no longer compiles protos.

## 2026-11-01: `gen/` holds hand-written packaging files beside the generated code

`gen/go/go.mod` and `gen/python/pyproject.toml` are hand-written. `just gen` deletes only `gen/go/drift` and
`gen/python/src/drift`, and `buf.gen.yaml` does not use `clean: true`.

Why: Go and Python each need the stubs to be an importable package. `clean: true` would delete the packaging files.

## 2026-11-01: Pinned remote `buf` plugins

Why: remote plugins need no local plugin install and give the same output on any machine. CI regenerates the stubs and
fails on a diff, so a stale `gen/` cannot merge. The Python plugin versions track the `protobuf` runtime, which rejects
stubs from a newer major version, so raise them together.

## 2026-11-01: The scorer also serves `Analyzer.Info`

Why: M1 requires a hello-world `Analyzer` in each language, and the scorer is the only Python service. Sharing its process
avoids a throwaway service. It should be listed separately from real analyzers once M7 adds `Scorer.Score`, so that the
orchestrator does not send it `Analyze` calls.

## 2026-11-01: Plaintext gRPC on a private compose network

Why: all services share one internal Docker network with no published ports and no route out, so TLS adds certificate
handling without protecting a real boundary in M1. Revisit if services ever run across hosts. M2 must give the orchestrator
registry access through a separate network, not by removing `internal: true`.

## 2026-11-01: The Docker build context is an allowlist

`.dockerignore` excludes everything and then re-includes source paths.

Why: a denylist fails open. With an allowlist, nothing under `eval/data` can reach the daemon or an image, whatever new
files appear (`CLAUDE.md` rule 3). Base images are also pinned by digest, because this project exists to catch mutable
upstream artifacts.

## 2026-11-01: Module path `github.com/nimishsrivastav/drift`, repo in `~/Documents/drift-oss-package`

The Go module path assumes the GitHub repo is named `drift`. The checkout is not at the `~/drift` that `CLAUDE.md` mentions,
but it is on the WSL filesystem, which is the part of that rule that matters.

## 2026-11-01: The default "previous version" is by semver, not publish time

With no `--from`, the predecessor is the highest semver below the target that was published before it, skipping
prereleases when the target is stable. With no such version, the job runs in new-package mode.

Why: publish order compares a backport with an unrelated major line (3.4.2 published after 4.0.0 would diff against
4.0.0). The publish-time filter stops a later backport to an older line from counting as a predecessor.

## 2026-11-01: Package-named tags win over `vX.Y.Z`, the reverse of the order in PLAN.md

Tags are tried as `name@X.Y.Z`, then the unscoped `name@X.Y.Z` for a scoped package, then `vX.Y.Z`, then `X.Y.Z`.

Why: in a monorepo a bare `v1.2.3` may belong to a different package, and comparing a tarball against the wrong commit
would produce false tarball-only findings. The extra unscoped form is a common monorepo convention.

## 2026-11-01: Repo resolution shells out to `git`, restricted to HTTPS on three forges

`repository` is attacker-controlled, so URLs are rewritten to `https://` on github.com, gitlab.com or bitbucket.org, and
anything else stays unresolved. Git runs from an environment built from nothing, with `GIT_ALLOW_PROTOCOL=https`, no
hooks, submodules, symlinks or host config. Checkouts drop `.git` and live under `<url hash>/<commit>`.

Why: the host allowlist stops a package aiming git at internal addresses, and the protocol restriction stops transport
helpers such as `ext::`, which run commands. Git itself is more robust against hostile remotes than a library, and these
options are its documented controls. The cost is that packages hosted elsewhere get no tarball-vs-repo diff, and that the
orchestrator image needs git. Tags can move, so the commit we actually checked out is what gets recorded.

## 2026-11-01: A tarball is stored as an opaque blob and never unpacked by the orchestrator

Why: parsing archives belongs to Rust (`CLAUDE.md`). `drift analyze` may fetch a malicious version if a registry still
serves it, and that is safe only because the file stays compressed and read-only (0444) outside any repo checkout. Real
samples kept for evaluation still follow rule 3.

## 2026-11-01: The job store is SQLite, through the pure-Go `modernc.org/sqlite`

Full messages are stored as protojson, with only the columns we filter on broken out. A sub-job's depth is derived from its
parent instead of being passed in, and a job has one report, which is never overwritten.

Why: `PLAN.md` allows SQLite or Postgres, and SQLite needs no extra service for a local CLI run. The images build with
`CGO_ENABLED=0`, which rules out the cgo driver. Deriving depth means it can't disagree with the parent, and a saved verdict
stays what was reported at the time, so tuning runs create new jobs. Revisit SQLite if watch mode needs several writers
across hosts.
