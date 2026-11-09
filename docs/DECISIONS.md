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

## 2026-11-01: A repo lookup failure doesn't fail the job, and `unresolved` doesn't say why

A missing or undownloadable tarball fails the job. Any repo error except cancellation records `repo_ref = "unresolved"` and
logs the reason. Each version uses the repository URL it declares itself, so a repo that moved between versions still resolves.

Why: plenty of benign releases have no tag, and static and dynamic analysis can still run without the source. The known gap
is that a transient network failure looks the same as a missing tag. `meta-go` must not treat `unresolved` as proof that a
tag is missing when it adds that signal in M7: it should distinguish the two, by re-checking or by a new field.

## 2026-11-01: Only the orchestrator has egress, and its image is Debian slim instead of distroless

The orchestrator joins a second network, `drift-egress`. `drift-internal` stays `internal: true`, and analyzers and the scorer
are only on that one. The job database has its own volume, so analyzers never see it. Tarballs and checkouts are readable
by analyzers because every service runs as uid 65532.

Why: the orchestrator needs the registry and the forges, and it is the one component that never parses package contents or
runs package code. The parsers are the likelier thing to be compromised, so they get no route out. Repo resolution needs git,
which distroless can't provide, so this image has a shell and a larger attack surface than the others. `drift-egress`
itself is unrestricted, not limited to the registry and the three forges: the URL checks are in the application, and M5's
sinkhole work covers sandbox egress, not this.

## 2026-11-01: Manifest schema additions beyond PLAN.md

`case_type` also has `hard_negative` and `routine`, and hard negatives add `traits` and `rationale`. Hashes are per tarball,
for the benign version too, and include `sha1`, a `source` and a `note`. `provenance_present` and `sample_available` stay
the `y`/`n` strings that the plan and handling rules use, and `true`/`false` are rejected.

Why: the plan's `case_type` values only describe positives, and metrics are reported per `case_type`, so negatives need
values too. Many advisories only state npm's SHA-1 `shasum`. The `source` makes every hash traceable to a citation, and the
`note` makes a missing hash an explicit statement rather than an oversight. `sample_available: y` requires a hash, because a
recovered file must be verified against one before use. The validator rejects duplicate keys and non-string versions,
because PyYAML otherwise keeps the last duplicate and reads `1.10` as the number 1.1, either of which silently corrupts the
dataset.

## 2026-11-01: Seeded incidents record only what a cited source states

16 npm incidents are seeded, and only axios has `sample_available: y`. Other incidents listed in the DataDog dataset stay `n`
with a note, because no cited source states their tarball hash. Sources give hashes of files inside the package, not of
the tarball, and OSV's origin `sha256` values identify source reports. M8 needs another way to get verifiable hashes, for
example from the dataset's own metadata, before those samples can be used.

`chalk`, `debug` and `rc` are held out: their sources establish that they were malicious but not when the payload runs, and
`payload_context` is required. `faker` and `@rspack/core` are also not seeded. Add them when a source settles the field.

Hard-negative rationales say only what registry metadata shows, because reading a tarball on the host is not allowed. M3's
analyzers can confirm the behavior each one implies. Each pair's trait was checked against the metadata of both versions.

## 2026-11-09: safe-unpack rejects rather than repairs, and never creates links

Any entry with `..`, a `.` or empty component, an absolute or drive-letter path, a control character, a backslash or a
non-UTF-8 name fails the whole archive, as does a regular file whose name ends in `/`, as do device files, fifos, sparse files, duplicate paths, and an entry under a path that is already a file
or a link. Symlinks and hardlinks are recorded in the manifest with their resolved target and never created on disk; one
whose target leaves the root fails the archive. Files are written with `O_EXCL` and mode 0644.

Why: a repaired path (say, `../x` turned into `x`) is a tree the archive didn't describe, and extractors repair in
different ways, which is room for an attacker to show the analyzer one thing and the installer another. Not creating links
makes write-through attacks impossible rather than merely checked, and npm doesn't extract links anyway (pacote filters
them out). Duplicates are rejected because extractors disagree on which copy wins. Rejection is not silence: static-rs
reports a rejected archive as an `archive_rejected` finding.

## 2026-11-09: safe-unpack parses tar extension headers itself

The `tar` crate runs in raw mode. GNU long-name and long-link bodies and pax headers are read by safe-unpack, each capped at
64 KiB before it is read into memory. A pax `size` that differs from the header size, a pax sparse file, and a pax global
header that sets a path, link or size are refused. A NUL inside a GNU long name is refused. Concatenated gzip members are
all read.

Why: in its default mode the crate reads extension bodies of any declared size into memory. Raw mode follows the header
size, so honouring a pax size override would mean reading the stream differently from node-tar; refusing it costs nothing
at our file-size limits. Global headers are applied by some extractors and ignored by others. npm's gunzip reads every
member, so a decoder that stopped after the first would miss appended content.

## 2026-11-09: Zip is limited to stored and deflated entries, without zip64

The end-of-central-directory record is read before the `zip` crate loads the central directory, so the entry limit holds
for a crafted directory. Encrypted entries and other compression methods are refused, and the ratio limit is measured
against the whole archive because zip entries may share compressed data.

Why: wheels use deflate, and nothing within our size limits needs zip64. Every extra method is attack surface for no gain.

## 2026-11-09: Extraction limits

Library defaults: 256 MiB archive, 1 GiB total and 256 MiB per file, 100,000 entries, depth 64, 4 KiB paths, and a 200:1
ratio enforced once 8 MiB has been decompressed. static-rs lowers the total to 512 MiB per version and runs two analyses at
once in a 2.25 GiB tmpfs. The paths remembered for duplicate checks are capped at 32 MiB in total. Every limit is checked on bytes actually produced, not on sizes the archive declares.

Why: the largest legitimate npm packages are a few hundred MiB unpacked and compress at most a few dozen to one; bombs are
in the thousands. The grace keeps small, very compressible files such as lockfiles from tripping the ratio.

## 2026-11-09: static-rs views a tarball the way npm installs it

The first path component is stripped whatever it is called, files directly at the top are dropped, a later entry for the
same installed path replaces an earlier one, and links are left out. More than one top-level directory is itself a finding,
`tarball_multiple_roots`.

Why: pacote extracts with `strip: 1`, so `package/index.js` and `evil/index.js` both install as `index.js`. Analyzing the
archive's own paths would miss that the second replaces the first.

## 2026-11-09: Tarball-vs-repo compares only what changed, and allowlists build output only where the repo lacks it

Only files added or changed since the old tarball are compared, so a file published the same way for years doesn't
reappear in every report. Paths under `dist/`, `lib/`, `build/` and similar, and suffixes such as `.min.js`, `.map` and
`.d.ts`, are skipped only when the repo doesn't track that directory or file; if it does, they are compared like anything
else. `package.json`, README, LICENSE and CHANGELOG at the top are skipped, because publish tooling rewrites them and
`package.json` changes are covered by the scripts diff. Line endings are ignored. When the new version's ref is unresolved,
the old version's checkout is used with half the confidence. When more than half the compared files differ, confidence is
halved again, because the checkout is probably the wrong commit.

Why: a blanket allowlist for `lib/` would hide a payload in a project that commits `lib/`, which is where the xz-style
divergence lives. The cost is that a package publishing compiled output into a directory the repo also uses gets some
noise, at low confidence.

## 2026-11-09: Install-hook weights, and npm's implicit `node-gyp rebuild`

`preinstall`, `install` and `postinstall` weigh 0.9; `prepare` and its pre/post hooks weigh 0.5, because npm runs them only
for git and local installs. A new `binding.gyp` with no declared `install` or `preinstall` counts as an added `install`
hook, because npm adds `node-gyp rebuild` by itself. Files a hook names (`node build.js`) get the `INSTALL` context; M4's
import graph will follow what they load.

## 2026-11-09: A failing analyzer never fails the job

The orchestrator calls every analyzer at once with its own timeout (5 minutes by default) and records each call in a new
`analyzer_runs` table as `ok`, `unimplemented` or `failed`, with its notes and duration. Findings are sanitized before
storage: the analyzer field is set to the configured name, `via_dependency` is cleared (roll-up is the orchestrator's job),
confidence is clamped to [0, 1], NaNs are dropped, and each analyzer is capped at 5,000 findings. Registry entries take a
`role`, and the scorer is discovered at startup but never sent `Analyze`. Without an analyzer config the CLI only ingests.

Why: meta-go and trace-rs are still stubs, and one analyzer being down shouldn't erase what the others found. A missing
result must still be visible, which is what the runs table is for; it also gives M8 its time-to-verdict numbers. An analyzer
is the likelier component to be compromised, so it must not be able to speak for another one or forge a dependency roll-up.

## 2026-11-09: M3's end-to-end incident is a synthetic fixture

PLAN.md names eslint-scope 3.7.1→3.7.2 "or another available incident". 3.7.2 was unpublished from npm, and no seeded
incident has a sample yet (only axios is `sample_available: y`, and real samples may only be unpacked inside a container).
`fixtures/npm/drift-fixture-install-hook` recreates the eslint-scope technique instead: an update adds a `postinstall` hook
running a new file, absent from the repo, that reads `~/.npmrc` and reports only its length to `sinkhole.invalid`.
`deploy/fixture-registry` serves it to the orchestrator as an npm registry, and `just demo-fixture` replays it.

Why: the end-to-end path (registry, ingest, store, gRPC, unpack, diff, findings) is what M3 has to prove, and a synthetic
fixture exercises all of it without a real sample on the host. Replaying real incidents is M8's job, in the sandbox.

## 2026-11-09: The fixture registry is its own Go module, outside go.work

Why: it writes tarballs, which needs `archive/tar` and `compress/gzip`, and the orchestrator module's test forbids those
imports to keep unpacking out of Go. It uses only the standard library, so it builds with `GOWORK=off` and doesn't make
every other Dockerfile copy one more module.

## 2026-11-09: Security review of the unpacker and static-rs

The `security-reviewer` agent found three high, five medium and three low issues; all are fixed, each with a test or attack
archive:

- **High, differentials that hid a payload from the analyzer but not from npm.** One zero block ended the archive for us
  but not for node-tar, so entries after it were invisible: the rest of the stream must now be zeros. `.` and empty
  components were normalized away before npm's `strip: 1`, so `./index.js` was dropped here and installed by npm: such
  paths are now rejected. Formats were detected from content, so a tar/zip polyglot could show us a benign zip: static-rs
  now accepts only tar for npm (`unpack_file_as`).
- **Medium.** A `package.json` serde_json refuses but npm accepts hid every install hook: it is now read leniently (BOM,
  invalid UTF-8, 16 MiB), and if it still fails, hooks are recovered from the raw text and a `manifest_unparseable`
  finding is reported. A pax path and a GNU long name on one entry are refused, since extractors pick different winners.
  The per-kind finding cap now keeps every install-time finding and ranks the rest by confidence, so junk files can't push
  the payload out; junk also no longer drives the wrong-ref heuristic. Files an install hook runs are never skipped by the
  tarball-vs-repo allowlists, and README/LICENSE-style names are skipped only with document extensions. The memory used for
  duplicate checks is bounded.
- **Low.** Errors and notes are escaped, the tmpfs covers the worst case, and a regular file named `dir/` is refused.
- **Speculative.** The zip end record must now be unique and end exactly at the end of the file, with no zip64 locator.

Deferred, because they concern later milestones:

- **Wheels (M9).** pip writes every member as a regular file, so a zip entry with symlink mode is code to pip, not a link.
  Zip names without the UTF-8 flag are cp437 to Python. The wheel path must handle both.
- **M4.** `EntryKind::Symlink.target` is resolved lexically, ignoring earlier links. It is safe only because links are
  never created or followed, so nothing may treat it as a trusted path.
- **M5.** Differential tests that list each attack archive with node-tar inside the sandbox would confirm the npm-side
  assumptions, which the review drew from memory of node-tar and pacote.
- **Accepted.** `tracked_by_repo` can learn whether a path exists outside the checkout through a symlinked directory in it.
  That is one boolean, in a read-only container, and git checkouts are made with symlinks disabled.

## 2026-11-09: Capability extraction walks the tree instead of running tree-sitter queries

PLAN.md puts the extractor's patterns in `capabilities/queries/*.scm`. They were written that way first, and a test with
20,000 nested IIFEs took 23 s in query matching against 0.2 s to parse: a query cursor keeps in-progress state per
ancestor, so its cost grows with size times nesting depth, and nesting is attacker-controlled. A time limit would only
let a payload hide by nesting deeper. Candidate nodes now come from one iterative pre-order walk that dispatches on node
kind (`capabilities::File::capture`), which is linear; the same test takes 0.7 s in a debug build. Classification was
always Rust code resolving names through the file's own bindings, so nothing else changed.

For the same reason nothing calls `Node::parent` per use (it is O(depth) in tree-sitter): whether code runs on load is
computed in one cursor walk that records the byte ranges of functions that don't, and every other walk is iterative or
capped (`MAX_EXPR_DEPTH`, `MAX_SCAN`).

## 2026-11-09: What counts as import-time, install-time and call-time

- **Install:** every file reachable from a file an install hook names, through any import. The script's own functions
  are what it calls, so all of its code counts, not just its top level.
- **Import:** top-level code in files reached from `main` (or `index.js`), `exports` and `module` through top-level
  imports only. A function is top level when it runs where it is defined: an IIFE (`(function(){})()`,
  `!function(){}()`, `.call(this)`), a class static block, or a callback passed to a call made at load. The callback rule
  over-approximates (a request handler registered at load is counted), which errs toward the stronger context; the
  scorer can discount it.
- **Call:** everything else, including a bare `require` of a capability module whose use can't be resolved. Evidence
  prefers a call over a bare load at the same context.

Module resolution is lexical over the tree's own file map, with Node's extension and `index` rules, bundled
`node_modules`, and one level of a nested `package.json` `main`. It never touches the disk or follows a link, which
settles the M4 caveat above about `EntryKind::Symlink.target`.

## 2026-11-09: The capability diff is per file, and changed code that can't be parsed is a finding

A `capability_added` finding is a (file, capability) pair new in `new`; for obfuscation the signal is part of the key, so
adding a decode→eval flow to a file that already had a long hash literal still shows. Confidence is halved when the old
package had the capability at the same or a stronger context elsewhere, which is what moved code looks like. A
capability that moved to a stronger context in the same file is `capability_context_escalated`. In new-package mode
every capability is reported.

Files are parsed once per content hash across both versions, in parallel (up to 4 threads), within a 64 MiB budget and
an 8 MiB per-file limit, with a 3 s parse deadline. Changed files are parsed first so that padding can't push the
payload out of the budget, and a changed file that wasn't analyzed (too large, too slow, over budget) becomes
`analysis_incomplete`, because code we couldn't inspect must not look clean. A release build analyzes a 4.7 MB package
against a changed predecessor in about 1 s (`just bench-static`).

Known gaps, left to the dynamic analyzer: data flow is intra-file and flow-insensitive (a decoder wrapped in a helper
function isn't followed), new uses of a capability a file already had don't show, and inline `node -e` hook scripts
aren't parsed.

## 2026-11-09: Dependency expansion

`depgraph.rs` reads `dependencies`, `optionalDependencies` and `peerDependencies` (optional peers excluded, since npm
doesn't install them), with npm's precedence, and classifies each spec as npm-package-arg does. `devDependencies` aren't
installed for consumers, so moving a package from them into `dependencies` counts as adding it. A range change on the
registry is routine and not reported; a change of source (registry to git or tarball, or a different alias target) is
`dependency_repointed`.

The orchestrator expands each registry or alias `dependency_added` into a new-package sub-job: depth at most 2, at most 20
per parent (most confident first), four at a time. Git, tarball and local sources have no registry version to fetch, and
bundled dependencies are already in the parent's tarball, so they are noted, not expanded. The version is the one npm
would install today (a dist-tag, else `latest` if it satisfies the range, else the highest match), resolved with
node-semver's range rules written on `x/mod/semver` rather than a new dependency. A finished new-package analysis of the
same version is reused if it was made at the same depth or shallower, since a deeper one expanded fewer levels. Child
findings are copied into the parent with `via_dependency` set, chained as `a@1.0.0 > b@2.0.0`, and what was expanded,
reused or skipped is the parent's `dependency-expansion` run. A dependency that fails is a note, never a failed parent.

Why "today" and not "as of the parent's publish": that is what a fresh install gets. For replaying an old incident whose
malicious dependency version has since been removed (M8), the sub-job fails and says so.
