# Fixtures

Synthetic benign and malicious packages for tests. Everything here is synthetic and clearly labeled as such, and payloads
may only target the sinkhole (`sinkhole.invalid`, a name that never resolves outside the M5 sandbox). Real samples never
go here, and no payload is copied from a real incident: each fixture recreates a technique. See `.claude/rules/samples.md`.

Static analyzers only parse these files. Nothing here is ever installed, imported or run outside the sandbox.

## Layout

`npm/<package>/<version>/` holds a version's files as they appear inside its tarball's `package/` directory. Tests and
the fixture registry (`deploy/fixture-registry/`) pack them into tarballs on the fly, so no archive is committed.
`npm/<package>/repo/` stands in for the source repository at the newest version's tag, for the tarball-vs-repo diff.

| Package | Versions | Technique |
|---|---|---|
| `drift-fixture-install-hook` | 1.0.0 → 1.0.1 | An update adds a `postinstall` hook running a new file that reads the npm config and reports to the sinkhole, published from a tree that differs from the repo (the eslint-scope 3.7.2 technique) |
| `drift-fixture-benign` | 1.0.0 → 1.0.1 | A routine refactor with an unchanged call-time HTTPS use; the benign baseline, with no capability findings |
| `drift-fixture-decode-eval` | 1.0.0 → 1.0.1 | The entry point decodes base64 and `eval`s it at import time (the flatmap-stream loader technique) |
| `drift-fixture-dep-inject` | 1.0.0 → 1.0.1 | An update adds only a dependency, `drift-fixture-evil-dep`, whose install hook carries the payload (the axios → plain-crypto-js technique) |
| `drift-fixture-evil-dep` | 1.0.0 | The injected dependency: a `postinstall` that reads the npm config, runs `uname` and looks up a sinkhole name |
