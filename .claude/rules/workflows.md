---
paths:
  - ".github/workflows/**"
---

# GitHub Actions rules

- Pin every third-party action to a full 40-character commit SHA, with the version in a trailing
  comment: `uses: owner/action@<sha> # v1.2.3`. Tags and branches are mutable, so they are not allowed.
  Look the SHA up from the upstream repo; never write one from memory.
- Set top-level `permissions: {}` (or `contents: read`) and grant the minimum per job.
- Never use `pull_request_target`.
- No secrets in PR-triggered jobs.
- Set `persist-credentials: false` on `actions/checkout` unless a later step needs the token.
- Never interpolate `${{ github.event.* }}` or other untrusted values directly into `run:`.
  Pass them through `env:` and quote the variable.
- No samples in Actions: no `eval/data/` paths in artifacts, caches or checkouts (`CLAUDE.md` rule 3).
- Never install or execute package code under analysis in CI (`CLAUDE.md` rule 1).
- After changing a workflow, run `actionlint` and `zizmor .github/workflows/`. Fix every high-severity finding.
