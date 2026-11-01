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
