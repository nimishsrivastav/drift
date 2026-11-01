#!/usr/bin/env bash
# PostToolUse (Edit|Write): format the edited file by extension.
# Best effort: a missing formatter or a syntax error never fails the edit, because
# `just lint` is what enforces formatting.

set -u

command -v jq >/dev/null 2>&1 || exit 0
file="$(jq -r '.tool_input.file_path // empty' 2>/dev/null)"
[ -n "$file" ] && [ -f "$file" ] || exit 0

root="${CLAUDE_PROJECT_DIR:-$PWD}"
case "$file" in
  "$root"/gen/* | "$root"/eval/data/*) exit 0 ;; # generated code; samples are never touched
  "$root"/*) ;;
  *) exit 0 ;; # outside the repo
esac

case "$file" in
  *.go)
    command -v gofmt >/dev/null 2>&1 && gofmt -w "$file" >/dev/null 2>&1
    ;;
  *.rs)
    command -v rustfmt >/dev/null 2>&1 && rustfmt --edition 2024 "$file" >/dev/null 2>&1
    ;;
  *.py | *.pyi)
    (cd "$root" && uv run --quiet ruff format "$file") >/dev/null 2>&1
    ;;
esac

exit 0
