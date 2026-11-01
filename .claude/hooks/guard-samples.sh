#!/usr/bin/env bash
# PreToolUse (Bash) guard: enforces CLAUDE.md safety rule 3.
#
# Blocks any Bash command that references eval/data/samples, unless the whole
# command is one `docker run` that selects the gVisor runtime as a docker option.
# Exit 2 tells Claude Code to block the call and show stderr as the reason.
#
# This is a guard rail against mistakes, not a security boundary: a shell command
# can always build a path at runtime (variables, base64, ...). Fails closed if the
# hook input cannot be parsed.

set -u

deny() {
  printf 'guard-samples: BLOCKED: %s\n' "$1" >&2
  printf 'Malware samples may only be touched via a single `docker run --runtime=runsc ...`. See CLAUDE.md safety rule 3.\n' >&2
  exit 2
}

command -v jq >/dev/null 2>&1 || deny "jq is not installed, so the command cannot be inspected"

input="$(cat)"
cmd="$(printf '%s' "$input" | jq -er '.tool_input.command // empty' 2>/dev/null)" \
  || deny "could not parse the hook input"
[ -n "$cmd" ] || exit 0

# Remove quotes and backslashes so that eval/"data"/sam\ples still matches.
flat="$(printf '%s' "$cmd" | tr -d "\"'\\\\")"

# Does the command reach the samples directory? Covers the literal path, repeated
# slashes, and ./ segments, globs after eval/data/, and entering eval/data first.
references_samples() {
  printf '%s' "$flat" | grep -Eq \
    -e 'eval/+(\./+)*data/+(\./+)*samples' \
    -e 'eval/+(\./+)*data/+(\./+)*[a-z]*[*?[]' \
    -e 'eval/+(\./+)*[a-z]*[*?[]' \
    -e '(^|[^[:alnum:]_/.-])cd[[:space:]]+(\./+)?eval(/+data)?/*([[:space:];&|]|$)'
}

references_samples || exit 0

# From here the command touches samples: it must be exactly one sandboxed docker run.

# Reject anything that could chain a second command or redirect around the docker run.
case "$cmd" in
  *';'* | *'&'* | *'|'* | *'`'* | *'$('* | *'>'* | *'<'* | *$'\n'*)
    deny "command references eval/data/samples and uses shell chaining or redirection"
    ;;
esac

read -r -a tokens <<<"$flat"
if [ "${tokens[0]:-}" != "docker" ] || [ "${tokens[1]:-}" != "run" ]; then
  deny "command references eval/data/samples and is not a docker run"
fi

# Walk docker's own options, stopping at the image name, so a --runtime=runsc passed
# to the container's command does not count. An unknown option that takes a separate
# value makes its value look like the image, which fails closed.
runtime=""
i=2
while [ "$i" -lt "${#tokens[@]}" ]; do
  t="${tokens[$i]}"
  case "$t" in
    --privileged | --privileged=true | --pid=host | --ipc=host | --uts=host | --userns=host | --cap-add=* | --device=* | --security-opt=*)
      deny "sandbox-weakening docker option: $t"
      ;;
    --cap-add | --device | --security-opt)
      deny "sandbox-weakening docker option: $t"
      ;;
    --network=host | --net=host)
      deny "sandbox-weakening docker option: $t"
      ;;
    --network | --net)
      i=$((i + 1))
      [ "${tokens[$i]:-}" != "host" ] || deny "sandbox-weakening docker option: $t host"
      ;;
    --runtime=*)
      runtime="${t#--runtime=}"
      ;;
    --runtime)
      i=$((i + 1))
      runtime="${tokens[$i]:-}"
      ;;
    -v | --volume | --mount | --name | -e | --env | --env-file | -w | --workdir | -u | --user | --entrypoint | --tmpfs | -l | --label | --memory | -m | --cpus | --pids-limit | --ulimit | --dns | --hostname | -h)
      i=$((i + 1))
      ;;
    -*)
      ;;
    *)
      break
      ;;
  esac
  i=$((i + 1))
done

[ "$runtime" = "runsc" ] || deny "docker run must select --runtime=runsc before the image name (got: '${runtime:-none}')"

exit 0
