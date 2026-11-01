#!/usr/bin/env bash
# Tests for guard-samples.sh. Each case feeds a command through the hook as Claude Code
# would and checks the exit code (0 = allowed, 2 = blocked). Nothing is executed.
# Run with: just test-hooks

set -u

hook="$(dirname "$0")/guard-samples.sh"
fails=0

check() {
  local want="$1" cmd="$2" got
  jq -n --arg c "$cmd" '{tool_name:"Bash",tool_input:{command:$c}}' | "$hook" >/dev/null 2>&1
  got=$?
  if [ "$got" -eq "$want" ]; then
    printf 'ok    (%s) %s\n' "$got" "$cmd"
  else
    printf 'FAIL  (want %s, got %s) %s\n' "$want" "$got" "$cmd"
    fails=$((fails + 1))
  fi
}

# Acceptance criteria from PLAN.md M1.
check 2 'cat eval/data/samples/test.zip'
check 0 'docker run --runtime=runsc --rm -v ./eval/data/samples:/samples:ro analyzer:dev scan /samples/test.zip'

# Unrelated commands pass.
check 0 'ls -la'
check 0 'cargo test --workspace'
check 0 'cat eval/manifests/positives.yaml'
check 0 'cat eval/README.md'

# Tools other than cat.
check 2 'unzip -P infected eval/data/samples/a.zip'
check 2 'cp eval/data/samples/a.zip /mnt/c/Users/x/a.zip'
check 2 'git add -f eval/data/samples/a.zip'

# Path spelling tricks.
check 2 'cat ./eval/data/samples/a.zip'
check 2 'cat eval//data///samples/a.zip'
check 2 'cat eval/./data/./samples/a.zip'
check 2 'cat "eval/data/samples/a.zip"'
check 2 "cat eval/'data'/samples/a.zip"
check 2 'cat eval/data/sam\ples/a.zip'
check 2 'cat /home/me/repo/eval/data/samples/a.zip'

# Globs and changing directory first.
check 2 'cat eval/data/s*/a.zip'
check 2 'cat eval/data/*/a.zip'
check 2 'cat eval/d*/samples/a.zip'
check 2 'cd eval/data && cat samples/a.zip'
check 2 'cd eval && cat data/samples/a.zip'

# Chaining onto an otherwise allowed docker run.
check 2 'docker run --runtime=runsc --rm img; cat eval/data/samples/a.zip'
check 2 'docker run --runtime=runsc --rm -v ./eval/data/samples:/s img && cat eval/data/samples/a.zip'
check 2 'docker run --runtime=runsc --rm -v ./eval/data/samples:/s img | tee out.txt'
check 2 'docker run --runtime=runsc --rm -v ./eval/data/samples:/s img $(cat eval/data/samples/a.zip)'
check 2 'docker run --runtime=runsc --rm -v ./eval/data/samples:/s img > out.txt'

# docker run without the gVisor runtime.
check 2 'docker run --rm -v ./eval/data/samples:/s img'
check 2 'docker run --runtime=runc --rm -v ./eval/data/samples:/s img'
check 2 'docker run --rm -v ./eval/data/samples:/s img --runtime=runsc'
check 2 'docker run img cat --runtime=runsc eval/data/samples/a.zip'
check 2 'docker exec box cat eval/data/samples/a.zip'
check 2 'echo docker run --runtime=runsc eval/data/samples'

# gVisor runtime, but with the sandbox weakened.
check 2 'docker run --runtime=runsc --privileged -v ./eval/data/samples:/s img'
check 2 'docker run --runtime=runsc --network=host -v ./eval/data/samples:/s img'
check 2 'docker run --runtime=runsc --network host -v ./eval/data/samples:/s img'
check 2 'docker run --runtime=runsc --cap-add=SYS_ADMIN -v ./eval/data/samples:/s img'

# Other accepted form of the runtime option.
check 0 'docker run --runtime runsc --rm -v ./eval/data/samples:/s:ro img'

# Fails closed on malformed hook input.
if printf 'not json' | "$hook" >/dev/null 2>&1; then
  printf 'FAIL  malformed input was allowed\n'
  fails=$((fails + 1))
else
  printf 'ok    malformed input blocked\n'
fi

if [ "$fails" -ne 0 ]; then
  printf '\n%s hook test(s) failed\n' "$fails"
  exit 1
fi
printf '\nall hook tests passed\n'
