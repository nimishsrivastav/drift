#!/usr/bin/env bash
# check-prereqs.sh — verify the tools the drift framework needs are installed.
# Read-only: it never installs anything and never uses sudo.
#
# Usage: ./check-prereqs.sh
# Exit code: 0 if everything needed for M1 is present, 1 otherwise.

set -u

# ---------- output helpers ----------
if [ -t 1 ]; then
  GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  GREEN=""; RED=""; YELLOW=""; DIM=""; BOLD=""; RESET=""
fi

MISSING_NOW=0
MISSING_LATER=0
WARNINGS=0

ok()      { printf "  %s✓%s %-16s %s\n" "$GREEN" "$RESET" "$1" "${2:-}"; }
fail()    { printf "  %s✗%s %-16s %s\n" "$RED" "$RESET" "$1" "${2:-}"; [ -n "${3:-}" ] && printf "      %s→ %s%s\n" "$DIM" "$3" "$RESET"; }
warn()    { printf "  %s!%s %-16s %s\n" "$YELLOW" "$RESET" "$1" "${2:-}"; [ -n "${3:-}" ] && printf "      %s→ %s%s\n" "$DIM" "$3" "$RESET"; WARNINGS=$((WARNINGS + 1)); }
section() { printf "\n%s%s%s\n" "$BOLD" "$1" "$RESET"; }

# version_ge A B  → true if version A >= version B
version_ge() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# first dotted version number in a string
extract_version() {
  grep -Eo '[0-9]+(\.[0-9]+)+' | head -n1
}

# check_tool TIER NAME VERSION_COMMAND MIN_VERSION HINT
#   TIER: now | later:<milestone> | optional
#   MIN_VERSION may be empty.
check_tool() {
  local tier="$1" name="$2" vcmd="$3" min="$4" hint="$5"
  local bin="${vcmd%% *}"
  local label="$name"

  if ! command -v "$bin" >/dev/null 2>&1; then
    case "$tier" in
      now)      fail "$label" "not found" "$hint"; MISSING_NOW=$((MISSING_NOW + 1)) ;;
      later:*)  fail "$label" "not found (needed by ${tier#later:})" "$hint"; MISSING_LATER=$((MISSING_LATER + 1)) ;;
      optional) warn "$label" "not found (optional)" "$hint" ;;
    esac
    return
  fi

  local ver
  ver="$(eval "$vcmd" 2>&1 | extract_version)"
  if [ -n "$min" ] && [ -n "$ver" ] && ! version_ge "$ver" "$min"; then
    case "$tier" in
      now)      fail "$label" "$ver (need ≥ $min)" "$hint"; MISSING_NOW=$((MISSING_NOW + 1)) ;;
      later:*)  fail "$label" "$ver (need ≥ $min by ${tier#later:})" "$hint"; MISSING_LATER=$((MISSING_LATER + 1)) ;;
      optional) warn "$label" "$ver (recommended ≥ $min)" "$hint" ;;
    esac
    return
  fi

  ok "$label" "${ver:-installed}"
}

printf "%sdrift — prerequisite check%s\n" "$BOLD" "$RESET"

# ---------- environment ----------
section "Environment"

if [ "$(uname -s)" != "Linux" ]; then
  fail "OS" "$(uname -s)" "Run this inside WSL2 Ubuntu (or a Linux VM)"
  MISSING_NOW=$((MISSING_NOW + 1))
else
  if grep -qi microsoft /proc/version 2>/dev/null; then
    if grep -qi "WSL2" /proc/version 2>/dev/null || [ -d /run/WSL ]; then
      ok "WSL" "WSL2 ($(uname -r))"
    else
      fail "WSL" "WSL1 detected" "Convert the distro: wsl --set-version <distro> 2 (from PowerShell)"
      MISSING_NOW=$((MISSING_NOW + 1))
    fi
  else
    ok "Linux" "$(uname -r)"
  fi
fi

case "$PWD" in
  /mnt/*) warn "working dir" "$PWD is on the Windows filesystem" "Keep the repo in the WSL filesystem, e.g. ~/drift" ;;
  *)      ok "working dir" "$PWD" ;;
esac

free_gb="$(df -Pk "$HOME" 2>/dev/null | awk 'NR==2 {printf "%d", $4/1048576}')"
if [ -n "$free_gb" ]; then
  if [ "$free_gb" -lt 20 ]; then
    warn "disk free" "${free_gb} GB in \$HOME" "Images, toolchains and datasets need ~20 GB+"
  else
    ok "disk free" "${free_gb} GB in \$HOME"
  fi
fi

# ---------- base tools ----------
section "Base tools (needed now)"
check_tool now "git"        "git --version"        "2.30" "sudo apt install git"
check_tool now "curl"       "curl --version"       ""     "sudo apt install curl"
check_tool now "jq"         "jq --version"         "1.6"  "sudo apt install jq   (used by the Claude Code hooks)"
check_tool now "gcc"        "gcc --version"        ""     "sudo apt install build-essential"
check_tool now "make"       "make --version"       ""     "sudo apt install build-essential"
check_tool now "pkg-config" "pkg-config --version" ""     "sudo apt install pkg-config"
check_tool now "unzip"      "unzip -v"             ""     "sudo apt install unzip"
check_tool now "just"       "just --version"       "1.0"  "cargo install just   (or: sudo apt install just)"

# ---------- Go ----------
section "Go"
check_tool now "go" "go version" "1.22" "https://go.dev/dl/  (latest stable)"
check_tool optional "golangci-lint" "golangci-lint --version" "" "https://golangci-lint.run/welcome/install/"

# ---------- Rust ----------
section "Rust"
check_tool now "rustup" "rustup --version" "" "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
check_tool now "rustc"  "rustc --version"  "1.85" "rustup update stable   (edition 2024 needs ≥ 1.85)"
check_tool now "cargo"  "cargo --version"  "1.85" "rustup update stable"

if command -v rustup >/dev/null 2>&1; then
  installed_components="$(rustup component list --installed 2>/dev/null)"
  for comp in rustfmt clippy; do
    if printf '%s\n' "$installed_components" | grep -q "^${comp}"; then
      ok "$comp" "installed"
    else
      fail "$comp" "not installed" "rustup component add $comp"
      MISSING_NOW=$((MISSING_NOW + 1))
    fi
  done

  if rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    ok "nightly toolchain" "installed"
  else
    fail "nightly toolchain" "not installed (needed by M3 for cargo-fuzz)" "rustup toolchain install nightly"
    MISSING_LATER=$((MISSING_LATER + 1))
  fi
fi

if command -v cargo >/dev/null 2>&1 && cargo fuzz --version >/dev/null 2>&1; then
  ok "cargo-fuzz" "$(cargo fuzz --version 2>&1 | extract_version)"
else
  fail "cargo-fuzz" "not found (needed by M3)" "cargo install cargo-fuzz"
  MISSING_LATER=$((MISSING_LATER + 1))
fi

# ---------- Python ----------
section "Python"
check_tool now "uv" "uv --version" "0.4" "curl -LsSf https://astral.sh/uv/install.sh | sh"

if command -v python3 >/dev/null 2>&1; then
  py_ver="$(python3 --version 2>&1 | extract_version)"
  if version_ge "$py_ver" "3.12"; then
    ok "python3" "$py_ver"
  elif command -v uv >/dev/null 2>&1; then
    warn "python3" "$py_ver (< 3.12)" "uv python install 3.12   (uv will use it for the workspace)"
  else
    fail "python3" "$py_ver (need ≥ 3.12)" "Install uv, then: uv python install 3.12"
    MISSING_NOW=$((MISSING_NOW + 1))
  fi
else
  if command -v uv >/dev/null 2>&1; then
    warn "python3" "not found" "uv python install 3.12"
  else
    fail "python3" "not found" "Install uv, then: uv python install 3.12"
    MISSING_NOW=$((MISSING_NOW + 1))
  fi
fi

# ---------- Protobuf ----------
section "Protobuf / gRPC"
check_tool now "buf"    "buf --version"    "1.30" "https://buf.build/docs/installation"
check_tool now "protoc" "protoc --version" "3.15" "sudo apt install protobuf-compiler   (tonic-build/prost-build needs protoc)"

# ---------- Containers ----------
section "Containers"
check_tool now "docker" "docker --version" "24.0" "https://docs.docker.com/engine/install/ubuntu/  (Docker Engine inside WSL2)"

if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    ok "docker daemon" "reachable without sudo"

    docker_os="$(docker info --format '{{.OperatingSystem}}' 2>/dev/null)"
    case "$docker_os" in
      *"Docker Desktop"*) warn "docker engine" "Docker Desktop detected" "The plan assumes Docker Engine inside WSL2 (simpler gVisor setup)" ;;
      *)                  ok "docker engine" "${docker_os:-unknown}" ;;
    esac

    if docker compose version >/dev/null 2>&1; then
      ok "docker compose" "$(docker compose version 2>&1 | extract_version)"
    else
      fail "docker compose" "plugin not found" "sudo apt install docker-compose-plugin"
      MISSING_NOW=$((MISSING_NOW + 1))
    fi

    if docker buildx version >/dev/null 2>&1; then
      ok "docker buildx" "$(docker buildx version 2>&1 | extract_version)"
    else
      fail "docker buildx" "plugin not found (needed by M10)" "sudo apt install docker-buildx-plugin"
      MISSING_LATER=$((MISSING_LATER + 1))
    fi

    if docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q '"runsc"'; then
      ok "runsc runtime" "registered with Docker"
    else
      fail "runsc runtime" "not registered with Docker (needed by M5)" "Install gVisor, then: sudo runsc install && sudo systemctl restart docker"
      MISSING_LATER=$((MISSING_LATER + 1))
    fi
  else
    fail "docker daemon" "not reachable" "Start Docker (sudo systemctl start docker) and add yourself to the docker group: sudo usermod -aG docker \$USER, then restart WSL"
    MISSING_NOW=$((MISSING_NOW + 1))
  fi
fi

check_tool "later:M5" "runsc" "runsc --version" "" "https://gvisor.dev/docs/user_guide/install/"

# ---------- CI / GitHub ----------
section "CI and GitHub tooling"
check_tool optional "gh"         "gh --version"         "" "https://cli.github.com/  (PRs, rulesets, gh attestation verify)"
check_tool optional "actionlint" "actionlint -version"  "" "go install github.com/rhysd/actionlint/cmd/actionlint@latest"
check_tool optional "zizmor"     "zizmor --version"     "" "uv tool install zizmor"

# ---------- Release (M10) ----------
section "Release tooling"
check_tool "later:M10" "cosign" "cosign version" "" "https://docs.sigstore.dev/cosign/system_config/installation/"
check_tool "later:M10" "syft"   "syft version"   "" "https://github.com/anchore/syft#installation"

# ---------- Claude Code ----------
section "Claude Code"
check_tool now "claude" "claude --version" "" "curl -fsSL https://claude.ai/install.sh | bash"

# ---------- summary ----------
section "Summary"
if [ "$MISSING_NOW" -eq 0 ]; then
  printf "  %s✓ Everything needed for M1 is present.%s\n" "$GREEN" "$RESET"
else
  printf "  %s✗ %d item(s) needed for M1 are missing or too old.%s\n" "$RED" "$MISSING_NOW" "$RESET"
fi
[ "$MISSING_LATER" -gt 0 ] && printf "  %s• %d item(s) needed by later milestones are not set up yet.%s\n" "$YELLOW" "$MISSING_LATER" "$RESET"
[ "$WARNINGS" -gt 0 ]      && printf "  %s• %d warning(s) / optional tool(s) to review.%s\n" "$YELLOW" "$WARNINGS" "$RESET"
printf "  %sNot needed on the host: node/npm/pip — packages are only ever installed inside the sandbox.%s\n" "$DIM" "$RESET"

[ "$MISSING_NOW" -eq 0 ]
