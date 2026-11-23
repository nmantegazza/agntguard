#!/usr/bin/env bash
set -euo pipefail

AGNTGUARD_DIR="${AGNTGUARD_DIR:-$HOME/.agntguard}"
AGNTGUARD_BIN_DIR="${AGNTGUARD_BIN_DIR:-$HOME/.local/bin}"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

Install AgntGuard runtime and CLI launcher from a local repository checkout.

Options:
  -h, --help    Show this help message and exit

Environment overrides:
  AGNTGUARD_DIR      Runtime and state directory (default: ~/.agntguard)
  AGNTGUARD_BIN_DIR  Launcher symlink directory (default: ~/.local/bin)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Run ./install.sh --help for usage." >&2
      exit 1
      ;;
  esac
done

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_CYAN=$'\033[36m'
  C_GREEN=$'\033[32m'
  C_RED=$'\033[31m'
  C_DIM=$'\033[2m'
  C_BOLD=$'\033[1m'
  C_RESET=$'\033[0m'
else
  C_CYAN="" C_GREEN="" C_RED="" C_DIM="" C_BOLD="" C_RESET=""
fi

rail_start() { printf "%s┌%s  %s%s%s\n" "$C_CYAN" "$C_RESET" "$C_BOLD" "$1" "$C_RESET"; }
rail_step()  { printf "%s│%s  %s◇%s %s\n" "$C_CYAN" "$C_RESET" "$C_CYAN" "$C_RESET" "$1"; }
rail_ok()    { printf "%s│%s  %s✔%s %s\n" "$C_CYAN" "$C_RESET" "$C_GREEN" "$C_RESET" "$1"; }
rail_info()  { printf "%s│%s    %s%s%s\n" "$C_CYAN" "$C_RESET" "$C_DIM" "$1" "$C_RESET"; }
rail_end()   { printf "%s└%s  %s\n" "$C_CYAN" "$C_RESET" "$1"; }
rail_fail()  {
  printf "%s│%s  %s✖%s %s\n" "$C_CYAN" "$C_RESET" "$C_RED" "$C_RESET" "$1" >&2
  printf "%s└%s  Installation aborted.\n" "$C_CYAN" "$C_RESET" >&2
  exit 1
}

run_quiet() {
  local output
  if ! output="$("$@" 2>&1)"; then
    printf "%s\n" "$output" >&2
    return 1
  fi
}

rail_start "AgntGuard Installer"

# 1. Verify OS
OS_NAME="$(uname -s)"
case "$OS_NAME" in
  Darwin|Linux) ;;
  MINGW*|MSYS*|CYGWIN*)
    rail_fail "Windows ($OS_NAME) is not supported. Use WSL2 on Windows."
    ;;
  *)
    rail_fail "Unsupported operating system: $OS_NAME"
    ;;
esac

# 2. Verify Node.js >= 20 and npm
if ! command -v node >/dev/null 2>&1; then
  rail_fail "Node.js is required (>= 20) but was not found on PATH."
fi
if ! command -v npm >/dev/null 2>&1; then
  rail_fail "npm is required but was not found on PATH."
fi

NODE_VERSION="$(node -v)"
NODE_MAJOR="${NODE_VERSION#v}"
NODE_MAJOR="${NODE_MAJOR%%.*}"
if ! [[ "$NODE_MAJOR" =~ ^[0-9]+$ ]] || (( NODE_MAJOR < 20 )); then
  rail_fail "Node.js >= 20 is required (found $NODE_VERSION)."
fi

# 3. Verify local checkout
if [[ ! -f "$SOURCE_DIR/package.json" ]] || ! node -e '
  const fs = require("fs");
  const pkg = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  process.exit(pkg.name === "agntguard" ? 0 : 1);
' "$SOURCE_DIR/package.json" 2>/dev/null; then
  rail_fail "install.sh must be run from a local AgntGuard repository checkout."
fi

rail_step "Environment verified ($OS_NAME, Node $NODE_VERSION)"

# 4. Build if dist/cli.js is missing
if [[ ! -f "$SOURCE_DIR/dist/cli.js" ]]; then
  rail_step "Building runtime from source..."
  run_quiet npm --prefix "$SOURCE_DIR" run build || rail_fail "Failed to build AgntGuard runtime."
fi

# 5. Copy runtime payload (never pre-seed config.json or credentials.json)
RUNTIME_DIR="$AGNTGUARD_DIR/runtime"
mkdir -p "$RUNTIME_DIR"
rm -rf "$RUNTIME_DIR/dist"
cp -R "$SOURCE_DIR/dist" "$RUNTIME_DIR/dist"
cp "$SOURCE_DIR/package.json" "$RUNTIME_DIR/package.json"
if [[ -f "$SOURCE_DIR/package-lock.json" ]]; then
  cp "$SOURCE_DIR/package-lock.json" "$RUNTIME_DIR/package-lock.json"
fi

rail_step "Installing production dependencies..."
if [[ -f "$RUNTIME_DIR/package-lock.json" ]]; then
  run_quiet npm --prefix "$RUNTIME_DIR" ci --omit=dev --no-audit --no-fund || rail_fail "Failed to install runtime dependencies."
else
  run_quiet npm --prefix "$RUNTIME_DIR" install --omit=dev --no-audit --no-fund || rail_fail "Failed to install runtime dependencies."
fi

# 6. Create executable CLI launcher and symlink
BIN_DIR="$AGNTGUARD_DIR/bin"
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/agntguard" <<EOF
#!/usr/bin/env bash
exec node "$RUNTIME_DIR/dist/cli.js" "\$@"
EOF
chmod +x "$BIN_DIR/agntguard"

mkdir -p "$AGNTGUARD_BIN_DIR"
if [[ "$AGNTGUARD_BIN_DIR" != "$BIN_DIR" ]]; then
  ln -sf "$BIN_DIR/agntguard" "$AGNTGUARD_BIN_DIR/agntguard"
fi

rail_ok "Installed runtime to $RUNTIME_DIR"
rail_ok "Linked CLI launcher at $AGNTGUARD_BIN_DIR/agntguard"

if [[ ":$PATH:" != *":$AGNTGUARD_BIN_DIR:"* ]]; then
  rail_info "Add $AGNTGUARD_BIN_DIR to your PATH:"
  rail_info "  export PATH=\"$AGNTGUARD_BIN_DIR:\$PATH\""
fi

rail_end "Next step: run ${C_BOLD}agntguard init${C_RESET} to configure your agents."
