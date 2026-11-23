#!/usr/bin/env bash
set -euo pipefail

AGNTGUARD_DIR="${AGNTGUARD_DIR:-$HOME/.agntguard}"
AGNTGUARD_BIN_DIR="${AGNTGUARD_BIN_DIR:-$HOME/.local/bin}"
KEEP_CONFIG="0"

usage() {
  cat <<'EOF'
Usage: ./uninstall.sh [options]

Detach AgntGuard hooks and remove the central runtime and CLI launcher.

Options:
  --keep-config   Preserve config.json, credentials.json, and logs/
  -h, --help      Show this help message and exit

Environment overrides:
  AGNTGUARD_DIR          Runtime and state directory (default: ~/.agntguard)
  AGNTGUARD_BIN_DIR      Launcher symlink directory (default: ~/.local/bin)
  ANTIGRAVITY_CONFIG_DIR  Antigravity config directory (default: ~/.gemini/config)
  OPENCODE_CONFIG_DIR     OpenCode config directory (default: ~/.config/opencode)
  OPENCODE_CONFIG_FILE    Explicit OpenCode config file override
  PI_DIR                  Pi base directory (default: ~/.pi)
  PI_EXTENSION_DIR        Pi extension directory override
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-config)
      KEEP_CONFIG="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Run ./uninstall.sh --help for usage." >&2
      exit 1
      ;;
  esac
done

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_CYAN=$'\033[36m'
  C_GREEN=$'\033[32m'
  C_DIM=$'\033[2m'
  C_BOLD=$'\033[1m'
  C_RESET=$'\033[0m'
else
  C_CYAN="" C_GREEN="" C_DIM="" C_BOLD="" C_RESET=""
fi

rail_start() { printf "%s┌%s  %s%s%s\n" "$C_CYAN" "$C_RESET" "$C_BOLD" "$1" "$C_RESET"; }
rail_step()  { printf "%s│%s  %s◇%s %s\n" "$C_CYAN" "$C_RESET" "$C_CYAN" "$C_RESET" "$1"; }
rail_ok()    { printf "%s│%s  %s✔%s %s\n" "$C_CYAN" "$C_RESET" "$C_GREEN" "$C_RESET" "$1"; }
rail_info()  { printf "%s│%s    %s%s%s\n" "$C_CYAN" "$C_RESET" "$C_DIM" "$1" "$C_RESET"; }
rail_end()   { printf "%s└%s  %s\n" "$C_CYAN" "$C_RESET" "$1"; }

rail_start "AgntGuard Uninstaller"

# 1. Detach agent hooks via CLI if runtime is intact
RUNTIME_CLI="$AGNTGUARD_DIR/runtime/dist/cli.js"
if [[ -f "$RUNTIME_CLI" ]] && command -v node >/dev/null 2>&1; then
  rail_step "Detaching agent hooks..."
  AGNTGUARD_DIR="$AGNTGUARD_DIR" node "$RUNTIME_CLI" disable --all >/dev/null 2>&1 || true
fi

# Defensive fallback unlinking for all supported agents
ANTIGRAVITY_PLUGIN_DIR="${ANTIGRAVITY_CONFIG_DIR:-$HOME/.gemini/config}/plugins/agntguard"
rm -rf "$ANTIGRAVITY_PLUGIN_DIR"

PI_EXT_DIR="${PI_EXTENSION_DIR:-${PI_DIR:-$HOME/.pi}/agent/extensions/agntguard}"
rm -rf "$PI_EXT_DIR"

OPENCODE_SHIM_DIR="$AGNTGUARD_DIR/adapters/opencode"
rm -rf "$OPENCODE_SHIM_DIR"

if [[ -n "${OPENCODE_CONFIG_FILE:-}" ]]; then
  OPENCODE_CFG="$OPENCODE_CONFIG_FILE"
else
  OC_BASE="${OPENCODE_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/opencode}"
  if [[ -f "$OC_BASE/opencode.jsonc" ]]; then
    OPENCODE_CFG="$OC_BASE/opencode.jsonc"
  else
    OPENCODE_CFG="$OC_BASE/opencode.json"
  fi
fi

if [[ -f "$OPENCODE_CFG" ]] && command -v node >/dev/null 2>&1; then
  OC_NOTICE="$(node - "$OPENCODE_CFG" "$OPENCODE_SHIM_DIR" <<'NODE'
const fs = require('fs');
const [,, cfgPath, shimDir] = process.argv;
let raw;
try { raw = fs.readFileSync(cfgPath, 'utf8'); } catch { process.exit(0); }

const matches = (p) =>
  (typeof p === 'string' && p === shimDir) ||
  (p && typeof p === 'object' && p.package === shimDir);

try {
  const cfg = JSON.parse(raw);
  if (Array.isArray(cfg.plugins)) {
    const next = cfg.plugins.filter((p) => !matches(p));
    if (next.length < cfg.plugins.length) {
      cfg.plugins = next;
      fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2) + '\n');
    }
  }
  process.exit(0);
} catch {
  // May be JSONC with comments/trailing commas; never rewrite automatically.
  const stripped = raw
    .replace(/\/\*[\s\S]*?\*\/|([^\\:]|^)\/\/.*$/gm, '$1')
    .replace(/,(\s*[}\]])/g, '$1');
  try {
    const cfg = JSON.parse(stripped);
    if (Array.isArray(cfg.plugins) && cfg.plugins.some(matches)) {
      console.log(`Notice: ${cfgPath} contains comments. Remove the plugin entry for ${shimDir} manually.`);
    }
  } catch {}
}
NODE
  )"
  if [[ -n "$OC_NOTICE" ]]; then
    rail_info "$OC_NOTICE"
  fi
fi

rail_ok "Detached agent hooks"

# 2. Remove launcher symlink
rm -f "$AGNTGUARD_BIN_DIR/agntguard"
rail_ok "Removed CLI launcher ($AGNTGUARD_BIN_DIR/agntguard)"

# 3. Remove runtime and state
if [[ "$KEEP_CONFIG" == "1" ]]; then
  rm -rf "$AGNTGUARD_DIR/runtime" "$AGNTGUARD_DIR/bin" "$AGNTGUARD_DIR/adapters"
  rail_ok "Removed runtime (preserved config, credentials, and logs in $AGNTGUARD_DIR)"
else
  rm -rf "$AGNTGUARD_DIR"
  rail_ok "Removed $AGNTGUARD_DIR"
fi

rail_end "AgntGuard uninstalled."
