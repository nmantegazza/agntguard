# AgntGuard

AgntGuard is a permission engine for coding agents (Antigravity, OpenCode, Pi). It intercepts proposed tool executions, shell commands, and file operations before they run and checks them against a unified policy.

Policy evaluation across harnesses is centralized into a binary verdict (`allow` / `restrict`), with shared credential management and decision telemetry.

## Architecture overview

```
                      Proposed Tool / Action
                                │
                                ▼
                       Host Agent Adapter
                    (Antigravity, OpenCode, Pi)
                                │
                                ▼
                    [AgntGuard PermissionEngine]
                                │
    ┌───────────────────────────┴───────────────────────────┐
    ▼                                                       ▼
[Tier 1: RulesPolicy (Deterministic)]          [Tier 2: RiskScoringPolicy (AI)]
- Gate 1: Unmapped tool verdict                - Contextual semantic evaluation
- Gate 2: 4-tier path & workspace boundary     - TypeSafe AI (jev-latest)
- Gate 3: System/user regex + unbash AST       - Triggered only on unmapped gaps
- Zero overhead (sub-millisecond)              - Timeout-bounded fail-safe
    └───────────────────────────┬───────────────────────────┘
                                │
                                ▼
                         Decision Envelope
                         (allow | restrict)
                                │
                                ▼
                       Host Agent Enforcement
            auto mode -> deny  |  ask mode -> user prompt
```

### Features

- Shell commands (`execute_command`) are parsed into an AST with `unbash`, so AgntGuard inspects atomic subcommands, redirects, environment assignments, and loop expansions.
- Path boundaries use four tiers (`no_access`, `read_only`, `allowed`, and `outside` workspace boundary fallbacks) across file tools and shell redirections.
- Tier 1 evaluates system invariants, path policies, and user rules in under a millisecond using regex and AST checks.
- Tier 2 sends unmatched actions, along with budgeted conversation context and git working-tree state, to TypeSafe AI (`jev-latest`) to assess risk across `harmful`, `sensitive`, `opaque`, and `external` dimensions.
- Tier 1 and workspace boundaries work out of the box without an external API key.
- Adapters translate host agent payloads into a common context and enforce restrictions using each host's primitives.

## Supported environments

- macOS and Linux (POSIX environments)
- Windows via Windows Subsystem for Linux (WSL2) or dev containers
- Node.js `>= 20` (`>= 22.18` or `24` recommended to run the TypeScript test suite)

## Installation and onboarding

### 1. Install from a local checkout

```bash
git clone https://github.com/NMantegazza/agntguard.git
cd agntguard
./install.sh
```

`install.sh` builds the runtime if needed, installs production dependencies into `~/.agntguard/runtime`, and links the `agntguard` CLI launcher at `~/.local/bin/agntguard` (configurable via `AGNTGUARD_DIR` and `AGNTGUARD_BIN_DIR`).

### 2. Onboard your agents

Run the interactive 3-step onboarding wizard to attach hooks for detected agents, choose an operating mode (`auto` or `ask`), and optionally configure Tier 2 credentials:

```bash
agntguard init
```

### 3. Uninstall

```bash
# Detach all agent hooks and remove ~/.agntguard and the CLI launcher
./uninstall.sh

# Detach hooks and remove runtime, while preserving config.json, credentials.json, and logs/
./uninstall.sh --keep-config
```

## Operating modes

AgntGuard supports two operating modes configured globally in `~/.agntguard/config.json`:

- `auto` (default): Denies any restricted operation immediately without human intervention, suited for autonomous workflows and headless batch runs.
- `ask`: Pauses tool execution and prompts the user for confirmation in interactive agent sessions.

Switch modes at any time:

```bash
agntguard config set mode auto
agntguard config set mode ask
```

## CLI reference

### Lifecycle and agent hooks

```bash
agntguard init                      # Interactive 3-step onboarding wizard
agntguard status                    # Agent hook health, mode, and policy summary
agntguard enable [agent...] [--all] # Attach hook for antigravity, opencode, or pi
agntguard disable [agent...] [--all]# Detach hook for target agent(s)
```

### Policy rules and path boundaries

```bash
# List user rules (add --system to expand built-in system rules)
agntguard rule list [--tool <tool>] [--system]

# Add an allow rule for a trusted command
agntguard rule add --list allow --pattern "^docker compose ps$"

# Add a restrict rule for sensitive file reads
agntguard rule add --tool read_file --list restrict --pattern "(^|/)\.secret_keys($|\.)" --dimension sensitive

# Remove a user rule
agntguard rule remove --list allow --pattern "^docker compose ps$"

# Inspect or update Gate 2 path policies (no_access | read_only | allowed)
agntguard path list [--system]
agntguard path add --list read_only --pattern "docs(?:/.*)?"
agntguard path remove --list read_only --pattern "docs(?:/.*)?"
```

### Configuration and credentials

```bash
agntguard config get [key]          # Inspect full config or a specific key
agntguard config set <key> <value>  # Update a whitelisted configuration key
agntguard config reset [--yes]      # Reset configuration to defaults

agntguard key set [key]             # Store TypeSafe AI API key (~/.agntguard/credentials.json, mode 0600)
agntguard key remove [--yes]        # Delete stored credentials
```

## Benchmarks and evaluation

AgntGuard includes an isolated Tier 2 benchmark suite of 104 scenarios (`benchmarks/scenarios/`) testing contextual risk decisions against ground truth (`allow` vs `restrict` across `safe`, `harmful`, `sensitive`, `opaque`, and `external` categories).

Latest run with TypeSafe AI (`jev-latest`, Tier 2 isolated):

| Metric | Result |
| --- | --- |
| Scenarios | 104 |
| Accuracy | 98.1% (102/104) |
| Precision / Recall | 100.0% / 96.8% |
| Confusion Matrix | `TP: 60` · `FP: 0` · `TN: 42` · `FN: 2` |
| False Positive Rate | 0.0% |
| Latency | 173ms p50 · 242ms p90 (192.9ms mean) |

Run the suite locally:

```bash
npm run benchmark
```

## Testing

Run the full automated test suite (TypeScript build plus unit, integration, and install/uninstall tests):

```bash
npm test
```

## License

[MIT](LICENSE)
