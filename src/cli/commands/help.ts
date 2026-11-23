import { getColors, renderRail } from '../theme.js';

export function getGeneralHelp(): string {
  const c = getColors();

  const lines = [
    `${c.dim('Unified permission engine for coding agents.')}`,
    '',
    `${c.bold('USAGE:')}`,
    `  ${c.cyan('agntguard')} <command> [subcommand] [flags]`,
    '',
    `${c.bold('COMMANDS:')}`,
    `  ${c.green('init')}                  Run 3-step interactive onboarding wizard`,
    `  ${c.green('status')}                View agent status, hook health, and policy summary`,
    `  ${c.green('enable')} [agent...]     Enable protection for agent(s) (or --all)`,
    `  ${c.green('disable')} [agent...]    Disable protection for agent(s) (or --all)`,
    '',
    `${c.bold('RESOURCE SUBCOMMANDS:')}`,
    `  ${c.green('rule')} <list|add|remove>    Manage Gate 3 regex rules`,
    `  ${c.green('path')} <list|add|remove>    Manage Gate 2 path policies`,
    `  ${c.green('config')} <get|set|reset>    Inspect, update, or reset configuration`,
    `  ${c.green('key')} <set|remove>          Manage Tier 2 API credentials`,
    '',
    `${c.bold('GLOBAL FLAGS:')}`,
    `  ${c.cyan('-h, --help')}             Show help for agntguard or a specific command`,
    '',
    `${c.dim('Run "agntguard <command> --help" for detailed command options.')}`
  ];

  return renderRail('AgntGuard Control Plane', lines);
}

export function getCommandHelp(command: string): string {
  const c = getColors();

  switch (command) {
    case 'init':
      return renderRail('agntguard init', [
        `${c.dim('Launch the interactive 3-step onboarding wizard.')}`,
        '',
        `${c.bold('USAGE:')}`,
        `  ${c.cyan('agntguard init')}`,
        '',
        `${c.bold('DESCRIPTION:')}`,
        '  Guides you through agent selection, operating mode (auto vs ask),',
        '  and optional Tier 2 TypeSafe AI API credentials setup.',
        '  Requires an interactive terminal (TTY).'
      ]);

    case 'status':
      return renderRail('agntguard status', [
        `${c.dim('Display single-screen operational status dashboard.')}`,
        '',
        `${c.bold('USAGE:')}`,
        `  ${c.cyan('agntguard status')}`,
        '',
        `${c.bold('DESCRIPTION:')}`,
        '  Shows agent detection/hook health, active operating mode, fallback verdict,',
        '  Gate 2 outside read/write posture, rule/path counts, Tier 2 status, and telemetry.'
      ]);

    case 'enable':
      return renderRail('agntguard enable', [
        `${c.dim('Attach global AgntGuard hook/shim for target coding agent(s).')}`,
        '',
        `${c.bold('USAGE:')}`,
        `  ${c.cyan('agntguard enable')} [agent...] [--all]`,
        '',
        `${c.bold('AGENTS:')}`,
        '  antigravity, opencode, pi',
        '',
        `${c.bold('FLAGS:')}`,
        `  ${c.cyan('--all')}                  Enable all detected agents`,
        '',
        `${c.dim('If run in a TTY without arguments, an interactive multi-select menu is shown.')}`
      ]);

    case 'disable':
      return renderRail('agntguard disable', [
        `${c.dim('Detach global AgntGuard hook/shim for target coding agent(s).')}`,
        '',
        `${c.bold('USAGE:')}`,
        `  ${c.cyan('agntguard disable')} [agent...] [--all]`,
        '',
        `${c.bold('AGENTS:')}`,
        '  antigravity, opencode, pi',
        '',
        `${c.bold('FLAGS:')}`,
        `  ${c.cyan('--all')}                  Disable all enabled agents`,
        '',
        `${c.dim('If run in a TTY without arguments, an interactive multi-select menu is shown.')}`
      ]);

    case 'rule':
      return renderRail('agntguard rule', [
        `${c.dim('Manage Gate 3 regex pattern rules.')}`,
        '',
        `${c.bold('SUBCOMMANDS:')}`,
        `  ${c.green('list')}     [--tool <tool>] [--system]`,
        '            List user rules (system rules summarized by default; --system expands)',
        `  ${c.green('add')}      --list <allow|restrict> --pattern <regex> [--tool <tool>] [--dimension <dim>]`,
        '            Add a regex rule (tool defaults to execute_command)',
        `  ${c.green('remove')}   --list <allow|restrict> --pattern <regex> [--tool <tool>]`,
        '            Remove a user regex rule (cannot remove built-in system rules)',
        '',
        `${c.bold('RISK DIMENSIONS (for restrict rules):')}`,
        '  harmful, sensitive, opaque, external'
      ]);

    case 'path':
      return renderRail('agntguard path', [
        `${c.dim('Manage Gate 2 path policies.')}`,
        '',
        `${c.bold('SUBCOMMANDS:')}`,
        `  ${c.green('list')}     [--system]`,
        '            Display outside read/write posture and path rules',
        `  ${c.green('add')}      --list <no_access|read_only|allowed> --pattern <path>`,
        '            Add a path policy entry',
        `  ${c.green('remove')}   --list <no_access|read_only|allowed> --pattern <path>`,
        '            Remove a user path policy entry (cannot remove system paths)'
      ]);

    case 'config':
      return renderRail('agntguard config', [
        `${c.dim('Inspect, update, or reset configuration settings.')}`,
        '',
        `${c.bold('SUBCOMMANDS:')}`,
        `  ${c.green('get')}   [key]`,
        '          Pretty-print full configuration or get specific key value',
        `  ${c.green('set')}   <key> <value>`,
        '          Update a configuration key (validated against whitelist schema)',
        `  ${c.green('reset')} [--yes]`,
        '          Reset configuration to default seed settings',
        '',
        `${c.bold('CONFIGURABLE KEYS:')}`,
        '  mode                    auto | ask',
        '  fallback_verdict        allow | restrict',
        '  unmapped_tool_verdict   allow | restrict',
        '  paths.outside_read      allow | restrict',
        '  paths.outside_write     allow | restrict',
        '  tier2.enabled           true | false',
        '  tier2.timeout_ms        100 - 60000',
        '  tier2.model             string',
        '  telemetry.enabled       true | false',
        '  telemetry.log_dir       string path'
      ]);

    case 'key':
      return renderRail('agntguard key', [
        `${c.dim('Manage TypeSafe AI API credentials for Tier 2.')}`,
        '',
        `${c.bold('SUBCOMMANDS:')}`,
        `  ${c.green('set')}    [key]`,
        '           Store API key in credentials.json (mode 0600)',
        '           Prompts with masked password input if [key] is omitted',
        `  ${c.green('remove')} [--yes]`,
        '           Delete credentials.json'
      ]);

    default:
      return getGeneralHelp();
  }
}

export function printHelp(command?: string): void {
  if (command && command !== 'help') {
    console.log(getCommandHelp(command));
  } else {
    console.log(getGeneralHelp());
  }
}
