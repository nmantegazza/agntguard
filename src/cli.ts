#!/usr/bin/env node
import { parseCliArgs } from './cli/parser.js';
import { printHelp } from './cli/commands/help.js';
import { handleConfigCommand } from './cli/commands/config.js';
import { handleRuleCommand } from './cli/commands/rule.js';
import { handlePathCommand } from './cli/commands/path.js';
import { handleKeyCommand } from './cli/commands/key.js';
import { handleStatusCommand } from './cli/commands/status.js';
import { handleInitCommand } from './cli/commands/init.js';
import { handleEnableCommand, handleDisableCommand } from './cli/commands/enable-disable.js';

async function main(): Promise<void> {
  if (process.platform === 'win32') {
    console.error('AgntGuard currently supports POSIX environments (macOS & Linux).');
    console.error('On Windows, please run AgntGuard inside WSL (Windows Subsystem for Linux) or a dev container.');
    process.exit(1);
  }

  const rawArgs = process.argv.slice(2);
  const parsed = parseCliArgs(rawArgs);

  if (parsed.flags.help) {
    printHelp(parsed.resource === 'help' ? undefined : parsed.resource);
    return;
  }

  switch (parsed.resource) {
    case 'init': {
      await handleInitCommand();
      break;
    }

    case 'rule': {
      await handleRuleCommand(parsed.subcommand, parsed.positional, parsed.flags);
      break;
    }

    case 'path': {
      await handlePathCommand(parsed.subcommand, parsed.positional, parsed.flags);
      break;
    }

    case 'config': {
      await handleConfigCommand(parsed.subcommand, parsed.positional, parsed.flags);
      break;
    }

    case 'key': {
      await handleKeyCommand(parsed.subcommand, parsed.positional, parsed.flags);
      break;
    }

    case 'status': {
      await handleStatusCommand();
      break;
    }

    case 'enable': {
      await handleEnableCommand(parsed.positional, parsed.flags);
      break;
    }

    case 'disable': {
      await handleDisableCommand(parsed.positional, parsed.flags);
      break;
    }

    case 'help': {
      printHelp(parsed.positional[0]);
      break;
    }

    default: {
      console.error(`Error: Unknown command "${parsed.resource}". Run "agntguard --help" for available commands.`);
      process.exit(1);
    }
  }
}

main().catch((err) => {
  console.error(`CLI execution error: ${err.message}`);
  process.exit(1);
});
