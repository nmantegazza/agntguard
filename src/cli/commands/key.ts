import fs from 'node:fs';
import * as p from '@clack/prompts';
import { saveApiKey, getDefaultCredentialsPath } from '../../credentials.js';

export async function handleKeyCommand(
  subcommand: string | undefined,
  positional: string[],
  flags: Record<string, string | boolean>
): Promise<void> {
  const action = subcommand || 'set';

  switch (action) {
    case 'set': {
      let key = positional[0] || (flags.key as string);

      if (!key) {
        if (!process.stdout.isTTY) {
          console.error('Error: Missing API key. Usage: agntguard key set <key>');
          process.exit(1);
        }

        const enteredKey = await p.password({
          message: 'Enter TypeSafe AI API key:'
        });

        if (p.isCancel(enteredKey)) {
          p.cancel('Operation cancelled.');
          process.exit(0);
        }

        key = String(enteredKey).trim();
      }

      if (!key) {
        console.error('Error: Missing API key. Usage: agntguard key set <key>');
        process.exit(1);
      }

      try {
        const savedPath = saveApiKey(key);
        console.log(`Successfully stored API key in ${savedPath} (mode: 0600)`);
      } catch (err: any) {
        console.error(`Error saving API key: ${err.message}`);
        process.exit(1);
      }
      break;
    }

    case 'remove': {
      const yesFlag = flags.yes === true;

      if (!yesFlag) {
        if (!process.stdout.isTTY) {
          console.error('Error: Confirmation required. Pass --yes to remove API key in non-interactive environments.');
          process.exit(1);
        }

        const confirmed = await p.confirm({
          message: 'Are you sure you want to remove the stored API key credentials?'
        });

        if (p.isCancel(confirmed) || !confirmed) {
          p.cancel('Removal cancelled.');
          process.exit(0);
        }
      }

      const credPath = getDefaultCredentialsPath();
      if (fs.existsSync(credPath)) {
        try {
          fs.unlinkSync(credPath);
          console.log(`Successfully removed API key from ${credPath}`);
        } catch (err: any) {
          console.error(`Error deleting credentials file: ${err.message}`);
          process.exit(1);
        }
      } else {
        console.log('No credentials file found to remove.');
      }
      break;
    }

    default:
      console.error(`Error: Unknown key subcommand "${action}". Use set or remove.`);
      process.exit(1);
  }
}
