import * as p from '@clack/prompts';
import { loadConfig, saveConfig, getDefaultConfigPath } from '../../config.js';
import { SYSTEM_PATHS } from '../../core/defaults/system-rules.js';
import { badgeScope } from '../theme.js';

type PathListKey = 'no_access' | 'read_only' | 'allowed';
const VALID_PATH_LISTS: PathListKey[] = ['no_access', 'read_only', 'allowed'];

export async function handlePathCommand(
  subcommand: string | undefined,
  positional: string[],
  flags: Record<string, string | boolean>
): Promise<void> {
  const action = subcommand || 'list';

  switch (action) {
    case 'list': {
      const config = loadConfig();
      const configPath = getDefaultConfigPath();
      const showSystem = flags.system === true;

      const outsideRead = config.paths?.outside_read || 'allow';
      const outsideWrite = config.paths?.outside_write || 'restrict';

      console.log(`Active Config: ${configPath}`);
      console.log(`Operating Mode: ${config.mode || 'auto'}\n`);
      console.log('=== Path Policy (Gate 2) ===\n');
      console.log(`  outside_read: ${outsideRead}`);
      console.log(`  outside_write: ${outsideWrite}\n`);

      const sections: Array<{ key: PathListKey; title: string; systemPaths: readonly string[] }> = [
        {
          key: 'no_access',
          title: 'noAccess / no_access (No-Read, No-Write):',
          systemPaths: SYSTEM_PATHS.noAccess
        },
        {
          key: 'read_only',
          title: 'readOnly / read_only (Read-Only):',
          systemPaths: SYSTEM_PATHS.readOnly
        },
        {
          key: 'allowed',
          title: 'allowed (Allowed Outside CWD):',
          systemPaths: SYSTEM_PATHS.allowed
        }
      ];

      for (const section of sections) {
        console.log(`  ${section.title}`);
        const userPaths = config.paths?.[section.key] || [];

        if (showSystem) {
          let sIdx = 1;
          for (const item of section.systemPaths) {
            console.log(`    ${sIdx++}. ${badgeScope('system')} ${item}`);
          }
        } else if (section.systemPaths.length > 0) {
          console.log(`    ${badgeScope('system')} ${section.systemPaths.length} built-in paths protected (--system to expand)`);
        }

        let uIdx = 1;
        for (const item of userPaths) {
          console.log(`    ${uIdx++}. ${badgeScope('user')} ${item}`);
        }
      }
      break;
    }

    case 'add': {
      let listName = (flags.list as PathListKey) || (positional[0] as PathListKey);
      let pattern = (flags.pattern as string) || positional[1];

      if (!listName || !pattern) {
        if (!process.stdout.isTTY) {
          if (!listName || !VALID_PATH_LISTS.includes(listName)) {
            console.error('Error: Valid --list <no_access|read_only|allowed> is required');
          } else {
            console.error('Error: --pattern <path> is required');
          }
          process.exit(1);
        }

        if (!listName) {
          const selectedList = await p.select({
            message: 'Select path policy category:',
            options: [
              { value: 'no_access', label: 'no_access (Block read and write)' },
              { value: 'read_only', label: 'read_only (Allow read, block write)' },
              { value: 'allowed', label: 'allowed (Permit outside workspace CWD)' }
            ]
          });
          if (p.isCancel(selectedList)) {
            p.cancel('Operation cancelled.');
            process.exit(0);
          }
          listName = selectedList as PathListKey;
        }

        const enteredPattern = await p.text({
          message: 'Path pattern:'
        });
        if (p.isCancel(enteredPattern)) {
          p.cancel('Operation cancelled.');
          process.exit(0);
        }
        pattern = String(enteredPattern).trim();
      }

      if (!listName || !VALID_PATH_LISTS.includes(listName)) {
        console.error('Error: Valid --list <no_access|read_only|allowed> is required');
        process.exit(1);
      }
      if (!pattern) {
        console.error('Error: --pattern <path> is required');
        process.exit(1);
      }

      const config = loadConfig();
      if (!config.paths) {
        config.paths = {
          outside_read: 'allow',
          outside_write: 'restrict',
          no_access: [],
          read_only: [],
          allowed: []
        };
      }
      if (!Array.isArray(config.paths[listName])) {
        config.paths[listName] = [];
      }

      if (config.paths[listName].includes(pattern)) {
        console.log(`Path already exists in [${listName}]: ${pattern}`);
      } else {
        config.paths[listName].push(pattern);
        saveConfig(config);
        console.log(`Added path to [${listName}]: ${pattern}`);
      }
      break;
    }

    case 'remove': {
      let listName = (flags.list as PathListKey) || (positional[0] as PathListKey);
      let pattern = (flags.pattern as string) || positional[1];

      const config = loadConfig();
      if (!config.paths) {
        config.paths = {
          outside_read: 'allow',
          outside_write: 'restrict',
          no_access: [],
          read_only: [],
          allowed: []
        };
      }

      if (!listName || !pattern) {
        if (!process.stdout.isTTY) {
          if (!listName || !VALID_PATH_LISTS.includes(listName)) {
            console.error('Error: Valid --list <no_access|read_only|allowed> is required');
          } else {
            console.error('Error: --pattern <path> is required');
          }
          process.exit(1);
        }

        const allUserPaths: Array<{ list: PathListKey; path: string }> = [
          ...(config.paths.no_access || []).map((path) => ({ list: 'no_access' as PathListKey, path })),
          ...(config.paths.read_only || []).map((path) => ({ list: 'read_only' as PathListKey, path })),
          ...(config.paths.allowed || []).map((path) => ({ list: 'allowed' as PathListKey, path }))
        ];

        if (allUserPaths.length === 0) {
          console.log('No user paths found to remove.');
          return;
        }

        const selected = await p.select({
          message: 'Select user path to remove:',
          options: allUserPaths.map((item) => ({
            value: JSON.stringify(item),
            label: `[${item.list}]: ${item.path}`
          }))
        });

        if (p.isCancel(selected)) {
          p.cancel('Operation cancelled.');
          process.exit(0);
        }

        const parsed = JSON.parse(String(selected));
        listName = parsed.list;
        pattern = parsed.path;
      }

      if (!listName || !VALID_PATH_LISTS.includes(listName)) {
        console.error('Error: Valid --list <no_access|read_only|allowed> is required');
        process.exit(1);
      }
      if (!pattern) {
        console.error('Error: --pattern <path> is required');
        process.exit(1);
      }

      const currentList = config.paths[listName] || [];
      const initialLength = currentList.length;
      config.paths[listName] = currentList.filter((p) => p !== pattern);

      if (config.paths[listName].length < initialLength) {
        saveConfig(config);
        console.log(`Removed path from [${listName}]: ${pattern}`);
        break;
      }

      // Check system paths
      const isSystemPath =
        SYSTEM_PATHS.noAccess.includes(pattern) ||
        SYSTEM_PATHS.readOnly.includes(pattern) ||
        SYSTEM_PATHS.allowed.includes(pattern);

      if (isSystemPath) {
        console.error(`Cannot remove system path "${pattern}". System rules are built-in security guardrails and cannot be deleted.`);
        process.exit(1);
      }

      console.log(`Path not found in [${listName}]: ${pattern}`);
      break;
    }

    default:
      console.error(`Error: Unknown path subcommand "${action}". Use list, add, or remove.`);
      process.exit(1);
  }
}
