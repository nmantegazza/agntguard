import * as p from '@clack/prompts';
import { loadConfig, saveConfig, getDefaultConfigPath } from '../../config.js';
import { DEFAULT_SEED_USER_CONFIG } from '../../core/defaults/system-rules.js';
import { PolicyConfig } from '../../types.js';
import { getColors } from '../theme.js';

export const CONFIG_WHITELIST = {
  mode: {
    description: 'Operating mode for permission restrictions',
    type: 'enum',
    allowed: ['auto', 'ask']
  },
  fallback_verdict: {
    description: 'Fallback verdict when system errors or timeouts occur',
    type: 'enum',
    allowed: ['allow', 'restrict']
  },
  unmapped_tool_verdict: {
    description: 'Default verdict for unmapped tools',
    type: 'enum',
    allowed: ['allow', 'restrict']
  },
  'paths.outside_read': {
    description: 'Default verdict for reads outside workspace CWD',
    type: 'enum',
    allowed: ['allow', 'restrict']
  },
  'paths.outside_write': {
    description: 'Default verdict for writes outside workspace CWD',
    type: 'enum',
    allowed: ['allow', 'restrict']
  },
  'tier2.enabled': {
    description: 'Enable or disable Tier 2 AI risk scoring',
    type: 'boolean'
  },
  'tier2.timeout_ms': {
    description: 'Timeout in milliseconds for Tier 2 evaluation (100-60000)',
    type: 'integer',
    min: 100,
    max: 60000
  },
  'tier2.model': {
    description: 'TypeSafe AI model name for Tier 2',
    type: 'string'
  },
  'telemetry.enabled': {
    description: 'Enable or disable decision JSONL logging',
    type: 'boolean'
  },
  'telemetry.log_dir': {
    description: 'Directory for decision telemetry logs',
    type: 'string'
  }
} as const;

export type ConfigWhitelistKey = keyof typeof CONFIG_WHITELIST;

export function printConfigWhitelist(): void {
  const c = getColors();
  console.error('\nValid configurable keys and accepted values:');
  for (const [k, v] of Object.entries(CONFIG_WHITELIST)) {
    if (v.type === 'enum') {
      console.error(`  ${c.cyan(k)}: ${v.allowed.join(' | ')}`);
    } else if (v.type === 'integer') {
      console.error(`  ${c.cyan(k)}: Integer (${v.min} - ${v.max})`);
    } else {
      console.error(`  ${c.cyan(k)}: ${v.type}`);
    }
  }
}

export function validateAndCoerceValue(key: string, rawVal: string): any {
  if (!(key in CONFIG_WHITELIST)) {
    throw new Error(`Unknown configuration key "${key}".`);
  }

  const rule = CONFIG_WHITELIST[key as ConfigWhitelistKey] as any;

  if (rule.type === 'enum') {
    if (!rule.allowed.includes(rawVal)) {
      throw new Error(`Invalid value "${rawVal}" for key "${key}". Accepted values: ${rule.allowed.join(', ')}`);
    }
    return rawVal;
  }

  if (rule.type === 'boolean') {
    const lower = rawVal.toLowerCase();
    if (lower === 'true') return true;
    if (lower === 'false') return false;
    throw new Error(`Invalid boolean value "${rawVal}" for key "${key}". Accepted values: true, false`);
  }

  if (rule.type === 'integer') {
    const num = Number(rawVal);
    if (!Number.isInteger(num) || isNaN(num)) {
      throw new Error(`Invalid integer value "${rawVal}" for key "${key}".`);
    }
    if (rule.min !== undefined && num < rule.min) {
      throw new Error(`Value ${num} for key "${key}" is below minimum ${rule.min}.`);
    }
    if (rule.max !== undefined && num > rule.max) {
      throw new Error(`Value ${num} for key "${key}" is above maximum ${rule.max}.`);
    }
    return num;
  }

  if (rule.type === 'string') {
    if (!rawVal || rawVal.trim() === '') {
      throw new Error(`Value for key "${key}" cannot be empty.`);
    }
    return rawVal.trim();
  }

  return rawVal;
}

export function setConfigValue(config: PolicyConfig, keyPath: string, rawValue: string): void {
  const validatedValue = validateAndCoerceValue(keyPath, rawValue);
  const parts = keyPath.split('.');
  let target: any = config;

  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (typeof target[part] !== 'object' || target[part] === null) {
      target[part] = {};
    }
    target = target[part];
  }

  const lastKey = parts[parts.length - 1];
  target[lastKey] = validatedValue;
}

export function getConfigValue(config: PolicyConfig, keyPath: string): any {
  const parts = keyPath.split('.');
  let current: any = config;

  for (const part of parts) {
    if (current === undefined || current === null) return undefined;
    current = current[part];
  }

  return current;
}

export async function handleConfigCommand(
  subcommand: string | undefined,
  positional: string[],
  flags: Record<string, string | boolean>
): Promise<void> {
  const action = subcommand || 'get';

  switch (action) {
    case 'get': {
      const key = positional[0] || (flags.key as string);
      const configPath = getDefaultConfigPath();
      const config = loadConfig();

      if (key) {
        if (key === 'path' || key === 'configPath') {
          console.log(configPath);
        } else {
          const val = getConfigValue(config, key);
          console.log(typeof val === 'object' ? JSON.stringify(val, null, 2) : String(val));
        }
      } else {
        console.log(`Active Config: ${configPath}\n`);
        console.log(JSON.stringify(config, null, 2));
      }
      break;
    }

    case 'set': {
      let key = positional[0] || (flags.key as string);
      let val = positional[1] || (flags.value as string);

      if (!key || val === undefined) {
        if (!process.stdout.isTTY) {
          console.error('Error: Missing key or value. Usage: agntguard config set <key> <value>');
          printConfigWhitelist();
          process.exit(1);
        }

        const selectedKey = await p.select({
          message: 'Select configuration key to update:',
          options: Object.keys(CONFIG_WHITELIST).map((k) => ({
            value: k,
            label: k
          }))
        });

        if (p.isCancel(selectedKey)) {
          p.cancel('Operation cancelled.');
          process.exit(0);
        }

        key = String(selectedKey);

        const enteredVal = await p.text({
          message: `Enter value for ${key}:`
        });

        if (p.isCancel(enteredVal)) {
          p.cancel('Operation cancelled.');
          process.exit(0);
        }

        val = String(enteredVal);
      }

      try {
        const config = loadConfig();
        setConfigValue(config, key, String(val));
        saveConfig(config);
        console.log(`Updated configuration: ${key} = ${val}`);
      } catch (err: any) {
        console.error(`Error: ${err.message}`);
        printConfigWhitelist();
        process.exit(1);
      }
      break;
    }

    case 'reset': {
      const yesFlag = flags.yes === true;
      if (!yesFlag) {
        if (!process.stdout.isTTY) {
          console.error('Error: Confirmation required. Pass --yes to reset in non-interactive environments.');
          process.exit(1);
        }

        const confirmed = await p.confirm({
          message: 'Reset configuration to default seed settings? This will overwrite ~/.agntguard/config.json'
        });

        if (p.isCancel(confirmed) || !confirmed) {
          p.cancel('Reset cancelled.');
          process.exit(0);
        }
      }

      const freshConfig = structuredClone(DEFAULT_SEED_USER_CONFIG);
      saveConfig(freshConfig);
      console.log('Successfully reset configuration to default settings.');
      break;
    }

    default:
      console.error(`Error: Unknown config subcommand "${action}". Use get, set, or reset.`);
      process.exit(1);
  }
}
