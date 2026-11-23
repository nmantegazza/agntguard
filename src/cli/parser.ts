export interface ParsedArgs {
  resource: string;
  subcommand?: string;
  positional: string[];
  flags: Record<string, string | boolean>;
}

const GROUPED_RESOURCES = new Set(['rule', 'path', 'config', 'key']);

const BOOLEAN_FLAGS = new Set([
  'system',
  'all',
  'yes',
  'no-open',
  'help',
  'h'
]);

export function parseCliArgs(argv: string[]): ParsedArgs {
  if (argv.length === 0) {
    return {
      resource: 'help',
      positional: [],
      flags: {}
    };
  }

  const flags: Record<string, string | boolean> = {};
  const nonFlagTokens: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];

    if (token === '-h') {
      flags['help'] = true;
      flags['h'] = true;
      continue;
    }

    if (token.startsWith('--')) {
      const equalsIdx = token.indexOf('=');
      let key: string;
      let val: string | undefined;

      if (equalsIdx !== -1) {
        key = token.slice(2, equalsIdx);
        val = token.slice(equalsIdx + 1);
      } else {
        key = token.slice(2);
      }

      if (val !== undefined) {
        if (val.toLowerCase() === 'true') {
          flags[key] = true;
        } else if (val.toLowerCase() === 'false') {
          flags[key] = false;
        } else {
          flags[key] = val;
        }
      } else if (BOOLEAN_FLAGS.has(key)) {
        flags[key] = true;
      } else if (i + 1 < argv.length && !argv[i + 1].startsWith('-')) {
        flags[key] = argv[++i];
      } else {
        flags[key] = true;
      }
      continue;
    }

    nonFlagTokens.push(token);
  }

  // If first token is help or if help flag was passed without resource
  if (nonFlagTokens.length === 0) {
    return {
      resource: 'help',
      positional: [],
      flags
    };
  }

  const firstToken = nonFlagTokens[0];
  const remainingTokens = nonFlagTokens.slice(1);

  if (firstToken === 'help') {
    return {
      resource: 'help',
      positional: remainingTokens,
      flags
    };
  }

  const resource = firstToken;

  if (GROUPED_RESOURCES.has(resource)) {
    const subcommand = remainingTokens[0];
    const positional = subcommand !== undefined ? remainingTokens.slice(1) : [];
    return {
      resource,
      subcommand,
      positional,
      flags
    };
  }

  return {
    resource,
    positional: remainingTokens,
    flags
  };
}
