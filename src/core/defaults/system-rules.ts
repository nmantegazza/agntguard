import os from 'node:os';
import type { AllowRule, PathsConfig, PolicyConfig, RestrictRule, SystemPathsConfig, Tier2Policy } from '../../types.js';

/**
 * Shared sensitive file and credential patterns across tools.
 * Excludes source code, definitions, tests, docs, and sample/template files.
 */
const NO_ACCESS_FILE_NAME =
  '(?![^/\\s"\']*(?:example|sample|template|dist|test|spec|mock|fixture|schema|types|\\.d\\.ts|\\.(?:ts|js|py|go|rs|md|c|cpp|h)(?=[/\\s"\']|$)))(\\.env(?:\\.[a-zA-Z0-9_-]+)*|\\.?(?:secret|credential)s?(?:\\.(?:json|ya?ml|toml|ini|conf|cfg|txt))?|id_(?:rsa|ed25519|ecdsa|dsa)|[^/\\s"\']+\\.(?:pem|key|pkcs12|pfx|p12|keystore))';

const NO_ACCESS_DOTFILE_PATH =
  '(?:~|\\$\\{?HOME\\}?)?\\.(?:ssh/(?:id_[^/\\s"\';|&>]+|authorized_keys|known_hosts|config)|aws/(?:credentials|config)|kube/config|docker/config\\.json|gnupg/.*|netrc|npmrc|pypirc|pgpass|git-credentials)';

const NO_ACCESS_AGNTGUARD_PATH =
  '(?:~|\\$\\{?HOME\\}?)?\\.agntguard(?:/(?!logs(?:/|$)).*)?';

const READ_ONLY_SYSTEM_PATH =
  '(?:\\.(?:bashrc|zshrc|profile|bash_profile|bash_login|zprofile|zshenv)|etc/(?:sudoers|sudoers\\.d/.*|pam\\.d/.*|shadow|master\\.passwd|profile|shells|hosts|resolv\\.conf))';

const READ_ONLY_AGNTGUARD_LOGS =
  '(?:~|\\$\\{?HOME\\}?)?\\.agntguard/logs(?:/.*)?';

function buildSystemAllowedPaths(): string[] {
  const dynamicTemp = os.tmpdir();
  const paths = [
    '/dev/null',
    '/tmp(?:/.*)?',
    '/private/tmp(?:/.*)?',
    '/var/tmp(?:/.*)?',
    '/var/folders(?:/.*)?',
    '\\$\\{?TMPDIR\\}?(?:/.*)?',
    '~/.gemini',
    '~/.pi',
    '~/.config/opencode',
    '~/.local/share/opencode'
  ];

  if (dynamicTemp && !['/tmp', '/var/tmp'].includes(dynamicTemp)) {
    const escaped = dynamicTemp.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    paths.push(`${escaped}(?:/.*)?`);
  }

  return Array.from(new Set(paths));
}

export const ALLOWED_SYSTEM_PATHS = buildSystemAllowedPaths();

export const SYSTEM_PATHS: SystemPathsConfig = {
  noAccess: [NO_ACCESS_FILE_NAME, NO_ACCESS_DOTFILE_PATH, NO_ACCESS_AGNTGUARD_PATH],
  readOnly: [READ_ONLY_SYSTEM_PATH, READ_ONLY_AGNTGUARD_LOGS],
  allowed: ALLOWED_SYSTEM_PATHS
};

export const PROTECTED_PATHS: SystemPathsConfig = SYSTEM_PATHS;

export const DEFAULT_PATHS_CONFIG: PathsConfig = {
  outside_read: 'allow',
  outside_write: 'restrict',
  no_access: [],
  read_only: [],
  allowed: []
};

/**
 * Normalizes a path pattern for Tier 2 evaluation so that relative patterns,
 * unanchored paths, and home aliases (~, $HOME) match intercepted targets
 * regardless of whether the target is absolute or relative.
 */
export function normalizeTier2PathRule(pattern: string, cwd?: string): string {
  let normalized = pattern.trim();
  if (!normalized) return normalized;

  const homedir = os.homedir();

  // 1. Expand or alias home directory: match either ~, $HOME, or the actual OS homedir
  if (normalized.startsWith('~') || /^\$\{?HOME\}?/.test(normalized)) {
    const escapedHome = homedir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    normalized = normalized.replace(
      /^(?:~|\$\{?HOME\}?)/,
      `(?:~|\\$\\{?HOME\\}?|${escapedHome})`
    );
    return normalized;
  }

  // 2. If it's already an absolute path, anchored regex, or has a boundary prefix, leave it
  if (
    normalized.startsWith('/') ||
    normalized.startsWith('^') ||
    normalized.startsWith('(?:^|/)') ||
    normalized.startsWith('(?![^/') ||
    normalized.startsWith('(?:~')
  ) {
    return normalized;
  }

  // 3. Unanchored relative pattern: ensure boundary prefix so it matches anywhere in a resolved path
  // e.g., "docs(?:/.*)?" becomes "(?:^|/)docs(?:/.*)?"
  return `(?:^|/)${normalized}`;
}

export function buildTier2Policy(
  userPaths?: PathsConfig,
  systemPaths: SystemPathsConfig = SYSTEM_PATHS,
  cwd?: string
): Tier2Policy {
  const normalize = (patterns: string[]): string[] =>
    patterns.map((p) => normalizeTier2PathRule(p, cwd));

  return {
    outside_read: userPaths?.outside_read ?? DEFAULT_PATHS_CONFIG.outside_read,
    outside_write: userPaths?.outside_write ?? DEFAULT_PATHS_CONFIG.outside_write,
    no_access: normalize([...(systemPaths.noAccess ?? []), ...(userPaths?.no_access ?? [])]),
    read_only: normalize([...(systemPaths.readOnly ?? []), ...(userPaths?.read_only ?? [])]),
    allowed: normalize([...(systemPaths.allowed ?? []), ...(userPaths?.allowed ?? [])])
  };
}

/**
 * Filesystem destruction rules protecting against unrecoverable system loss.
 */
export const FILESYSTEM_DESTRUCTION_RULES: RestrictRule[] = [
  {
    tool: 'execute_command',
    pattern: '(?:^|[\\s;&|(/])(?:sudo\\s+|command\\s+|exec\\s+)?rm(?=[^\\n]*\\s(?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)(?=\\s|$))(?=[^\\n]*\\s(?:/\\*?|\\*+|~[^\\s]*|\\$HOME[^\\s]*|\\.\\.?(?=\\s|$))(?=\\s|$))',
    dimension: 'harmful'
  },
  {
    tool: 'execute_command',
    pattern: '(?:^|[\\s;&|(/])find\\b[^\\n]*\\s(?:-delete\\b|-(?:exec|execdir|ok|okdir)\\s+(?:sudo\\s+)?(?:rm|shred|srm|dd|mkfs|wipefs|sed\\s+-[a-zA-Z]*i|perl\\s+-[a-zA-Z]*i)\\b)',
    dimension: 'harmful'
  },
  {
    tool: 'execute_command',
    pattern: 'mkfs(\\.[a-zA-Z0-9]+)?\\s+',
    dimension: 'harmful'
  },
  {
    tool: 'execute_command',
    pattern: 'dd\\s+.*\\b(?:if|of)=/dev/',
    dimension: 'harmful'
  },
  {
    tool: 'execute_command',
    pattern: '\\b(?:wipefs|fdisk|gdisk|parted|sfdisk|mkswap)\\b',
    dimension: 'harmful'
  },
  {
    tool: 'execute_command',
    pattern: '\\b(?:shred|srm)\\b',
    dimension: 'harmful'
  }
];

/**
 * Credential and secret protection rules preventing sensitive data leaks.
 */
export const CREDENTIAL_PROTECTION_RULES: RestrictRule[] = [
  // Shell commands dumping sensitive environment variables
  {
    tool: 'execute_command',
    pattern: '\\b(?:cat|head|tail|less|more|base64|xxd|od|strings|grep|rg|sed|find|ls|cp|mv|chmod|chown)\\b[^\\n]*\\$\\{?(?:[A-Za-z0-9_]*(?:SECRET|CREDENTIAL|CRED|TOKEN|PASSWORD|PASSWD|AUTH|PRIVATE|APIKEY|DOTENV|SSH_KEY)[A-Za-z0-9_]*)\\b',
    dimension: 'sensitive'
  },
  // Keychain and password manager access
  {
    tool: 'execute_command',
    pattern: '\\b(?:security\\s+(?:find-generic-password|find-certificate|dump-keychain)|secret-tool\\s+lookup|pass\\s+show)\\b',
    dimension: 'sensitive'
  }
];

/**
 * Remote code execution and malicious payload rules.
 */
export const REMOTE_CODE_EXECUTION_RULES: RestrictRule[] = [
  {
    tool: 'execute_command',
    pattern: 'curl\\s+.*\\|\\s*(ba)?sh',
    dimension: 'opaque'
  },
  {
    tool: 'execute_command',
    pattern: 'wget\\s+.*\\|\\s*(ba)?sh',
    dimension: 'opaque'
  },
  {
    tool: 'execute_command',
    pattern: ':\\(\\)\\s*\\{\\s*:\\|:&\\s*\\};:',
    dimension: 'harmful'
  },
  {
    tool: 'execute_command',
    pattern: '\\|\\s*(?:base64|xxd|openssl\\s+enc|openssl\\s+base64)\\b[^\\n]*-[a-zA-Z]*d[a-zA-Z]*\\b',
    dimension: 'opaque'
  },
  {
    tool: 'execute_command',
    pattern: '(?:curl|wget)\\s+.*\\|\\s*(?:python[23]?|node|perl|ruby|zsh)\\b',
    dimension: 'opaque'
  },
  {
    tool: 'execute_command',
    pattern: '(?:^|[\\s;&|(/])(?:nc|ncat)\\s+.*-[a-zA-Z]*e\\b',
    dimension: 'opaque'
  },
  {
    tool: 'execute_command',
    pattern: '(?:^|[\\s;&|(/])socat\\b[^\\n]*\\bTCP-LISTEN\\b',
    dimension: 'opaque'
  },
  {
    tool: 'execute_command',
    pattern: '/dev/(?:tcp|udp)/',
    dimension: 'opaque'
  }
];

/**
 * Repository and supply chain safety rules.
 */
export const REPOSITORY_SAFETY_RULES: RestrictRule[] = [
  {
    tool: 'execute_command',
    pattern: 'git\\s+push\\s+.*(--force|-f)',
    dimension: 'harmful'
  },
  {
    tool: 'execute_command',
    pattern: 'git\\s+reset\\s+--hard',
    dimension: 'harmful'
  },
  {
    tool: 'execute_command',
    pattern: 'git\\s+clean\\s+.*-[a-zA-Z]*f',
    dimension: 'harmful'
  },
  {
    tool: 'execute_command',
    pattern: 'git\\s+(?:restore\\s+\\.|checkout\\s+--\\s+\\.)',
    dimension: 'harmful'
  }
];

/**
 * Process stability rules preventing system interruption.
 */
export const PROCESS_STABILITY_RULES: RestrictRule[] = [
  {
    tool: 'execute_command',
    pattern: '\\b(?:shutdown|reboot|poweroff|halt|init\\s+[06]|kill\\s+-9\\s+-1)\\b',
    dimension: 'harmful'
  }
];

/**
 * Privilege escalation and administrative boundary protection rules.
 */
export const PRIVILEGE_ESCALATION_RULES: RestrictRule[] = [
  {
    tool: 'execute_command',
    pattern: '(?:^|[\\s;&|(/])(?:sudo|su|doas|pkexec)\\s+',
    dimension: 'harmful'
  }
];

/**
 * Persistence, shell environment, and resolver tampering rules.
 */
export const PERSISTENCE_AND_TAMPERING_RULES: RestrictRule[] = [
  {
    tool: 'execute_command',
    pattern: '(?:^|[\\s;&|(/])crontab\\s+-[re]',
    dimension: 'harmful'
  },
  {
    tool: 'execute_command',
    pattern: 'git\\s+config\\s+.*core\\.hooksPath',
    dimension: 'opaque'
  }
];

/**
 * Network perimeter, metadata service (SSRF), and exfiltration tunnel rules.
 */
export const NETWORK_AND_SSRF_RULES: RestrictRule[] = [
  {
    tool: 'fetch_web',
    pattern: '^https?://(?:169\\.254\\.169\\.254|metadata\\.google\\.internal|100\\.100\\.100\\.200)(?:/|$)',
    dimension: 'sensitive'
  },
  {
    tool: 'execute_command',
    pattern: '(?:curl|wget)\\b[^\\n]*(?:169\\.254\\.169\\.254|metadata\\.google\\.internal|100\\.100\\.100\\.200)',
    dimension: 'sensitive'
  },
  {
    tool: 'execute_command',
    pattern: '\\b(?:ngrok|localtunnel)\\b|cloudflared\\s+tunnel\\b',
    dimension: 'opaque'
  }
];

/**
 * Universal baseline inspection allow rules.
 */
/**
 * Universal read-only inspection allow rules (Proven Pure Reads).
 */
export const PURE_READ_ALLOW_RULES: AllowRule[] = [
  {
    tool: 'execute_command',
    pattern: '^git\\s+(status|diff|log|branch|show|grep)(\\s+.*)?$'
  },
  {
    tool: 'execute_command',
    pattern: '^ls(\\s+.*)?$'
  },
  {
    tool: 'execute_command',
    pattern: '^cat(\\s+.*)?$'
  },
  {
    tool: 'execute_command',
    pattern: '^head(\\s+.*)?$'
  },
  {
    tool: 'execute_command',
    pattern: '^tail(\\s+.*)?$'
  },
  {
    tool: 'execute_command',
    pattern: '^grep(\\s+.*)?$'
  },
  {
    tool: 'execute_command',
    pattern: '^find\\b(?![^\\n]*\\s-(?:delete|exec|execdir|ok|okdir|fprint0?|fls)\\b)(\\s+.*)?$'
  },
  {
    tool: 'execute_command',
    pattern: '^pwd$'
  },
  {
    tool: 'execute_command',
    pattern: '^which(\\s+.*)?$'
  },
  {
    tool: 'execute_command',
    pattern: '^rg(\\s+.*)?$'
  },
  {
    tool: 'execute_command',
    pattern: '^git\\s+(rev-parse|describe|remote)(\\s+.*)?$'
  },
  {
    tool: 'execute_command',
    pattern: '^(wc|diff|stat|file|uniq|cut|tr)(\\s+.*)?$'
  },
  {
    tool: 'execute_command',
    pattern: '^sort\\b(?![^\\n]*\\s(?:-o\\b|--output(?:=|\\s)))(\\s+.*)?$'
  },
  {
    tool: 'execute_command',
    pattern: '^echo(\\s+.*)?$'
  },
  {
    tool: 'execute_command',
    pattern: "^sed\\s+-n\\s+['\"]?[0-9]+(,[0-9]+)?p['\"]?\\s+[\\w./@-]+$"
  },
  {
    tool: 'execute_command',
    pattern: '^(uname|whoami|id|date|basename|dirname|realpath)(\\s+.*)?$'
  },
  {
    tool: 'execute_command',
    pattern: '^(node|npm|pnpm|yarn|python|python3|cargo|git|go|rustc)\\s+(--version|-v|-V)$'
  },
  {
    tool: 'fetch_web',
    pattern: '.*'
  },
  {
    tool: 'read_file',
    pattern: '.*'
  },
  {
    tool: 'web_search',
    pattern: '.*'
  },
  {
    tool: 'subagent',
    pattern: '.*'
  },
  {
    tool: 'skill',
    pattern: '.*'
  }
];

/**
 * Universal safe mutation allow rules (modifies files or directories).
 */
export const SAFE_MUTATION_ALLOW_RULES: AllowRule[] = [
  {
    tool: 'execute_command',
    pattern: '^mkdir\\s+(?:-p\\s+)?[\\w./@][\\w./@-]*$'
  },
  {
    tool: 'execute_command',
    pattern: '^git\\s+(?:mv|add)\\s+[\\w./@-]+(?:\\s+[\\w./@-]+)*$'
  },
  {
    tool: 'write_file',
    pattern: '.*'
  }
];

export const BASELINE_ALLOW_RULES: AllowRule[] = [
  ...PURE_READ_ALLOW_RULES,
  ...SAFE_MUTATION_ALLOW_RULES
];

export const SYSTEM_RESTRICT_RULES: RestrictRule[] = [
  ...FILESYSTEM_DESTRUCTION_RULES,
  ...CREDENTIAL_PROTECTION_RULES,
  ...REMOTE_CODE_EXECUTION_RULES,
  ...REPOSITORY_SAFETY_RULES,
  ...PROCESS_STABILITY_RULES,
  ...PRIVILEGE_ESCALATION_RULES,
  ...PERSISTENCE_AND_TAMPERING_RULES,
  ...NETWORK_AND_SSRF_RULES
];

export const SYSTEM_ALLOW_RULES: AllowRule[] = [
  ...BASELINE_ALLOW_RULES
];

export const DEFAULT_SEED_USER_CONFIG: PolicyConfig = {
  mode: 'auto',
  fallback_verdict: 'allow',
  unmapped_tool_verdict: 'allow',
  rules: {
    restrict: [],
    allow: []
  },
  paths: DEFAULT_PATHS_CONFIG,
  tier2: {
    enabled: true,
    provider: 'typesafe',
    timeout_ms: 3500,
    model: 'jev-latest'
  },
  telemetry: {
    enabled: true,
    log_dir: 'logs'
  }
};
