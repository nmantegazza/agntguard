import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { OperatingMode, PathsConfig, PolicyConfig, RulesConfig, RiskDimension, Verdict } from './types.js';
import { DEFAULT_PATHS_CONFIG, DEFAULT_SEED_USER_CONFIG } from './core/defaults/system-rules.js';

export function getGlobalConfigDir(): string {
  const agntguardDir = process.env.AGNTGUARD_DIR || process.env.AGNTGUARD_HOME;
  if (agntguardDir && agntguardDir.trim()) {
    return path.resolve(agntguardDir.trim());
  }

  const xdgConfigHome = process.env.XDG_CONFIG_HOME;
  if (xdgConfigHome && xdgConfigHome.trim()) {
    return path.join(xdgConfigHome.trim(), 'agntguard');
  }

  return path.join(os.homedir(), '.agntguard');
}

export function getGlobalLogDir(): string {
  return path.join(getGlobalConfigDir(), 'logs');
}

export function getDefaultConfigPath(): string {
  if (process.env.AGNTGUARD_CONFIG) {
    return path.resolve(process.env.AGNTGUARD_CONFIG);
  }

  const globalConfigPath = path.join(getGlobalConfigDir(), 'config.json');
  if (fs.existsSync(globalConfigPath)) {
    return globalConfigPath;
  }

  // Resolve directory of current file (works for both src/ and dist/)
  const currentFilePath = fileURLToPath(import.meta.url);
  const packageRoot = path.resolve(path.dirname(currentFilePath), '..');
  return path.join(packageRoot, 'config.json');
}

export function loadConfig(customPath?: string): PolicyConfig {
  const configPath = customPath ? path.resolve(customPath) : getDefaultConfigPath();

  if (!fs.existsSync(configPath)) {
    return structuredClone(DEFAULT_SEED_USER_CONFIG);
  }

  const raw = fs.readFileSync(configPath, 'utf8');
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch (err: any) {
    throw new Error(`Failed to parse configuration file at ${configPath}: ${err.message}`);
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error(`Invalid configuration format at ${configPath}`);
  }

  const rules: RulesConfig = {
    restrict: [],
    allow: []
  };

  if (parsed.rules && typeof parsed.rules === 'object') {
    if (Array.isArray(parsed.rules.restrict)) {
      rules.restrict = parsed.rules.restrict.map((r: any) => ({
        tool: String(r.tool),
        pattern: String(r.pattern),
        ...(r.dimension ? { dimension: r.dimension as RiskDimension } : {})
      }));
    }
    if (Array.isArray(parsed.rules.allow)) {
      rules.allow = parsed.rules.allow.map((r: any) => ({
        tool: String(r.tool),
        pattern: String(r.pattern)
      }));
    }
  }

  const rawFallback = parsed.fallback_verdict;
  const fallback_verdict: Verdict =
    rawFallback === 'allow' || rawFallback === 'restrict'
      ? rawFallback
      : (rawFallback ? (console.warn(`agntguard: unknown fallback_verdict "${rawFallback}", defaulting to "allow"`), 'allow') : 'allow');

  const rawUnmapped = parsed.unmapped_tool_verdict;
  const unmapped_tool_verdict: Verdict =
    rawUnmapped === 'allow' || rawUnmapped === 'restrict'
      ? rawUnmapped
      : (rawUnmapped ? (console.warn(`agntguard: unknown unmapped_tool_verdict "${rawUnmapped}", defaulting to "allow"`), 'allow') : 'allow');

  const rawOutsideRead = parsed.paths?.outside_read;
  const outside_read: Verdict =
    rawOutsideRead === 'allow' || rawOutsideRead === 'restrict'
      ? rawOutsideRead
      : DEFAULT_PATHS_CONFIG.outside_read;

  const rawOutsideWrite = parsed.paths?.outside_write;
  const outside_write: Verdict =
    rawOutsideWrite === 'allow' || rawOutsideWrite === 'restrict'
      ? rawOutsideWrite
      : DEFAULT_PATHS_CONFIG.outside_write;

  const paths: PathsConfig = {
    outside_read,
    outside_write,
    no_access: Array.isArray(parsed.paths?.no_access) ? parsed.paths.no_access.map((p: any) => String(p)) : [],
    read_only: Array.isArray(parsed.paths?.read_only) ? parsed.paths.read_only.map((p: any) => String(p)) : [],
    allowed: Array.isArray(parsed.paths?.allowed) ? parsed.paths.allowed.map((p: any) => String(p)) : []
  };

  return {
    mode: (parsed.mode || 'auto') as OperatingMode,
    fallback_verdict,
    unmapped_tool_verdict,
    agent: typeof parsed.agent === 'string' ? parsed.agent : parsed.adapter?.name || 'antigravity',
    adapter: parsed.adapter ? {
      name: parsed.adapter.name || 'antigravity',
      tool_mappings: parsed.adapter.tool_mappings || {}
    } : undefined,
    rules,
    paths,
    tier2: {
      enabled: Boolean(parsed.tier2?.enabled ?? DEFAULT_SEED_USER_CONFIG.tier2.enabled),
      provider: parsed.tier2?.provider || DEFAULT_SEED_USER_CONFIG.tier2.provider,
      timeout_ms: Number(parsed.tier2?.timeout_ms ?? DEFAULT_SEED_USER_CONFIG.tier2.timeout_ms),
      model: parsed.tier2?.model || DEFAULT_SEED_USER_CONFIG.tier2.model
    },
    telemetry: {
      enabled: Boolean(parsed.telemetry?.enabled ?? true),
      log_dir: parsed.telemetry?.log_dir || getGlobalLogDir()
    }
  };
}

export function saveConfig(config: PolicyConfig, customPath?: string): void {
  const configPath = customPath
    ? path.resolve(customPath)
    : (process.env.AGNTGUARD_CONFIG
        ? path.resolve(process.env.AGNTGUARD_CONFIG)
        : path.join(getGlobalConfigDir(), 'config.json'));
  const dirPath = path.dirname(configPath);

  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }

  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', 'utf8');
}

