import os from 'node:os';
import path from 'node:path';
import type {
  OperatingMode,
  PathsConfig,
  PolicyDecision,
  SystemPathsConfig
} from '../../types.js';
import { pathPolicyReason } from './reason-catalog.js';

export interface PathEvaluationInput {
  targets: string[];
  isShellToken: boolean;
  isProvenPureRead: boolean;
  mode: OperatingMode;
  systemPaths: SystemPathsConfig;
  userPaths?: PathsConfig;
  cwd?: string;
}

export function expandHome(rawPath: string): string {
  const trimmed = rawPath.trim();
  if (/^~(?=\/|$)/.test(trimmed)) {
    return path.join(os.homedir(), trimmed.slice(1));
  }
  if (/^\$\{?HOME\}?(?=\/|$)/.test(trimmed)) {
    return trimmed.replace(/^\$\{?HOME\}?/, os.homedir());
  }
  return trimmed;
}

export function resolveAgainstCwd(rawPath: string, cwd: string): string {
  const expanded = expandHome(rawPath);
  const expandedCwd = expandHome(cwd);
  return path.resolve(expandedCwd, expanded);
}

export function isWithinDir(targetPath: string, rootDir: string): boolean {
  const normTarget = path.resolve(targetPath);
  const normRoot = path.resolve(rootDir);
  if (normTarget === normRoot) return true;
  const prefix = normRoot.endsWith(path.sep) ? normRoot : normRoot + path.sep;
  return normTarget.startsWith(prefix);
}

function safeRegexTest(pattern: string, target: string): boolean {
  try {
    return new RegExp(pattern).test(target);
  } catch {
    return false;
  }
}

export function matchesPathEntry(
  target: string,
  entry: string,
  isShellToken: boolean,
  cwd?: string
): boolean {
  const boundaryPattern = isShellToken
    ? `^(?:\\S*/)?(?:${entry})$`
    : `(?:^|/)(?:${entry})$`;

  if (safeRegexTest(boundaryPattern, target)) {
    return true;
  }

  const isConcreteEntry =
    entry.startsWith('/') ||
    entry.startsWith('~') ||
    entry.startsWith('$') ||
    (Boolean(cwd) && entry.startsWith('.'));

  if (isConcreteEntry) {
    const baseDir = cwd || '/';
    const canResolveTarget =
      Boolean(cwd) ||
      target.startsWith('/') ||
      target.startsWith('~') ||
      target.startsWith('$');
    if (canResolveTarget) {
      const resolvedTarget = resolveAgainstCwd(target, baseDir);
      const resolvedEntry = resolveAgainstCwd(entry, baseDir);
      if (isWithinDir(resolvedTarget, resolvedEntry)) {
        return true;
      }
    }
  }

  return false;
}

export function canShellTokenResolveOutsideCwd(token: string): boolean {
  const t = token.trim();
  if (!t) return false;
  if (/\s/.test(t)) return false;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(t)) return false;
  if (/['"();<>|&]/.test(t)) return false;

  if (
    t.startsWith('/') ||
    t === '~' ||
    t.startsWith('~/') ||
    /^\$\{?HOME\}?(?:\/|$)/.test(t) ||
    /^\$\{?TMPDIR\}?(?:\/|$)/.test(t)
  ) {
    return true;
  }

  if (/(?:^|\/)\.\.(?:\/|$)/.test(t)) {
    return true;
  }

  return false;
}

/**
 * Evaluates Gate 2 (Unified Path Policy & Workspace Boundary) across the four-tier hierarchy:
 *   1. `no_access` (System + User) -> restrict reads & writes everywhere
 *   2. `read_only` (System + User) -> allow Proven Pure Reads; restrict writes everywhere
 *   3. `allowed` (`cwd` + `SYSTEM_PATHS.allowed` + `userPaths.allowed`) -> pass Gate 2
 *   4. `outside` fallback -> apply `outside_read` (default 'allow') or `outside_write` (default 'restrict')
 */
export function evaluatePathPolicy(input: PathEvaluationInput): PolicyDecision | null {
  const {
    targets,
    isShellToken,
    isProvenPureRead,
    mode,
    systemPaths,
    userPaths,
    cwd
  } = input;

  const noAccessList = [...(systemPaths.noAccess ?? []), ...(userPaths?.no_access ?? [])];
  const readOnlyList = [...(systemPaths.readOnly ?? []), ...(userPaths?.read_only ?? [])];
  const systemAllowedList = systemPaths.allowed ?? [];
  const userAllowedList = userPaths?.allowed ?? [];

  for (const rawTarget of targets) {
    const target = rawTarget.trim();
    if (!target) continue;

    // Tier 1: no_access (System + User)
    for (const p of noAccessList) {
      if (matchesPathEntry(target, p, isShellToken, cwd)) {
        return {
          decision: 'restrict',
          reason: pathPolicyReason('no_access', mode),
          tierMatched: 'tier1',
          evidence: {
            tier1List: 'restrict',
            tier1Pattern: p,
            pathPolicyViolation: 'no_access',
            mode
          }
        };
      }
    }

    // Tier 2: read_only (System + User)
    let matchedReadOnlyPattern: string | undefined;
    for (const p of readOnlyList) {
      if (matchesPathEntry(target, p, isShellToken, cwd)) {
        matchedReadOnlyPattern = p;
        break;
      }
    }
    if (matchedReadOnlyPattern !== undefined) {
      if (!isProvenPureRead) {
        return {
          decision: 'restrict',
          reason: pathPolicyReason('read_only', mode),
          tierMatched: 'tier1',
          evidence: {
            tier1List: 'restrict',
            tier1Pattern: matchedReadOnlyPattern,
            pathPolicyViolation: 'read_only',
            mode
          }
        };
      }
      // Proven Pure Read on a read_only path is permitted even outside cwd
      continue;
    }

    // Tier 3: allowed / Workspace Boundary
    if (isShellToken && !canShellTokenResolveOutsideCwd(target)) {
      continue;
    }

    const expandedTarget = expandHome(target);
    if (
      systemAllowedList.some(
        p =>
          safeRegexTest(`^(?:${p})$`, target) ||
          safeRegexTest(`^(?:${p})$`, expandedTarget) ||
          matchesPathEntry(target, p, isShellToken, cwd)
      )
    ) {
      continue;
    }

    // If no workspace boundary context is configured, skip workspace boundary enforcement
    if (!cwd) {
      continue;
    }

    const resolvedTarget = resolveAgainstCwd(target, cwd);

    if (
      systemAllowedList.some(
        p =>
          safeRegexTest(`^(?:${p})$`, resolvedTarget) ||
          matchesPathEntry(resolvedTarget, p, false, cwd)
      )
    ) {
      continue;
    }

    if (isWithinDir(resolvedTarget, resolveAgainstCwd(cwd, cwd))) {
      continue;
    }

    if (
      userAllowedList.some(
        entry =>
          isWithinDir(resolvedTarget, resolveAgainstCwd(entry, cwd)) ||
          matchesPathEntry(target, entry, isShellToken, cwd)
      )
    ) {
      continue;
    }

    // Tier 4: outside Fallback
    if (isProvenPureRead) {
      const outsideReadVerdict = userPaths?.outside_read ?? 'allow';
      if (outsideReadVerdict === 'restrict') {
        return {
          decision: 'restrict',
          reason: pathPolicyReason('outside_read', mode),
          tierMatched: 'tier1',
          evidence: {
            tier1List: 'restrict',
            tier1Pattern: 'paths.outside_read',
            pathPolicyViolation: 'outside_read',
            mode
          }
        };
      }
    } else {
      const outsideWriteVerdict = userPaths?.outside_write ?? 'restrict';
      if (outsideWriteVerdict === 'restrict') {
        return {
          decision: 'restrict',
          reason: pathPolicyReason('outside_write', mode),
          tierMatched: 'tier1',
          evidence: {
            tier1List: 'restrict',
            tier1Pattern: 'paths.outside_write',
            pathPolicyViolation: 'outside_write',
            mode
          }
        };
      }
    }
  }

  return null;
}
