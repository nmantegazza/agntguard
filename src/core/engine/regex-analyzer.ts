import type {
  AllowRule,
  OperatingMode,
  PathsConfig,
  PolicyDecision,
  RestrictRule,
  SystemPathsConfig
} from '../../types.js';
import { reasonFor } from './reason-catalog.js';
import { evaluatePathPolicy } from './path-policy.js';

export interface RegexPathContext {
  cwd?: string;
  userPaths?: PathsConfig;
}

/**
 * RegexAnalyzer: Evaluates non-shell tools (e.g. read_file, write_file, fetch_web)
 * using deterministic regex pattern matching over canonical payload strings.
 */
export class RegexAnalyzer {
  public evaluate(
    toolName: string,
    payload: string,
    mode: OperatingMode,
    restrictRules: RestrictRule[],
    allowRules: AllowRule[],
    systemPaths: SystemPathsConfig,
    pathContext?: RegexPathContext
  ): PolicyDecision | null {
    if (!payload) return null;

    // 1. Restrict list (Gate 1)
    for (const rule of restrictRules) {
      if (this.matches(rule.pattern, payload)) {
        return {
          decision: 'restrict',
          reason: reasonFor(rule.dimension, mode),
          tierMatched: 'tier1',
          evidence: {
            tier1List: 'restrict',
            tier1Dimension: rule.dimension,
            tier1Pattern: rule.pattern,
            mode
          }
        };
      }
    }

    // Gate 2: Unified Path Policy & Workspace Boundary
    if (toolName === 'read_file' || toolName === 'write_file') {
      const pathDecision = evaluatePathPolicy({
        targets: [payload],
        isShellToken: false,
        isProvenPureRead: toolName === 'read_file',
        mode,
        systemPaths,
        userPaths: pathContext?.userPaths,
        cwd: pathContext?.cwd
      });
      if (pathDecision) {
        return pathDecision;
      }
    }

    // 2. Allow list (Fast-Allow)
    for (const rule of allowRules) {
      if (this.matches(rule.pattern, payload)) {
        return {
          decision: 'allow',
          reason: `Permitted by Tier 1 allow pattern: ${rule.pattern}`,
          tierMatched: 'tier1',
          evidence: {
            tier1List: 'allow',
            tier1Pattern: rule.pattern,
            mode
          }
        };
      }
    }

    return null;
  }

  private matches(pattern: string, target: string): boolean {
    try {
      return new RegExp(pattern).test(target);
    } catch {
      return false;
    }
  }
}
