import type {
  CanonicalContext,
  GitState,
  OperatingMode,
  PolicyConfig,
  PolicyDecision
} from '../../types.js';
import { PermissionEngine } from '../engine/permission-engine.js';
import { TelemetryLogger } from '../telemetry/logger.js';
import { inspectGitContext } from '../../context/git-context.js';
import { fallbackReason } from '../engine/reason-catalog.js';

export interface PolicyRunnerDeps {
  config: PolicyConfig;
  engine?: PermissionEngine;
  telemetry?: TelemetryLogger;
  inspectGit?: typeof inspectGitContext;
  signal?: AbortSignal;
}

const GIT_STATES: GitState[] = ['not_tracked', 'clean', 'dirty'];

/** Accepts the canonical shape; tolerates legacy {isGitRepo,hasUncommittedChanges} injectors. */
export function resolveGitState(raw: unknown): GitState {
  if (raw && typeof raw === 'object') {
    const r = raw as { git_state?: unknown; isGitRepo?: unknown; hasUncommittedChanges?: unknown };
    if (typeof r.git_state === 'string' && (GIT_STATES as string[]).includes(r.git_state)) {
      return r.git_state as GitState;
    }
    if (typeof r.isGitRepo === 'boolean') {
      if (!r.isGitRepo) return 'not_tracked';
      return r.hasUncommittedChanges === true ? 'dirty' : 'clean';
    }
  }
  return 'not_tracked';
}

/** Fail-safe decision used when evaluation itself throws. */
export function fallbackDecision(verdict: 'allow' | 'restrict', detail: string, mode: OperatingMode): PolicyDecision {
  return {
    decision: verdict,
    reason: fallbackReason(detail, verdict, mode),
    tierMatched: 'fallback',
    evidence: { mode, fallbackVerdict: verdict }
  };
}

export class PolicyRunner {
  private config: PolicyConfig;
  private engine: PermissionEngine;
  private telemetry: TelemetryLogger;
  private inspectGit: typeof inspectGitContext;
  private signal?: AbortSignal;

  constructor(deps: PolicyRunnerDeps) {
    this.config = deps.config;
    this.engine = deps.engine ?? new PermissionEngine(deps.config);
    this.telemetry = deps.telemetry ?? new TelemetryLogger(deps.config);
    this.inspectGit = deps.inspectGit ?? inspectGitContext;
    this.signal = deps.signal;
  }

  public async run(context: CanonicalContext): Promise<PolicyDecision> {
    const mode: OperatingMode = this.config.mode || 'auto';
    try {
      try {
        const gitState = await this.inspectGit(context.cwd);
        const state = resolveGitState(gitState);
        context.gitState = state;
        context.isGitRepo = state !== 'not_tracked';
        context.hasUncommittedChanges = state === 'dirty';
      } catch {
        // Git enrichment is best-effort; never fail evaluation.
      }
      const result = await this.engine.evaluate(context, this.signal);
      try {
        this.telemetry.log(context, result);
      } catch {
        // Telemetry must never break evaluation.
      }
      return result;
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      const fallback = this.config.fallback_verdict || 'allow';
      const fallbackRes = fallbackDecision(fallback, detail, mode);
      try {
        this.telemetry.log(context, fallbackRes);
      } catch {
        // Telemetry must never break evaluation.
      }
      return fallbackRes;
    }
  }
}
