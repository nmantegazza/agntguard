import type {
  CanonicalContext,
  DecisionProvider,
  OperatingMode,
  PathsConfig,
  PolicyDecision,
  ProviderEvaluationOutput,
  Tier2Category,
  Tier2Config,
  Verdict
} from '../../types.js';
import { fallbackReason, reasonFor } from './reason-catalog.js';
import { buildTier2Policy, SYSTEM_PATHS } from '../defaults/system-rules.js';

/** Target is required: every gated tool must carry something to judge. */
function hasTarget(context: CanonicalContext): boolean {
  return typeof context.payload === 'string' && context.payload.trim().length > 0;
}

/**
 * Tier 2: classify the action with an AI decision provider as categorical choice
 * (safe, harmful, sensitive, opaque). Always opinionated — never returns null.
 * Provider errors, timeouts, and aborted callers fall back to the configured fail-safe verdict.
 */
export class RiskScoringPolicy {
  constructor(
    private config: Tier2Config,
    private provider?: DecisionProvider,
    private fallbackVerdict: Verdict = 'allow',
    private mode: OperatingMode = 'auto',
    private userPaths?: PathsConfig
  ) {}

  public async evaluate(context: CanonicalContext, signal?: AbortSignal): Promise<PolicyDecision> {
    const fallbackVerdict = this.fallbackVerdict;

    if (!this.config.enabled) {
      return this.fallback('The agntguard provider is disabled', fallbackVerdict);
    }

    if (!this.provider) {
      const decision = this.fallback('The agntguard provider is not configured', fallbackVerdict);
      decision.evidence.aiInteraction = {
        provider: 'none',
        model: this.config.model,
        latencyMs: 0,
        error: 'No decision provider configured'
      };
      return decision;
    }

    if (!hasTarget(context)) {
      const decision = this.fallback('Tier 2 evaluation requires a target resource', fallbackVerdict);
      decision.evidence.aiInteraction = {
        provider: this.provider.name,
        model: this.config.model,
        latencyMs: 0,
        error: 'missing target'
      };
      return decision;
    }

    const enrichedContext: CanonicalContext = context.policy
      ? context
      : { ...context, policy: buildTier2Policy(this.userPaths, SYSTEM_PATHS, context.cwd) };

    const startTime = Date.now();

    try {
      const output = await this.evaluateWithTimeout(this.provider, enrichedContext, this.config.timeout_ms, signal);
      const latencyMs = Date.now() - startTime;

      const category: Tier2Category = typeof output === 'string' ? output : output.category;
      const requestPayload = typeof output === 'object' && output && 'request' in output ? output.request : undefined;
      const rawResponse = typeof output === 'object' && output && 'response' in output ? output.response : undefined;

      const decision = this.resolveCategory(category, latencyMs);
      if (requestPayload || rawResponse) {
        decision.evidence.aiInteraction = {
          provider: this.provider.name,
          model: this.config.model,
          request: requestPayload,
          response: rawResponse,
          latencyMs
        };
      }
      return decision;
    } catch (err: any) {
      const latencyMs = Date.now() - startTime;
      const isTimeout = err?.message?.includes('timed out');
      const detail = isTimeout
        ? `The agntguard provider timed out after ${this.config.timeout_ms}ms`
        : `The agntguard provider error (${err?.message || 'unknown error'})`;

      const decision = this.fallback(detail, fallbackVerdict);
      decision.evidence.tier2LatencyMs = latencyMs;
      decision.evidence.aiInteraction = {
        provider: this.provider.name,
        model: this.config.model,
        latencyMs,
        error: err?.message || 'unknown error'
      };
      return decision;
    }
  }

  private fallback(detail: string, verdict: Verdict): PolicyDecision {
    return {
      decision: verdict,
      reason: fallbackReason(detail, verdict, this.mode),
      tierMatched: 'fallback',
      evidence: { fallbackVerdict: verdict, mode: this.mode }
    };
  }

  private async evaluateWithTimeout(
    provider: DecisionProvider,
    context: CanonicalContext,
    timeoutMs: number,
    signal?: AbortSignal
  ): Promise<Tier2Category | ProviderEvaluationOutput> {
    if (signal?.aborted) {
      throw new Error(`The agntguard provider was aborted`);
    }
    let timer: NodeJS.Timeout | undefined;

    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(new Error(`The agntguard provider timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    });

    const abortPromise = signal
      ? new Promise<never>((_, reject) => {
          signal.addEventListener('abort', () => reject(new Error('The agntguard provider was aborted')), { once: true });
        })
      : undefined;

    try {
      const pending = [provider.evaluate(context, signal), timeoutPromise];
      if (abortPromise) pending.push(abortPromise);
      return await Promise.race(pending);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private resolveCategory(category: Tier2Category, latencyMs?: number): PolicyDecision {
    if (category === 'safe') {
      return {
        decision: 'allow',
        reason: 'Permitted by Tier 2 supervisor evaluation (safe)',
        tierMatched: 'tier2',
        evidence: {
          tier2Category: 'safe',
          tier2LatencyMs: latencyMs,
          mode: this.mode
        }
      };
    }

    return {
      decision: 'restrict',
      reason: reasonFor(category, this.mode),
      tierMatched: 'tier2',
      evidence: {
        tier2Category: category,
        tier2LatencyMs: latencyMs,
        breachedDimension: category,
        mode: this.mode
      }
    };
  }
}
