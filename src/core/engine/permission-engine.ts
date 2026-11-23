import type { CanonicalContext, DecisionProvider, PolicyConfig, PolicyDecision } from '../../types.js';
import { RulesPolicy } from './rules-policy.js';
import { RiskScoringPolicy } from './risk-scoring-policy.js';

/**
 * Arbitrates the two policy modules: deterministic rules first, risk scoring
 * only where rules have no opinion. Operates strictly on single-resource contexts.
 */
export class PermissionEngine {
  private rules: RulesPolicy;
  private risk: RiskScoringPolicy;

  constructor(config: PolicyConfig, provider?: DecisionProvider) {
    const mode = config.mode || 'auto';
    this.risk = new RiskScoringPolicy(config.tier2, provider, config.fallback_verdict || 'allow', mode, config.paths);
    this.rules = new RulesPolicy(config.rules, mode, config.unmapped_tool_verdict || 'allow', config.paths);
  }

  public async evaluate(context: CanonicalContext, signal?: AbortSignal): Promise<PolicyDecision> {
    return this.rules.evaluate(context, signal) ?? await this.risk.evaluate(context, signal);
  }
}

