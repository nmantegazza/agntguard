import type {
  AllowRule,
  CanonicalContext,
  OperatingMode,
  PathsConfig,
  PolicyDecision,
  RestrictRule,
  RulesConfig,
  Verdict
} from '../../types.js';
import {
  SYSTEM_RESTRICT_RULES,
  SYSTEM_ALLOW_RULES,
  SYSTEM_PATHS,
  PURE_READ_ALLOW_RULES
} from '../defaults/system-rules.js';
import { unmappedToolReason } from './reason-catalog.js';
import { RegexAnalyzer } from './regex-analyzer.js';
import { AstAnalyzer } from './ast-analyzer.js';

/**
 * Tier 1: deterministic rule matching over system baseline and user config.
 *
 * Evaluates system restrict rules first as a non-bypassable security floor,
 * followed by user restrict rules, then conjunction over combined allow rules.
 * Owns tool gating and unmapped tool handling.
 * Delegates `execute_command` to `AstAnalyzer` (POSIX AST shell parser)
 * and non-shell tools to `RegexAnalyzer` (regex pattern matcher).
 */
export class RulesPolicy {
  private systemRestrictRulesByTool = new Map<string, RestrictRule[]>();
  private systemAllowRulesByTool = new Map<string, AllowRule[]>();
  private userRestrictRulesByTool = new Map<string, RestrictRule[]>();
  private userAllowRulesByTool = new Map<string, AllowRule[]>();
  private pureReadCommandRules: AllowRule[] = [];
  private regexAnalyzer = new RegexAnalyzer();
  private astAnalyzer = new AstAnalyzer();

  constructor(
    rules?: RulesConfig,
    private mode: OperatingMode = 'auto',
    private unmappedToolVerdict: Verdict = 'allow',
    private userPaths?: PathsConfig
  ) {
    this.pureReadCommandRules = PURE_READ_ALLOW_RULES.filter(r => r.tool === 'execute_command');

    // 1. Index built-in system baseline rules
    for (const rule of SYSTEM_RESTRICT_RULES) {
      if (!rule || !rule.tool) continue;
      const list = this.systemRestrictRulesByTool.get(rule.tool);
      if (list) list.push(rule);
      else this.systemRestrictRulesByTool.set(rule.tool, [rule]);
    }

    for (const rule of SYSTEM_ALLOW_RULES) {
      if (!rule || !rule.tool) continue;
      const list = this.systemAllowRulesByTool.get(rule.tool);
      if (list) list.push(rule);
      else this.systemAllowRulesByTool.set(rule.tool, [rule]);
    }

    // 2. Index user-configured rules
    for (const rule of rules?.restrict ?? []) {
      if (!rule || !rule.tool) continue;
      const list = this.userRestrictRulesByTool.get(rule.tool);
      if (list) list.push(rule);
      else this.userRestrictRulesByTool.set(rule.tool, [rule]);
    }

    for (const rule of rules?.allow ?? []) {
      if (!rule || !rule.tool) continue;
      const list = this.userAllowRulesByTool.get(rule.tool);
      if (list) list.push(rule);
      else this.userAllowRulesByTool.set(rule.tool, [rule]);
    }
  }

  /**
   * `signal` is accepted for interface symmetry with the risk-scoring policy;
   * rule matching is synchronous and never observes cancellation.
   */
  public evaluate(context: CanonicalContext, _signal?: AbortSignal): PolicyDecision | null {
    const toolName = context.toolName;
    if (!toolName) return null;

    // 0. Tools no rule list gates get a direct verdict, never Tier 2.
    if (!this.isGated(toolName)) {
      const verdict = this.unmappedToolVerdict;
      return {
        decision: verdict,
        reason: unmappedToolReason(toolName, verdict, this.mode),
        tierMatched: 'tier1',
        evidence: { tier1List: verdict === 'allow' ? 'allow' : undefined, mode: this.mode }
      };
    }

    const payload = this.payloadOf(context);
    if (!payload) return null;

    // Hierarchical evaluation: System restrict -> User restrict -> Combined allow
    const systemRestrict = this.systemRestrictRulesByTool.get(toolName) ?? [];
    const userRestrict = this.userRestrictRulesByTool.get(toolName) ?? [];
    const restrictRules = [...systemRestrict, ...userRestrict];

    const systemAllow = this.systemAllowRulesByTool.get(toolName) ?? [];
    const userAllow = this.userAllowRulesByTool.get(toolName) ?? [];
    const allowRules = [...systemAllow, ...userAllow];

    const pathContext = {
      cwd: context.cwd,
      userPaths: this.userPaths
    };

    if (toolName === 'execute_command') {
      return this.astAnalyzer.evaluate(
        payload,
        this.mode,
        restrictRules,
        allowRules,
        SYSTEM_PATHS,
        this.pureReadCommandRules,
        pathContext
      );
    }

    return this.regexAnalyzer.evaluate(
      toolName,
      payload,
      this.mode,
      restrictRules,
      allowRules,
      SYSTEM_PATHS,
      pathContext
    );
  }

  private isGated(toolName: string): boolean {
    return (
      this.systemRestrictRulesByTool.has(toolName) ||
      this.systemAllowRulesByTool.has(toolName) ||
      this.userRestrictRulesByTool.has(toolName) ||
      this.userAllowRulesByTool.has(toolName)
    );
  }

  private payloadOf(context: CanonicalContext): string | undefined {
    const payload = context.payload !== undefined && context.payload !== null
      ? String(context.payload).trim()
      : undefined;

    return payload || undefined;
  }
}
