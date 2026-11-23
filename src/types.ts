export type Verdict = 'allow' | 'restrict';
export type OperatingMode = 'auto' | 'ask';

export type GitState = 'not_tracked' | 'clean' | 'dirty';

export type RiskDimension = 'harmful' | 'sensitive' | 'opaque' | 'external';
export type Tier2Category = 'safe' | RiskDimension;

export interface RecentToolCall {
  tool: string;
  payload: string;
}

export interface PendingAction {
  tool: string;
  target: string;
  summary?: string;
}

export interface Tier2Policy {
  outside_read: Verdict;
  outside_write: Verdict;
  no_access: string[];
  read_only: string[];
  allowed: string[];
}

/** Agent-agnostic Tier 2 model input. Only universally available, canonical fields. */
export interface Tier2State {
  cwd: string;
  git_state: GitState;
  policy: Tier2Policy;
  latest_user_request: string;
  previous_user_requests: string[];
  recent_tool_calls: RecentToolCall[];
  pending_action: PendingAction;
}

export interface RestrictRule {
  tool: string;
  pattern: string;
  dimension?: RiskDimension;
}

export interface AllowRule {
  tool: string;
  pattern: string;
}

export interface RulesConfig {
  restrict: RestrictRule[];
  allow: AllowRule[];
}

export interface SystemPathsConfig {
  noAccess: string[];
  readOnly: string[];
  allowed: string[];
}

export type ProtectedPathsConfig = SystemPathsConfig;

export interface PathsConfig {
  outside_read: Verdict;
  outside_write: Verdict;
  no_access: string[];
  read_only: string[];
  allowed: string[];
}

export type PathPolicyViolation = 'no_access' | 'read_only' | 'outside_read' | 'outside_write';

export interface AdapterConfig {
  name: string;
  tool_mappings?: Record<string, string>;
}

export interface Tier2Config {
  enabled: boolean;
  provider: string;
  timeout_ms: number;
  model?: string;
}

export interface TelemetryConfig {
  enabled: boolean;
  log_dir: string;
}

export interface AIInteractionRecord {
  provider: string;
  model?: string;
  request?: {
    state?: Tier2State;
    questions?: Record<string, unknown>;
  };
  response?: unknown;
  latencyMs?: number;
  error?: string;
}

export interface PolicyConfig {
  mode?: OperatingMode;
  fallback_verdict?: Verdict;
  unmapped_tool_verdict?: Verdict;
  agent?: string;
  adapter?: AdapterConfig;
  rules: RulesConfig;
  paths?: PathsConfig;
  tier2: Tier2Config;
  telemetry: TelemetryConfig;
}

export interface CanonicalContext {
  agent?: string;
  toolName: string;
  payload?: string;
  summary?: string;
  args?: Record<string, unknown>;
  cwd?: string;
  workspacePaths?: string[];
  gitState?: GitState;
  /** @deprecated Use gitState. Kept for backward-compatible enrichment. */
  isGitRepo?: boolean;
  /** @deprecated Use gitState. Kept for backward-compatible enrichment. */
  hasUncommittedChanges?: boolean;
  policy?: Tier2Policy;
  latestUserRequest?: string;
  previousUserRequests?: string[];
  recentToolCalls?: RecentToolCall[];
  conversationId?: string;
  stepIdx?: number;
  rawInput?: unknown;
}

/**
 * The single outcome type of the policy core.
 *
 * `decision` + `reason` are the gating contract; `evidence` is the diagnostic
 * block (never part of what the host is asked to enforce). `reason` is already
 * directed at the audience implied by `mode`, so no second string exists.
 */
export interface PolicyDecision {
  decision: Verdict;
  reason: string;
  tierMatched: 'tier1' | 'tier2' | 'fallback';
  evidence: {
    tier1List?: 'restrict' | 'allow';
    tier1Dimension?: RiskDimension;
    tier1Pattern?: string;
    pathPolicyViolation?: PathPolicyViolation;
    tier2Category?: Tier2Category;
    tier2LatencyMs?: number;
    breachedDimension?: RiskDimension;
    fallbackVerdict?: Verdict;
    mode?: OperatingMode;
    aiInteraction?: AIInteractionRecord;
  };
}

export interface SessionContext {
  latestUserRequest?: string;
  previousUserRequests?: string[];
  recentToolCalls?: RecentToolCall[];
}

export type PartialCanonicalContext = Partial<CanonicalContext> & Pick<CanonicalContext, 'toolName'>;

export interface ProviderEvaluationOutput {
  category: Tier2Category;
  request?: {
    state?: Tier2State;
    questions?: Record<string, unknown>;
  };
  response?: unknown;
}

export interface DecisionProvider {
  readonly name: string;
  evaluate(context: CanonicalContext, signal?: AbortSignal): Promise<Tier2Category | ProviderEvaluationOutput>;
}
