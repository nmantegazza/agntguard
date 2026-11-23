import type { OperatingMode, PathPolicyViolation, RiskDimension, Verdict } from '../../types.js';

type DimensionKey = RiskDimension | 'generic';

const DIMENSION_REASONS: Record<'restrict' | 'ask', Record<DimensionKey, string>> = {
  restrict: {
    harmful:   'Denied by agntguard: The requested operation was classified as potentially harmful or destructive. You are prohibited from executing destructive operations; select a safe, non-destructive alternative.',
    sensitive: 'Access denied by agntguard: The requested operation targets sensitive system configurations, credentials, or protected resources. You are prohibited from accessing or exfiltrating sensitive data.',
    opaque:    'Execution denied by agntguard: The requested operation involves opaque, obfuscated, or unverified external code whose behavior cannot be determined from the command. You must only run transparent, readable commands and recognizable tools.',
    external:  'Execution denied by agntguard: The requested operation crosses the machine boundary to install external packages or mutate remote state without authorization. Ask the user before installing new packages, pushing to remotes, or sending data to external services.',
    generic:   'Action denied by agntguard policy.'
  },
  ask: {
    harmful:   'The agent is requesting to execute a command that may have potentially destructive or irreversible effects on your environment. Do you want to authorize this operation?',
    sensitive: 'The agent is requesting access to potentially sensitive files, system paths, or credential stores. Do you want to authorize access to these resources?',
    opaque:    'The agent is attempting to run an opaque, obfuscated, or unverified external command whose full behavior cannot be determined upfront. Do you want to permit this operation?',
    external:  'The agent is requesting to install external packages, mutate remote state, or transmit data outside your local environment. Do you want to authorize this operation?',
    generic:   'The agent is requesting a restricted operation. Do you want to authorize this?'
  }
};

const PATH_POLICY_REASONS: Record<'restrict' | 'ask', Record<PathPolicyViolation, string>> = {
  restrict: {
    no_access:     'Access denied by agntguard: The requested path is a protected no-access resource (credentials, secrets, or guard configuration). You are prohibited from reading or modifying this path.',
    read_only:     'Modification denied by agntguard: The requested path is read-only. You may inspect this file using read-only tools, but you are prohibited from modifying, overwriting, or deleting it.',
    outside_read:  'Access denied by agntguard: Reading files outside the active workspace directory is restricted by path policy.',
    outside_write: 'Modification denied by agntguard: Writing or mutating files outside the active workspace directory is restricted by path policy.'
  },
  ask: {
    no_access:     'The agent is requesting access to a protected no-access path (credentials, secrets, or guard configuration). Do you want to authorize access to this path?',
    read_only:     'The agent is requesting to modify or overwrite a read-only path. Do you want to authorize modifying this path?',
    outside_read:  'The agent is requesting to read a file outside the active workspace directory. Do you want to authorize reading this path?',
    outside_write: 'The agent is requesting to write or modify a path outside the active workspace directory. Do you want to authorize this operation?'
  }
};

/**
 * The single place that maps operating mode to audience. Every restricted
 * decision carries exactly one message, synthesized here for the reader the
 * host will actually show it to: the agent in `auto`, the user in `ask`.
 */
function audienceBucket(mode: OperatingMode): 'restrict' | 'ask' {
  return mode === 'ask' ? 'ask' : 'restrict';
}

/** Refusal/prompt for a dimension-tagged restriction. `undefined` → generic bucket. */
export function reasonFor(dimension: RiskDimension | undefined, mode: OperatingMode): string {
  return DIMENSION_REASONS[audienceBucket(mode)][dimension ?? 'generic'];
}

/** Refusal/prompt for a Path Policy Gate (`paths`) restriction. */
export function pathPolicyReason(violation: PathPolicyViolation, mode: OperatingMode): string {
  return PATH_POLICY_REASONS[audienceBucket(mode)][violation];
}

/** Verdict for a tool no rule list gates. */
export function unmappedToolReason(tool: string, verdict: Verdict, mode: OperatingMode): string {
  if (verdict === 'restrict') {
    return mode === 'ask'
      ? `Tool '${tool}' is not configured for policy gating; approval required`
      : `Tool '${tool}' is not configured for policy gating; passing with unmapped tool verdict: ${verdict}`;
  }
  return `Tool '${tool}' is not configured for policy gating; passing with unmapped tool verdict: ${verdict}`;
}

/** Fail-safe message for any internal error path (provider failure, runner throw). */
export function fallbackReason(detail: string, verdict: Verdict, mode: OperatingMode): string {
  if (verdict === 'allow') {
    return `Auto-permissions fallback: ${detail}; permitted by fallback policy`;
  }
  return mode === 'ask'
    ? `Auto-permissions fallback: ${detail}; requires user approval`
    : `Auto-permissions fallback: ${detail}; restricted by fallback policy`;
}

/** Refusal string when the user explicitly rejects an action in an interactive confirmation dialog. */
export function userRejectedReason(): string {
  return 'Action denied: The user explicitly rejected this operation when prompted by agntguard. Do not attempt to bypass or retry this action without asking the user first.';
}

