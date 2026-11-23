import type { StateProjector } from '../types/projector.js';
import type { Scenario } from '../types/scenario.js';
import type { PathsConfig, Tier2State } from '../../types.js';
import { ANTIGRAVITY_TOOL_MAPPINGS } from '../../agents/antigravity-adapter.js';
import { budgetUserRequests, budgetRecentToolCalls } from '../../agents/shared/history-format.js';
import { buildTier2Policy, DEFAULT_PATHS_CONFIG, SYSTEM_PATHS } from '../../core/defaults/system-rules.js';

export const MAX_HISTORY_TARGET_CHARS = 100;
export const MAX_HISTORY_ITEMS = 3;

const PRIORITY_TARGET_KEYS = [
  'CommandLine',
  'commandLine',
  'command',
  'cmd',
  'Path',
  'AbsolutePath',
  'absolutePath',
  'TargetFile',
  'targetFile',
  'path',
  'filePath',
  'file',
  'Url',
  'url',
  'query',
  'q',
  'pattern',
  'payload',
  'text'
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function collapseWhitespace(value: string): string {
  return value.replace(/\s+/g, ' ').trim();
}

/**
 * Resolve the target resource string from tool arguments.
 * Checks tool-specific Antigravity argument conventions first,
 * then falls back to generic target keys or first string property.
 * Returns untruncated target.
 */
export function resolveToolTarget(toolName: string, args: Record<string, unknown> | undefined): string | null {
  if (!args || !isRecord(args)) {
    return null;
  }

  const str = (v: unknown): string | null => {
    if (typeof v === 'string' && v.trim()) return v.trim();
    return null;
  };

  let candidate: string | null = null;

  switch (toolName) {
    case 'run_command':
    case 'execute_command':
    case 'shell':
    case 'bash':
      candidate = str(args.CommandLine) ?? str(args.command) ?? str(args.cmd);
      break;
    case 'view_file':
    case 'read_file':
    case 'read':
    case 'glob':
    case 'grep':
      candidate = str(args.Path) ?? str(args.AbsolutePath) ?? str(args.path) ?? str(args.file);
      break;
    case 'write_to_file':
    case 'replace_file_content':
    case 'edit_file':
    case 'write_file':
    case 'edit':
      candidate = str(args.Path) ?? str(args.TargetFile) ?? str(args.path) ?? str(args.file);
      break;
    case 'read_url_content':
    case 'fetch_web':
    case 'webfetch':
      candidate = str(args.Url) ?? str(args.url);
      break;
    case 'search_web':
    case 'web_search':
    case 'websearch':
      candidate = str(args.query) ?? str(args.q);
      break;
    default:
      candidate = str(args.payload);
      break;
  }

  if (candidate) {
    return collapseWhitespace(candidate);
  }

  // Fallback: check general priority keys
  for (const key of PRIORITY_TARGET_KEYS) {
    const v = args[key];
    if (typeof v === 'string' && v.trim()) {
      return collapseWhitespace(v.trim());
    }
  }

  // Fallback: check any string property in args
  for (const v of Object.values(args)) {
    if (typeof v === 'string' && v.trim()) {
      return collapseWhitespace(v.trim());
    }
  }

  return null;
}

export function resolveToolSummary(args: Record<string, unknown> | undefined): string | undefined {
  if (args && typeof args.toolSummary === 'string' && args.toolSummary.trim()) {
    return args.toolSummary.trim();
  }
  return undefined;
}

/**
 * Translates an uncompressed Scenario fixture directly into a Tier2State model payload.
 */
export function projectBaselineState(scenario: Scenario): Tier2State {
  const rawTool = scenario.intercepted_action.name.trim();
  const mapTool = (n: string): string => ANTIGRAVITY_TOOL_MAPPINGS[n] ?? n;
  const target = resolveToolTarget(rawTool, scenario.intercepted_action.args);

  if (!target) {
    throw new Error(
      `Failed to project scenario "${scenario.id}": could not resolve target resource for tool "${rawTool}". ` +
      `Tier 2 evaluation requires a non-empty target.`
    );
  }

  const summary = resolveToolSummary(scenario.intercepted_action.args);

  // Extract user messages
  const userMessages: string[] = [];
  for (const turn of scenario.transcript) {
    if (turn.role === 'user' && turn.content && turn.content.trim()) {
      userMessages.push(turn.content.trim());
    }
  }

  const { latestUserRequest, previousUserRequests } = budgetUserRequests(userMessages);

  // Extract historical tool calls
  const toolEntries: Array<{ name: string; input?: unknown }> = [];
  for (const turn of scenario.transcript) {
    if (turn.role === 'tool' && Array.isArray(turn.calls)) {
      for (const call of turn.calls) {
        if (call && typeof call.name === 'string' && call.name.trim()) {
          toolEntries.push({ name: call.name, input: call.args });
        }
      }
    }
  }

  const recentToolCalls = budgetRecentToolCalls(toolEntries, mapTool);

  const mergedPaths: PathsConfig = {
    outside_read: scenario.environment.paths?.outside_read ?? DEFAULT_PATHS_CONFIG.outside_read,
    outside_write: scenario.environment.paths?.outside_write ?? DEFAULT_PATHS_CONFIG.outside_write,
    no_access: scenario.environment.paths?.no_access ?? DEFAULT_PATHS_CONFIG.no_access,
    read_only: scenario.environment.paths?.read_only ?? DEFAULT_PATHS_CONFIG.read_only,
    allowed: scenario.environment.paths?.allowed ?? DEFAULT_PATHS_CONFIG.allowed
  };
  const policy = buildTier2Policy(mergedPaths, SYSTEM_PATHS, scenario.environment.cwd);

  return {
    cwd: scenario.environment.cwd,
    git_state: scenario.environment.git_state,
    policy,
    latest_user_request: latestUserRequest,
    previous_user_requests: previousUserRequests,
    recent_tool_calls: recentToolCalls,
    pending_action: {
      tool: mapTool(rawTool),
      target,
      ...(summary ? { summary } : {})
    }
  };
}

/**
 * Baseline State Projector class implementing the StateProjector interface.
 */
export class BaselineStateProjector implements StateProjector {
  public readonly name = 'baseline';

  public project(scenario: Scenario): Tier2State {
    return projectBaselineState(scenario);
  }
}
