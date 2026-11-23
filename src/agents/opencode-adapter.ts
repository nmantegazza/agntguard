import path from 'node:path';
import { Plugin } from '@opencode/plugin';
import { budgetUserRequests, budgetRecentToolCalls } from './shared/history-format.js';
import { PolicyRuntime } from '../core/runner/policy-runtime.js';
import { fallbackDecision } from '../core/runner/policy-runner.js';
import { loadConfig } from '../config.js';
import type {
  CanonicalContext,
  OperatingMode,
  PolicyDecision,
  RecentToolCall,
  SessionContext,
  Verdict
} from '../types.js';

export interface OpencodePermissionEvaluationPayload {
  sessionID?: string;
  agent?: string;
  action?: string;
  resources?: string[];
  metadata?: Record<string, unknown>;
  source?: { type?: string; messageID?: string; id?: string };
  effect?: string;
  message?: string;
  cwd?: string;
  workspacePaths?: string[];
  sessionContext?: {
    latestUserRequest?: string;
    previousUserRequests?: string[];
    recentToolCalls?: RecentToolCall[];
  };
  [key: string]: unknown;
}

export interface OpencodeResponse {
  effect: 'allow' | 'ask' | 'deny';
  message: string;
}

export interface OpencodeSessionHost {
  session?: {
    get?(input: { sessionID: string }): Promise<{
      location?: {
        directory?: string;
        workspaceID?: string;
      };
      subpath?: string;
      [key: string]: unknown;
    }>;
    context(input: { sessionID: string }): Promise<readonly OpencodeContextMessage[] | { messages?: readonly OpencodeContextMessage[] }>;
  };
  location?: {
    directory: string;
  };
  options?: {
    configPath?: string;
    credentialsPath?: string;
    enrichSessionContext?: boolean;
    [key: string]: unknown;
  };
}

export interface OpencodeToolPart {
  type?: unknown;
  name?: unknown;
  input?: unknown;
  args?: unknown;
  arguments?: unknown;
  state?: unknown;
}

export interface OpencodeContextMessage {
  type?: unknown;
  role?: unknown;
  text?: unknown;
  content?: unknown;
  messages?: unknown;
}

export interface OpencodeContextOptions {
  cwd?: string;
  workspacePaths?: string[];
  toolOverrides?: Record<string, string>;
  signal?: AbortSignal;
}

export const OPENCODE_TOOL_MAPPINGS: Record<string, string> = {
  shell: 'execute_command',
  read: 'read_file',
  edit: 'write_file',
  glob: 'read_file',
  grep: 'read_file',
  webfetch: 'fetch_web',
  websearch: 'web_search',
  subagent: 'subagent',
  skill: 'skill'
};

export function parseOpencodePayload(raw: unknown): OpencodePermissionEvaluationPayload {
  if (typeof raw === 'string') {
    if (!raw.trim()) throw new Error('Failed to parse OpenCode PermissionEvaluation payload');
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') return parsed as OpencodePermissionEvaluationPayload;
    } catch {
      // fall through
    }
    throw new Error('Failed to parse OpenCode PermissionEvaluation payload');
  }
  if (raw && typeof raw === 'object') return raw as OpencodePermissionEvaluationPayload;
  throw new Error('Failed to parse OpenCode PermissionEvaluation payload');
}

export async function enrichOpencodeContext(
  raw: unknown,
  host?: OpencodeSessionHost
): Promise<Partial<SessionContext & { conversationId?: string }>> {
  let sessionID: string | undefined;
  if (raw && typeof raw === 'object') {
    const p = raw as { sessionID?: unknown };
    if (typeof p.sessionID === 'string') sessionID = p.sessionID;
  }
  if (!host?.session || !sessionID) return sessionID ? { conversationId: sessionID } : {};
  try {
    const rawData = await host.session.context({ sessionID });
    const messages: readonly OpencodeContextMessage[] = Array.isArray(rawData)
      ? rawData
      : rawData && typeof rawData === 'object' && 'messages' in rawData && Array.isArray((rawData as { messages?: unknown }).messages)
        ? (rawData as { messages: readonly OpencodeContextMessage[] }).messages
        : [];
    const userTexts: string[] = [];
    const toolEntries: Array<{ name: string; input?: unknown }> = [];
    for (const message of messages) {
      if (!message || typeof message !== 'object') continue;
      const m = message as OpencodeContextMessage & { role?: unknown };
      const kind = typeof m.type === 'string' ? m.type : typeof m.role === 'string' ? m.role : undefined;
      if (kind === 'user' && typeof m.text === 'string' && m.text.trim()) {
        userTexts.push(m.text.trim());
      }
      const content = (m as { content?: unknown }).content;
      if ((kind === 'assistant' || kind === undefined) && Array.isArray(content)) {
        for (const part of content as OpencodeToolPart[]) {
          if (!part || typeof part !== 'object') continue;
          const pType = typeof part.type === 'string' ? part.type : undefined;
          if ((pType === 'tool' || pType === 'tool-call') && typeof part.name === 'string') {
            const stateInput =
              part.state !== null &&
              typeof part.state === 'object' &&
              'input' in (part.state as Record<string, unknown>)
                ? (part.state as Record<string, unknown>).input
                : undefined;
            const input = stateInput !== undefined
              ? stateInput
              : 'input' in part && part.input !== undefined
                ? part.input
                : 'args' in part && part.args !== undefined
                  ? part.args
                  : 'arguments' in part
                    ? part.arguments
                    : undefined;
            toolEntries.push({ name: part.name, input });
          }
        }
      }
    }
    if (userTexts.length === 0 && toolEntries.length === 0) {
      return { conversationId: sessionID };
    }
    const mapName = (n: string): string => OPENCODE_TOOL_MAPPINGS[n] ?? n;
    const { latestUserRequest, previousUserRequests } = budgetUserRequests(userTexts);
    const recentToolCalls = budgetRecentToolCalls(toolEntries, mapName);
    return {
      conversationId: sessionID,
      latestUserRequest,
      previousUserRequests,
      recentToolCalls
    };
  } catch {
    return sessionID ? { conversationId: sessionID } : {};
  }
}

const VERDICT_SEVERITY: Record<Verdict, number> = { allow: 0, restrict: 1 };

export async function buildOpencodeContexts(
  raw: unknown,
  host?: OpencodeSessionHost,
  options?: OpencodeContextOptions
): Promise<CanonicalContext[]> {
  const p = parseOpencodePayload(raw);
  const rawAction = typeof p.action === 'string' && p.action ? p.action : 'unknown_action';
  const resources = Array.isArray(p.resources)
    ? p.resources.filter((r): r is string => typeof r === 'string')
    : [];

  const mappings =
    options?.toolOverrides && Object.keys(options.toolOverrides).length > 0
      ? options.toolOverrides
      : OPENCODE_TOOL_MAPPINGS;

  const toolName = rawAction in mappings ? mappings[rawAction] : rawAction;

  const metadataStr =
    p.metadata && typeof p.metadata === 'object' && Object.keys(p.metadata).length > 0
      ? JSON.stringify(p.metadata)
      : undefined;

  let sessionCwd: string | undefined;
  let sessionWorkspaces: string[] | undefined;
  if (host?.session?.get && p.sessionID) {
    try {
      const sess = await host.session.get({ sessionID: p.sessionID });
      const dir = sess?.location?.directory;
      if (typeof dir === 'string' && dir.trim()) {
        sessionWorkspaces = [dir.trim()];
        sessionCwd = sess.subpath ? path.resolve(dir.trim(), sess.subpath) : dir.trim();
      }
    } catch {
      // Keep fallbacks
    }
  }

  const workspacePaths = Array.isArray(p.workspacePaths)
    ? p.workspacePaths.filter((w): w is string => typeof w === 'string')
    : (sessionWorkspaces ?? options?.workspacePaths ?? []);

  const cwd = p.cwd || options?.cwd || sessionCwd || (workspacePaths.length > 0 ? workspacePaths[0] : process.cwd());

  let sessionContext: Partial<SessionContext & { conversationId?: string }> = {};
  if (p.sessionContext) {
    sessionContext = {
      latestUserRequest: p.sessionContext.latestUserRequest,
      previousUserRequests: p.sessionContext.previousUserRequests,
      recentToolCalls: p.sessionContext.recentToolCalls,
      conversationId: p.sessionID
    };
  } else if (host) {
    sessionContext = await enrichOpencodeContext(p, host);
  }

  const base: Omit<CanonicalContext, 'payload'> = {
    agent: 'opencode',
    toolName,
    args: p.metadata,
    cwd,
    workspacePaths,
    conversationId: sessionContext.conversationId || p.sessionID,
    latestUserRequest: sessionContext.latestUserRequest,
    previousUserRequests: sessionContext.previousUserRequests,
    recentToolCalls: sessionContext.recentToolCalls,
    rawInput: p
  };

  if (resources.length > 0) {
    return resources.map((r) => ({
      ...base,
      payload: metadataStr ? `${r} ${metadataStr}` : r
    }));
  }

  return [
    {
      ...base,
      payload: metadataStr
    }
  ];
}

export async function buildOpencodeContext(
  raw: unknown,
  host?: OpencodeSessionHost,
  options?: OpencodeContextOptions
): Promise<CanonicalContext> {
  const contexts = await buildOpencodeContexts(raw, host, options);
  return contexts[0];
}

export function formatOpencodeResponse(
  decision: PolicyDecision,
  _context?: CanonicalContext,
  mode: OperatingMode = 'auto'
): OpencodeResponse {
  // `reason` is already directed at this mode's audience by the reason catalog.
  if (decision.decision === 'restrict') {
    return { effect: mode === 'ask' ? 'ask' : 'deny', message: decision.reason };
  }
  return {
    effect: 'allow',
    message: decision.reason
  };
}

export interface OpencodeHandleOptions extends OpencodeContextOptions {
  runtime?: PolicyRuntime;
  configPath?: string;
  credentialsPath?: string;
}

export async function handleOpencode(
  rawEvent: unknown,
  host?: OpencodeSessionHost,
  options?: OpencodeHandleOptions
): Promise<OpencodeResponse> {
  const runtime = options?.runtime ?? new PolicyRuntime(options?.configPath, options?.credentialsPath);
  let mode: OperatingMode = 'auto';
  let fallback: Verdict = 'allow';

  try {
    const config = runtime.getConfig();
    if (config.mode) mode = config.mode;
    if (config.fallback_verdict) fallback = config.fallback_verdict;
  } catch {
    // Keep defaults
  }

  try {
    const contexts = await buildOpencodeContexts(rawEvent, host, options);
    const runner = runtime.getRunner(options?.signal);

    let worstDecision: PolicyDecision | undefined;
    let worstContext: CanonicalContext | undefined;

    for (const ctx of contexts) {
      const outcome = await runner.run(ctx);
      if (!worstDecision || VERDICT_SEVERITY[outcome.decision] > VERDICT_SEVERITY[worstDecision.decision]) {
        worstDecision = outcome;
        worstContext = ctx;
      }
      if (worstDecision.decision === 'restrict') {
        break;
      }
    }

    return formatOpencodeResponse(worstDecision!, worstContext, mode);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return formatOpencodeResponse(fallbackDecision(fallback, detail, mode), undefined, mode);
  }
}

export const OpencodeAdapter = {
  name: 'opencode',
  defaultToolMappings: OPENCODE_TOOL_MAPPINGS,
  buildContext: buildOpencodeContext,
  buildContexts: buildOpencodeContexts,
  formatResponse: formatOpencodeResponse,
  handle: handleOpencode,
  // Convenience aliases
  normalize: async (raw: unknown, opts?: OpencodeContextOptions) => buildOpencodeContext(raw, undefined, opts),
  normalizeAll: async (raw: unknown, opts?: OpencodeContextOptions) => buildOpencodeContexts(raw, undefined, opts),
  enrichContext: async (raw: unknown, host?: OpencodeSessionHost) => enrichOpencodeContext(raw, host)
};

export const OpencodeAgent = OpencodeAdapter;

const sharedRuntime = new PolicyRuntime();

export default Plugin.define({
  id: 'agntguard',
  async setup(ctx) {
    const options = (ctx.options ?? {}) as {
      configPath?: string;
      credentialsPath?: string;
      enrichSessionContext?: boolean;
    };
    const scopedRuntime =
      options.configPath || options.credentialsPath
        ? new PolicyRuntime(options.configPath, options.credentialsPath)
        : sharedRuntime;

    const registration = await ctx.permission.hook('evaluate', async (event) => {
      let sessionCwd: string | undefined;
      let sessionWorkspaces: string[] | undefined;
      if (ctx.session?.get && event.sessionID) {
        try {
          const session = await ctx.session.get({ sessionID: event.sessionID });
          const dir = session?.location?.directory;
          if (typeof dir === 'string' && dir.trim()) {
            sessionWorkspaces = [dir.trim()];
            sessionCwd = session.subpath ? path.resolve(dir.trim(), session.subpath) : dir.trim();
          }
        } catch {
          // Keep fallbacks
        }
      }

      const response = await handleOpencode(event, options.enrichSessionContext !== false ? ctx : undefined, {
        runtime: scopedRuntime,
        ...(sessionCwd ? { cwd: sessionCwd } : {}),
        ...(sessionWorkspaces ? { workspacePaths: sessionWorkspaces } : {})
      });
      event.effect = response.effect;
      event.message = response.message;
    });

    return () => {
      void registration.dispose();
    };
  }
});
