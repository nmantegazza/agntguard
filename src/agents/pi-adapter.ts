import { budgetUserRequests, budgetRecentToolCalls } from './shared/history-format.js';
import { PolicyRuntime } from '../core/runner/policy-runtime.js';
import { fallbackDecision } from '../core/runner/policy-runner.js';
import { reasonFor, userRejectedReason } from '../core/engine/reason-catalog.js';
import type {
  CanonicalContext,
  OperatingMode,
  PolicyDecision,
  SessionContext,
  Verdict
} from '../types.js';

export interface PiToolCallEvent {
  type: 'tool_call';
  toolCallId?: string;
  toolName: string;
  input: Record<string, unknown>;
}

export interface PiToolCallEventResult {
  block?: boolean;
  reason?: string;
}

export interface PiSessionMessage {
  role?: string;
  content?: string | Array<string | { type?: string; text?: string; [key: string]: unknown }>;
  parts?: Array<{
    type?: string;
    text?: string;
    name?: string;
    toolName?: string;
    tool?: string;
    input?: unknown;
    args?: unknown;
    arguments?: unknown;
    [key: string]: unknown;
  }>;
  text?: string;
  [key: string]: unknown;
}

export interface PiSessionManager {
  getSessionId(): string;
  getBranch(): PiSessionMessage[];
}

export interface PiUI {
  confirm(title: string, message: string): Promise<boolean>;
}

export interface PiExtensionContext {
  sessionManager?: PiSessionManager;
  ui?: PiUI;
  hasUI?: boolean;
  signal?: AbortSignal;
  cwd?: string;
  [key: string]: unknown;
}

export interface PiExtensionAPI {
  on(
    event: 'tool_call',
    handler: (event: PiToolCallEvent, ctx: PiExtensionContext) => Promise<PiToolCallEventResult | undefined>
  ): void;
  [key: string]: unknown;
}

export interface PiResponse {
  effect: 'allow' | 'ask' | 'deny';
  reason: string;
}

export interface PiContextOptions {
  cwd?: string;
  workspacePaths?: string[];
  toolOverrides?: Record<string, string>;
  signal?: AbortSignal;
}

export interface PiHandleOptions extends PiContextOptions {
  runtime?: PolicyRuntime;
  configPath?: string;
  credentialsPath?: string;
}

export const PI_TOOL_MAPPINGS: Record<string, string> = {
  bash: 'execute_command',
  powershell: 'execute_command',
  read: 'read_file',
  write: 'write_file',
  edit: 'write_file',
  ls: 'read_file',
  find: 'read_file',
  grep: 'read_file'
};

export function parsePiPayload(raw: unknown): PiToolCallEvent {
  let obj: unknown = raw;
  if (typeof raw === 'string') {
    if (!raw.trim()) throw new Error('Failed to parse Pi ToolCall payload');
    try {
      obj = JSON.parse(raw);
    } catch {
      throw new Error('Failed to parse Pi ToolCall payload');
    }
  }
  if (obj && typeof obj === 'object') {
    const record = obj as Record<string, unknown>;
    const toolName =
      typeof record.toolName === 'string' && record.toolName
        ? record.toolName
        : typeof record.tool === 'string' && record.tool
          ? record.tool
          : typeof (record.toolCall as { name?: unknown })?.name === 'string' && (record.toolCall as { name: string }).name
            ? (record.toolCall as { name: string }).name
            : 'unknown_tool';
    const input =
      record.input && typeof record.input === 'object' && !Array.isArray(record.input)
        ? (record.input as Record<string, unknown>)
        : record.args && typeof record.args === 'object' && !Array.isArray(record.args)
          ? (record.args as Record<string, unknown>)
          : {};
    return {
      type: 'tool_call',
      toolCallId:
        typeof record.toolCallId === 'string'
          ? record.toolCallId
          : typeof (record.toolCall as { id?: unknown })?.id === 'string'
            ? (record.toolCall as { id: string }).id
            : undefined,
      toolName,
      input
    };
  }
  throw new Error('Failed to parse Pi ToolCall payload');
}

export async function enrichPiContext(
  ctx?: PiExtensionContext
): Promise<Partial<SessionContext & { conversationId?: string }>> {
  if (!ctx?.sessionManager) return {};
  let conversationId: string | undefined;
  try {
    if (typeof ctx.sessionManager.getSessionId === 'function') {
      conversationId = ctx.sessionManager.getSessionId();
    }
  } catch {
    // Graceful degradation
  }

  try {
    if (typeof ctx.sessionManager.getBranch !== 'function') {
      return conversationId ? { conversationId } : {};
    }
    const branch = ctx.sessionManager.getBranch();
    if (!Array.isArray(branch)) {
      return conversationId ? { conversationId } : {};
    }

    const userTexts: string[] = [];
    const toolEntries: Array<{ name: string; input?: unknown }> = [];

    for (const msg of branch) {
      if (!msg || typeof msg !== 'object') continue;
      const role = msg.role;

      if (role === 'user') {
        if (typeof msg.content === 'string' && msg.content.trim()) {
          userTexts.push(msg.content.trim());
        } else if (typeof msg.text === 'string' && msg.text.trim()) {
          userTexts.push(msg.text.trim());
        } else if (Array.isArray(msg.content)) {
          for (const item of msg.content) {
            if (typeof item === 'string' && item.trim()) {
              userTexts.push(item.trim());
            } else if (item && typeof item === 'object') {
              const text = (item as { text?: unknown }).text;
              if (typeof text === 'string' && text.trim()) {
                userTexts.push(text.trim());
              }
            }
          }
        } else if (Array.isArray(msg.parts)) {
          for (const part of msg.parts) {
            if (part && typeof part === 'object' && typeof part.text === 'string' && part.text.trim()) {
              userTexts.push(part.text.trim());
            }
          }
        }
      } else if (role === 'assistant') {
        if (Array.isArray(msg.parts)) {
          for (const part of msg.parts) {
            if (!part || typeof part !== 'object') continue;
            const name =
              typeof part.name === 'string'
                ? part.name
                : typeof part.toolName === 'string'
                  ? part.toolName
                  : typeof part.tool === 'string'
                    ? part.tool
                    : undefined;
            if (name) {
              const input = part.input !== undefined ? part.input : (part.args !== undefined ? part.args : part.arguments);
              toolEntries.push({ name, input });
            }
          }
        }
        if (Array.isArray(msg.content)) {
          for (const part of msg.content) {
            if (!part || typeof part !== 'object') continue;
            const name =
              typeof (part as { name?: unknown }).name === 'string'
                ? (part as { name: string }).name
                : typeof (part as { toolName?: unknown }).toolName === 'string'
                  ? (part as { toolName: string }).toolName
                  : typeof (part as { tool?: unknown }).tool === 'string'
                    ? (part as { tool: string }).tool
                    : undefined;
            if (name) {
              const input =
                (part as { input?: unknown }).input !== undefined
                  ? (part as { input?: unknown }).input
                  : (part as { args?: unknown }).args !== undefined
                    ? (part as { args?: unknown }).args
                    : (part as { arguments?: unknown }).arguments;
              toolEntries.push({ name, input });
            }
          }
        }
      }
    }

    if (userTexts.length === 0 && toolEntries.length === 0) {
      return conversationId ? { conversationId } : {};
    }

    const mapName = (n: string): string => PI_TOOL_MAPPINGS[n] ?? n;
    const { latestUserRequest, previousUserRequests } = budgetUserRequests(userTexts);
    const recentToolCalls = budgetRecentToolCalls(toolEntries, mapName);
    return {
      conversationId,
      latestUserRequest,
      previousUserRequests,
      recentToolCalls
    };
  } catch {
    return conversationId ? { conversationId } : {};
  }
}

export async function buildPiContexts(
  rawEvent: unknown,
  ctx?: PiExtensionContext,
  options?: PiContextOptions
): Promise<CanonicalContext[]> {
  const event = parsePiPayload(rawEvent);
  const rawToolName = event.toolName || 'unknown_tool';
  const input = event.input || {};

  const mappings =
    options?.toolOverrides && Object.keys(options.toolOverrides).length > 0
      ? options.toolOverrides
      : PI_TOOL_MAPPINGS;

  const toolName = rawToolName in mappings ? mappings[rawToolName] : rawToolName;

  const cwd = ctx?.cwd || options?.cwd || process.cwd();
  const workspacePaths = Array.isArray(options?.workspacePaths)
    ? options.workspacePaths.filter((w): w is string => typeof w === 'string')
    : ctx?.cwd ? [ctx.cwd] : [process.cwd()];

  let sessionContext: Partial<SessionContext & { conversationId?: string }> = {};
  if (ctx) {
    sessionContext = await enrichPiContext(ctx);
  }

  const base: Omit<CanonicalContext, 'payload'> = {
    agent: 'pi',
    toolName,
    args: input,
    cwd,
    workspacePaths,
    conversationId: sessionContext.conversationId,
    latestUserRequest: sessionContext.latestUserRequest,
    previousUserRequests: sessionContext.previousUserRequests,
    recentToolCalls: sessionContext.recentToolCalls,
    rawInput: event
  };

  if (rawToolName === 'bash' || rawToolName === 'powershell') {
    const cmd = typeof input.command === 'string' ? input.command : (typeof input.cmd === 'string' ? input.cmd : undefined);
    return [{ ...base, payload: cmd }];
  }

  if (rawToolName === 'read' || rawToolName === 'write' || rawToolName === 'edit') {
    const p = typeof input.path === 'string' ? input.path : (typeof input.filePath === 'string' ? input.filePath : (typeof input.file === 'string' ? input.file : undefined));
    return [{ ...base, payload: p }];
  }

  if (rawToolName === 'ls') {
    const p = typeof input.path === 'string' && input.path.trim() ? input.path.trim() : '.';
    return [{ ...base, payload: p }];
  }

  if (rawToolName === 'find') {
    const candidates: string[] = [];
    if (typeof input.path === 'string' && input.path.trim()) candidates.push(input.path.trim());
    if (typeof input.pattern === 'string' && input.pattern.trim()) candidates.push(input.pattern.trim());
    const targetPaths = candidates.length > 0 ? Array.from(new Set(candidates)) : ['.'];
    return targetPaths.map((p) => ({ ...base, payload: p }));
  }

  if (rawToolName === 'grep') {
    const candidates: string[] = [];
    if (typeof input.path === 'string' && input.path.trim()) candidates.push(input.path.trim());
    if (typeof input.glob === 'string' && input.glob.trim()) candidates.push(input.glob.trim());
    const targetPaths = candidates.length > 0 ? Array.from(new Set(candidates)) : ['.'];
    return targetPaths.map((p) => ({ ...base, payload: p }));
  }

  let payload: string | undefined;
  if (typeof input.payload === 'string') {
    payload = input.payload;
  } else if (typeof input.command === 'string') {
    payload = input.command;
  } else if (typeof input.path === 'string') {
    payload = input.path;
  } else if (Object.keys(input).length > 0) {
    payload = JSON.stringify(input);
  }

  return [{ ...base, payload }];
}

export async function buildPiContext(
  rawEvent: unknown,
  ctx?: PiExtensionContext,
  options?: PiContextOptions
): Promise<CanonicalContext> {
  const contexts = await buildPiContexts(rawEvent, ctx, options);
  return contexts[0];
}

export function formatPiResponse(
  decision: PolicyDecision,
  _context?: CanonicalContext,
  mode: OperatingMode = 'auto'
): PiResponse {
  if (decision.decision === 'restrict') {
    return { effect: mode === 'ask' ? 'ask' : 'deny', reason: decision.reason };
  }
  return {
    effect: 'allow',
    reason: decision.reason
  };
}

const VERDICT_SEVERITY: Record<Verdict, number> = { allow: 0, restrict: 1 };

export async function handlePiToolCall(
  rawEvent: unknown,
  ctx?: PiExtensionContext,
  options?: PiHandleOptions
): Promise<PiToolCallEventResult | undefined> {
  const effectiveCtx: PiExtensionContext = ctx ?? {};
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

  let response: PiResponse;
  try {
    const contexts = await buildPiContexts(rawEvent, effectiveCtx, options);
    const runner = runtime.getRunner(options?.signal ?? effectiveCtx.signal);

    let worstDecision: PolicyDecision | undefined;
    let worstContext: CanonicalContext | undefined;

    for (const c of contexts) {
      const outcome = await runner.run(c);
      if (!worstDecision || VERDICT_SEVERITY[outcome.decision] > VERDICT_SEVERITY[worstDecision.decision]) {
        worstDecision = outcome;
        worstContext = c;
      }
      if (worstDecision.decision === 'restrict') {
        break;
      }
    }

    response = formatPiResponse(worstDecision!, worstContext, mode);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    response = formatPiResponse(fallbackDecision(fallback, detail, mode), undefined, mode);
  }

  if (response.effect === 'allow') {
    return undefined;
  }

  if (response.effect === 'deny') {
    return { block: true, reason: response.reason };
  }

  // Ask mode (response.effect === 'ask')
  if (effectiveCtx.hasUI && effectiveCtx.ui && typeof effectiveCtx.ui.confirm === 'function') {
    const approved = await effectiveCtx.ui.confirm('AgntGuard Permission Request', response.reason);
    if (approved) {
      return undefined;
    }
    return { block: true, reason: userRejectedReason() };
  }

  return { block: true, reason: reasonFor(undefined, 'auto') };
}

export const PiAdapter = {
  name: 'pi',
  defaultToolMappings: PI_TOOL_MAPPINGS,
  parsePayload: parsePiPayload,
  buildContext: buildPiContext,
  buildContexts: buildPiContexts,
  enrichContext: enrichPiContext,
  formatResponse: formatPiResponse,
  handle: handlePiToolCall,
  normalize: async (raw: unknown, ctx?: PiExtensionContext, opts?: PiContextOptions) =>
    buildPiContext(raw, ctx, opts),
  normalizeAll: async (raw: unknown, ctx?: PiExtensionContext, opts?: PiContextOptions) =>
    buildPiContexts(raw, ctx, opts)
};

export const PiAgent = PiAdapter;

const sharedRuntime = new PolicyRuntime();

export default function agntguardExtension(pi: PiExtensionAPI, extensionOptions?: PiHandleOptions): void {
  pi.on('tool_call', async (event: PiToolCallEvent, ctx: PiExtensionContext) => {
    const customConfigPath =
      extensionOptions?.configPath ??
      (ctx as { options?: { configPath?: string } })?.options?.configPath ??
      process.env.AGNTGUARD_CONFIG;
    const runtime =
      extensionOptions?.runtime ??
      (customConfigPath ? new PolicyRuntime(customConfigPath, extensionOptions?.credentialsPath) : sharedRuntime);
    return await handlePiToolCall(event, ctx, { ...extensionOptions, runtime });
  });
}

