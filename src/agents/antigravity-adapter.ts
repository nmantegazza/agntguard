#!/usr/bin/env node
import fs from 'node:fs';
import readline from 'node:readline';
import { budgetUserRequests, budgetRecentToolCalls } from './shared/history-format.js';
import { PolicyRuntime } from '../core/runner/policy-runtime.js';
import { fallbackDecision } from '../core/runner/policy-runner.js';
import type {
  CanonicalContext,
  OperatingMode,
  PolicyDecision,
  RecentToolCall,
  Verdict
} from '../types.js';

export interface AntigravityPreToolUsePayload {
  toolCall?: {
    name?: string;
    args?: Record<string, unknown>;
  };
  conversationId?: string;
  workspacePaths?: string[];
  transcriptPath?: string;
  artifactDirectoryPath?: string;
  stepIdx?: number;
  modelName?: string;
  cwd?: string;
  [key: string]: unknown;
}

export interface AntigravityResponse {
  decision: string;
  reason: string;
  permissionOverrides?: string[];
}

export interface AntigravitySessionContext {
  latestUserRequest?: string;
  previousUserRequests?: string[];
  recentToolCalls?: RecentToolCall[];
}

export interface AntigravityContextOptions {
  cwd?: string;
  workspacePaths?: string[];
  toolOverrides?: Record<string, string>;
  signal?: AbortSignal;
}

export const ANTIGRAVITY_TOOL_MAPPINGS: Record<string, string> = {
  run_command: 'execute_command',
  view_file: 'read_file',
  write_to_file: 'write_file',
  replace_file_content: 'write_file',
  edit_file: 'write_file',
  read_url_content: 'fetch_web',
  search_web: 'web_search'
};

const CANONICAL_TOOLS = ['execute_command', 'read_file', 'write_file', 'web_search', 'fetch_web'];

export function parseAntigravityPayload(raw: unknown): AntigravityPreToolUsePayload {
  if (typeof raw === 'string') {
    if (!raw.trim()) return {};
    try {
      return JSON.parse(raw) as AntigravityPreToolUsePayload;
    } catch (err) {
      throw new Error(`Failed to parse Antigravity input JSON: ${(err as Error).message}`);
    }
  }
  if (raw && typeof raw === 'object') return raw as AntigravityPreToolUsePayload;
  return {};
}

export function cleanUserMessage(raw: string): string {
  if (!raw) return '';
  const userRequestMatches = Array.from(raw.matchAll(/<USER_REQUEST>([\s\S]*?)<\/USER_REQUEST>/g));
  let text = '';
  if (userRequestMatches.length > 0) {
    text = userRequestMatches.map((m) => m[1].trim()).join('\n\n');
  } else {
    text = raw
      .replace(/<ADDITIONAL_METADATA>[\s\S]*?<\/ADDITIONAL_METADATA>/g, '')
      .replace(/<USER_SETTINGS_CHANGE>[\s\S]*?<\/USER_SETTINGS_CHANGE>/g, '')
      .replace(/<SYSTEM_INSTRUCTION>[\s\S]*?<\/SYSTEM_INSTRUCTION>/g, '')
      .replace(/<CONTEXT>[\s\S]*?<\/CONTEXT>/g, '');
  }
  text = text.replace(/# Terminal Formatting Guidelines[\s\S]*$/i, '');
  return text.trim();
}

export async function extractAntigravitySessionContext(transcriptPath?: string): Promise<AntigravitySessionContext> {
  if (!transcriptPath || !fs.existsSync(transcriptPath)) {
    return {};
  }
  const userMessages: string[] = [];
  const toolEntries: Array<{ name: string; input?: unknown }> = [];
  try {
    const fileStream = fs.createReadStream(transcriptPath, { encoding: 'utf8' });
    const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });
    for await (const line of rl) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const item = JSON.parse(trimmed) as {
          type?: unknown;
          content?: unknown;
          tool_calls?: unknown;
        };
        if (item.type === 'USER_INPUT' && item.content) {
          const rawContent = typeof item.content === 'string' ? item.content : JSON.stringify(item.content);
          const cleaned = cleanUserMessage(rawContent);
          if (cleaned) userMessages.push(cleaned);
        } else if (item.tool_calls && Array.isArray(item.tool_calls)) {
          for (const tc of item.tool_calls as Array<Record<string, unknown>>) {
            if (!tc || typeof tc !== 'object') continue;
            const nameRaw = typeof tc.toolAction === 'string'
              ? tc.toolAction
              : typeof tc.name === 'string'
                ? tc.name
                : undefined;
            if (!nameRaw) continue;
            const input = tc.args !== undefined
              ? tc.args
              : tc.input !== undefined
                ? tc.input
                : tc.arguments !== undefined
                  ? tc.arguments
                  : undefined;
            toolEntries.push({ name: nameRaw, input });
          }
        }
      } catch {
        // Skip unparseable line
      }
    }
    const mapName = (n: string): string => ANTIGRAVITY_TOOL_MAPPINGS[n] ?? n;
    const { latestUserRequest, previousUserRequests } = budgetUserRequests(userMessages);
    const recentToolCalls = budgetRecentToolCalls(toolEntries, mapName);
    return {
      latestUserRequest,
      previousUserRequests,
      recentToolCalls
    };
  } catch {
    return {};
  }
}

export async function buildAntigravityContext(
  raw: unknown,
  options?: AntigravityContextOptions
): Promise<CanonicalContext> {
  const p = parseAntigravityPayload(raw);
  const toolCall = p.toolCall || {};
  const rawToolName = typeof toolCall.name === 'string' ? toolCall.name : '';
  const args = (toolCall.args && typeof toolCall.args === 'object' ? toolCall.args : {}) as Record<string, unknown>;

  const mappings =
    options?.toolOverrides && Object.keys(options.toolOverrides).length > 0
      ? options.toolOverrides
      : ANTIGRAVITY_TOOL_MAPPINGS;

  let toolName: string;
  if (rawToolName in mappings) {
    toolName = mappings[rawToolName];
  } else if (CANONICAL_TOOLS.includes(rawToolName)) {
    toolName = rawToolName;
  } else {
    toolName = rawToolName || 'unknown_tool';
  }

  const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);
  const summary = str(args.toolSummary)?.trim() || undefined;
  let payload: string | undefined;
  switch (toolName) {
    case 'execute_command':
      payload = str(args.CommandLine) ?? str(args.command) ?? str(args.cmd);
      break;
    case 'read_file':
      payload = str(args.Path) ?? str(args.AbsolutePath) ?? str(args.path) ?? str(args.file);
      break;
    case 'write_file':
      payload = str(args.Path) ?? str(args.TargetFile) ?? str(args.path) ?? str(args.file);
      break;
    case 'web_search':
      payload = str(args.query) ?? str(args.q);
      break;
    case 'fetch_web':
      payload = str(args.Url) ?? str(args.url);
      break;
    default:
      payload = str(args.payload);
      break;
  }

  const workspacePaths = Array.isArray(p.workspacePaths)
    ? p.workspacePaths.filter((w): w is string => typeof w === 'string')
    : (options?.workspacePaths ?? []);

  const cwd =
    str(args.Cwd) ??
    (typeof p.cwd === 'string' && p.cwd.trim() ? p.cwd.trim() : undefined) ??
    options?.cwd ??
    (workspacePaths.length > 0 ? workspacePaths[0] : process.cwd());

  let sessionContext: AntigravitySessionContext = {};
  if (typeof p.transcriptPath === 'string' && p.transcriptPath.trim()) {
    sessionContext = await extractAntigravitySessionContext(p.transcriptPath);
  }

  return {
    agent: 'antigravity',
    toolName,
    payload,
    summary,
    args,
    cwd,
    workspacePaths,
    conversationId: typeof p.conversationId === 'string' ? p.conversationId : undefined,
    stepIdx: typeof p.stepIdx === 'number' ? p.stepIdx : undefined,
    latestUserRequest: sessionContext.latestUserRequest,
    previousUserRequests: sessionContext.previousUserRequests,
    recentToolCalls: sessionContext.recentToolCalls,
    rawInput: p
  };
}

export function formatAntigravityResponse(
  decision: PolicyDecision,
  context?: CanonicalContext,
  mode: OperatingMode = 'auto'
): AntigravityResponse {
  if (decision.decision === 'restrict') {
    // `reason` is already directed at this mode's audience by the reason catalog.
    return { decision: mode === 'ask' ? 'ask' : 'deny', reason: decision.reason };
  }
  return {
    decision: 'allow',
    reason: decision.reason,
    ...(context?.toolName === 'execute_command' && context.payload
      ? { permissionOverrides: [`command(${context.payload})`] }
      : {})
  };
}

export interface AntigravityHandleOptions extends AntigravityContextOptions {
  runtime?: PolicyRuntime;
  configPath?: string;
}

export async function handleAntigravity(
  rawInput: unknown,
  options?: AntigravityHandleOptions
): Promise<AntigravityResponse> {
  const runtime = options?.runtime ?? new PolicyRuntime(options?.configPath);
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
    if (typeof rawInput === 'string' && !rawInput.trim()) {
      throw new Error('Empty input payload received by agntguard hook');
    }
    const context = await buildAntigravityContext(rawInput, options);
    const runner = runtime.getRunner(options?.signal);
    const outcome = await runner.run(context);
    return formatAntigravityResponse(outcome, context, mode);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return formatAntigravityResponse(fallbackDecision(fallback, detail, mode), undefined, mode);
  }
}

export async function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data));
    process.stdin.resume();
  });
}

export async function runCli(): Promise<void> {
  const rawInput = await readStdin();
  const response = await handleAntigravity(rawInput);
  process.stdout.write(JSON.stringify(response) + '\n');
  process.exit(0);
}

export const AntigravityAdapter = {
  name: 'antigravity',
  defaultToolMappings: ANTIGRAVITY_TOOL_MAPPINGS,
  buildContext: buildAntigravityContext,
  formatResponse: formatAntigravityResponse,
  handle: handleAntigravity,
  runCli,
  // Convenience aliases
  normalize: async (raw: unknown, opts?: AntigravityContextOptions) => buildAntigravityContext(raw, opts),
  enrichContext: async (raw: unknown) => {
    const ctx = await buildAntigravityContext(raw);
    return {
      conversationId: ctx.conversationId,
      stepIdx: ctx.stepIdx,
      summary: ctx.summary,
      latestUserRequest: ctx.latestUserRequest,
      previousUserRequests: ctx.previousUserRequests,
      recentToolCalls: ctx.recentToolCalls
    };
  }
};

export const AntigravityAgent = AntigravityAdapter;

const isMain = process.argv[1] && (
  process.argv[1].endsWith('antigravity-adapter.js') ||
  process.argv[1].endsWith('antigravity-adapter.ts') ||
  process.argv[1].endsWith('transport.js')
);

if (isMain) {
  runCli();
}
