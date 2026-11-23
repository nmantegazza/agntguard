import type { RecentToolCall } from '../../types.js';

export const MAX_PREVIOUS_REQUEST_CHARS = 500;
export const MAX_PREVIOUS_REQUESTS_TOTAL_CHARS = 2000;
export const TRIMMED_HISTORY_NOTICE = '[Earlier conversation history trimmed for brevity]';
export const MAX_RECENT_TOOL_PAYLOAD_CHARS = 300;
export const MAX_RECENT_TOOLS_TOTAL_CHARS = 1500;
export const MAX_HISTORY_TARGET_CHARS = MAX_RECENT_TOOL_PAYLOAD_CHARS;
export const MAX_HISTORY_ITEMS = 3;

/** Keys checked first when a history input is an object (mirrors both normalizers). */
const PRIORITY_TARGET_KEYS = [
  'CommandLine',
  'commandLine',
  'command',
  'cmd',
  'Path',
  'AbsolutePath',
  'absolutePath',
  'TargetFile',
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

function truncateTarget(value: string, maxChars: number = MAX_RECENT_TOOL_PAYLOAD_CHARS): string {
  const collapsed = collapseWhitespace(value);
  if (!collapsed) return '';
  return collapsed.length > maxChars ? collapsed.slice(0, maxChars) : collapsed;
}

/** Extract a short human-readable target from a history tool input. */
export function resolveHistoryTarget(input: unknown, maxChars: number = MAX_RECENT_TOOL_PAYLOAD_CHARS): string | undefined {
  if (typeof input === 'string') {
    const t = truncateTarget(input, maxChars);
    return t ? t : undefined;
  }
  if (typeof input === 'number' || typeof input === 'boolean') {
    return truncateTarget(String(input), maxChars) || undefined;
  }
  if (Array.isArray(input)) {
    const parts: string[] = [];
    for (const item of input) {
      if (typeof item === 'string' && item.trim()) parts.push(item.trim());
      else if (isRecord(item)) {
        const nested = resolveHistoryTarget(item, maxChars);
        if (nested) parts.push(nested);
      }
      if (parts.join('\n').length >= maxChars) break;
    }
    if (parts.length === 0) return undefined;
    return truncateTarget(parts.join(' '), maxChars) || undefined;
  }
  if (isRecord(input)) {
    for (const key of PRIORITY_TARGET_KEYS) {
      const v = input[key];
      if (typeof v === 'string' && v.trim()) {
        const t = truncateTarget(v, maxChars);
        if (t) return t;
      }
    }
    for (const v of Object.values(input)) {
      if (typeof v === 'string' && v.trim()) {
        const t = truncateTarget(v, maxChars);
        if (t) return t;
      }
    }
    return undefined;
  }
  return undefined;
}

export function formatHistoryEntry(tool: string, target?: unknown): string {
  const name = tool.trim() || 'unknown_tool';
  const resolved = typeof target === 'string' || typeof target === 'number' || typeof target === 'boolean' || Array.isArray(target) || isRecord(target)
    ? resolveHistoryTarget(target)
    : undefined;
  return resolved ? `${name}:${resolved}` : name;
}

/** Map + format + keep last N. Pure, so both enrichers share windowing. */
export function buildRecentHistory(
  entries: ReadonlyArray<{ name: string; input?: unknown }>,
  mapName: (raw: string) => string,
  maxItems: number = MAX_HISTORY_ITEMS
): string[] | undefined {
  const formatted: string[] = [];
  for (const e of entries) {
    if (!e || typeof e.name !== 'string' || !e.name.trim()) continue;
    formatted.push(formatHistoryEntry(mapName(e.name.trim()), e.input));
  }
  const tail = formatted.slice(-maxItems);
  return tail.length > 0 ? tail : undefined;
}

export function budgetUserRequests(rawRequests: ReadonlyArray<string>): {
  latestUserRequest: string;
  previousUserRequests: string[];
} {
  const cleaned = rawRequests.map((r) => r.trim()).filter(Boolean);
  if (cleaned.length === 0) {
    return { latestUserRequest: '', previousUserRequests: [] };
  }
  const latestUserRequest = cleaned[cleaned.length - 1];
  const earlier = cleaned.slice(0, -1);
  if (earlier.length === 0) {
    return { latestUserRequest, previousUserRequests: [] };
  }

  const selected: string[] = [];
  let totalChars = 0;

  for (let i = earlier.length - 1; i >= 0; i--) {
    const item = earlier[i];
    const truncated = item.length > MAX_PREVIOUS_REQUEST_CHARS
      ? item.slice(0, MAX_PREVIOUS_REQUEST_CHARS)
      : item;
    if (totalChars + truncated.length > MAX_PREVIOUS_REQUESTS_TOTAL_CHARS) {
      break;
    }
    selected.unshift(truncated);
    totalChars += truncated.length;
  }

  if (selected.length < earlier.length) {
    selected.unshift(TRIMMED_HISTORY_NOTICE);
  }

  return { latestUserRequest, previousUserRequests: selected };
}

export function budgetRecentToolCalls(
  entries: ReadonlyArray<{ name: string; input?: unknown }>,
  mapName: (raw: string) => string = (n) => n
): RecentToolCall[] {
  const normalized: RecentToolCall[] = [];
  for (const e of entries) {
    if (!e || typeof e.name !== 'string' || !e.name.trim()) continue;
    normalized.push({
      tool: mapName(e.name.trim()),
      payload: resolveHistoryTarget(e.input, MAX_RECENT_TOOL_PAYLOAD_CHARS) ?? ''
    });
  }

  const selected: RecentToolCall[] = [];
  let totalChars = 0;

  for (let i = normalized.length - 1; i >= 0; i--) {
    const item = normalized[i];
    if (totalChars + item.payload.length > MAX_RECENT_TOOLS_TOTAL_CHARS) {
      break;
    }
    selected.unshift(item);
    totalChars += item.payload.length;
  }

  return selected;
}
