import fs from 'node:fs';
import path from 'node:path';
import { CanonicalContext, PolicyConfig, PolicyDecision, Tier2Category, Tier2State } from '../../types.js';
import { getDefaultConfigPath, getGlobalLogDir } from '../../config.js';

export interface TelemetryRecord {
  timestamp: string;
  agent?: string;
  conversationId?: string;
  action: {
    toolName: string;
    payload?: string;
    cwd?: string;
  };
  evaluation: {
    tierMatched: 'tier1' | 'tier2' | 'fallback';
    tier1List?: string;
    tier1Pattern?: string;
    tier2Category?: Tier2Category;
    tier2LatencyMs?: number;
    breachedDimension?: string;
  };
  outcome: {
    verdict: string;
    reason: string;
  };
}

export interface AIOutputRecord {
  timestamp: string;
  agent?: string;
  conversationId?: string;
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

export function formatDailyDate(date: Date = new Date()): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

export function resolveLogFilePath(basePath: string, date: Date = new Date()): string {
  const resolved = path.resolve(basePath);
  const dateStr = formatDailyDate(date);
  const dir = resolved.endsWith('.jsonl') ? path.dirname(resolved) : resolved;
  return path.join(dir, dateStr, 'decisions.jsonl');
}

export function resolveLogDirectory(config: PolicyConfig, customLogPath?: string): string {
  if (customLogPath) {
    const resolved = path.resolve(customLogPath);
    if (resolved.endsWith('.jsonl')) {
      return path.dirname(resolved);
    }
    return resolved;
  }

  if (config.telemetry?.log_dir) {
    if (path.isAbsolute(config.telemetry.log_dir)) {
      return config.telemetry.log_dir;
    }
    const configDir = path.dirname(getDefaultConfigPath());
    return path.resolve(configDir, config.telemetry.log_dir);
  }

  return getGlobalLogDir();
}

export class TelemetryLogger {
  private config: PolicyConfig;
  private logDir: string;

  constructor(config: PolicyConfig, customLogPath?: string) {
    this.config = config;
    this.logDir = resolveLogDirectory(config, customLogPath);
  }

  public getLogDir(): string {
    return this.logDir;
  }

  public getDecisionsLogFilePath(date: Date = new Date()): string {
    const dateStr = formatDailyDate(date);
    return path.join(this.logDir, dateStr, 'decisions.jsonl');
  }

  public getOutputsLogFilePath(date: Date = new Date()): string {
    const dateStr = formatDailyDate(date);
    return path.join(this.logDir, dateStr, 'outputs.jsonl');
  }

  // Alias for backward compatibility with existing tests and callers
  public getLogFilePath(date: Date = new Date()): string {
    return this.getDecisionsLogFilePath(date);
  }

  public log(context: CanonicalContext, result: PolicyDecision): void {
    if (!this.config.telemetry.enabled) {
      return; // Zero I/O when disabled
    }

    const now = new Date();

    // 1. Log policy decision to decisions.jsonl
    try {
      const decisionRecord: TelemetryRecord = {
        timestamp: now.toISOString(),
        ...(context.agent ? { agent: context.agent } : {}),
        ...(context.conversationId ? { conversationId: context.conversationId } : {}),
        action: {
          toolName: context.toolName,
          ...(context.payload !== undefined ? { payload: context.payload } : {}),
          ...(context.cwd ? { cwd: context.cwd } : {})
        },
        evaluation: {
          tierMatched: result.tierMatched,
          tier1List: result.evidence.tier1List,
          tier1Pattern: result.evidence.tier1Pattern,
          tier2Category: result.evidence.tier2Category,
          tier2LatencyMs: result.evidence.tier2LatencyMs,
          breachedDimension: result.evidence.breachedDimension ?? result.evidence.tier1Dimension
        },
        outcome: {
          verdict: result.decision,
          reason: result.reason
        }
      };

      const decisionsPath = this.getDecisionsLogFilePath(now);
      this.ensureDirAndAppend(decisionsPath, JSON.stringify(decisionRecord) + '\n');
    } catch {
      // Resilience: Never interrupt execution due to logging failure
    }

    // 2. If Tier 2 AI was called, log prompt request & raw output to outputs.jsonl
    const aiInteraction = result.evidence.aiInteraction;
    if (aiInteraction) {
      try {
        const outputRecord: AIOutputRecord = {
          timestamp: now.toISOString(),
          ...(context.agent ? { agent: context.agent } : {}),
          ...(context.conversationId ? { conversationId: context.conversationId } : {}),
          provider: aiInteraction.provider,
          ...(aiInteraction.model ? { model: aiInteraction.model } : {}),
          ...(aiInteraction.request ? { request: aiInteraction.request } : {}),
          ...(aiInteraction.response !== undefined ? { response: aiInteraction.response } : {}),
          ...(aiInteraction.latencyMs !== undefined ? { latencyMs: aiInteraction.latencyMs } : {}),
          ...(aiInteraction.error ? { error: aiInteraction.error } : {})
        };

        const outputsPath = this.getOutputsLogFilePath(now);
        this.ensureDirAndAppend(outputsPath, JSON.stringify(outputRecord) + '\n');
      } catch {
        // Resilience: Never interrupt execution due to logging failure
      }
    }
  }

  private ensureDirAndAppend(filePath: string, data: string): void {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.appendFileSync(filePath, data, 'utf8');
  }
}
