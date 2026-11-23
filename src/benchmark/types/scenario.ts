import { z } from 'zod';
import type { GitState, Tier2Category, Verdict } from '../../types.js';

export type { GitState };

/**
 * Single tool invocation.
 * Standardized across both historical transcript steps and the pending intercepted action.
 */
export interface ToolCall {
  name: string;
  args: Record<string, unknown>;
}

export const ToolCallSchema = z.object({
  name: z.string().min(1, 'Tool name is required'),
  args: z.record(z.string(), z.unknown())
});

export interface UserTurn {
  role: 'user';
  content: string;
}

export const UserTurnSchema = z.object({
  role: z.literal('user'),
  content: z.string()
});

export interface AssistantTurn {
  role: 'assistant';
  content: string;
}

export const AssistantTurnSchema = z.object({
  role: z.literal('assistant'),
  content: z.string()
});

export interface ToolTurn {
  role: 'tool';
  calls: ToolCall[];
}

export const ToolTurnSchema = z.object({
  role: z.literal('tool'),
  calls: z.array(ToolCallSchema)
});

export type TranscriptTurn = UserTurn | AssistantTurn | ToolTurn;

export const TranscriptTurnSchema = z.discriminatedUnion('role', [
  UserTurnSchema,
  AssistantTurnSchema,
  ToolTurnSchema
]);

export interface ScenarioPathsOverride {
  outside_read?: Verdict;
  outside_write?: Verdict;
  no_access?: string[];
  read_only?: string[];
  allowed?: string[];
}

export const ScenarioPathsOverrideSchema = z.object({
  outside_read: z.enum(['allow', 'restrict']).optional(),
  outside_write: z.enum(['allow', 'restrict']).optional(),
  no_access: z.array(z.string()).optional(),
  read_only: z.array(z.string()).optional(),
  allowed: z.array(z.string()).optional()
});

export interface ScenarioEnvironment {
  cwd: string;
  git_state: GitState;
  git_branch?: string;
  paths?: ScenarioPathsOverride;
}

export const ScenarioEnvironmentSchema = z.object({
  cwd: z.string().min(1, 'cwd must not be empty'),
  git_state: z.enum(['not_tracked', 'clean', 'dirty']),
  git_branch: z.string().optional(),
  paths: ScenarioPathsOverrideSchema.optional()
});

export interface ScenarioGroundTruth {
  verdict: 'allow' | 'restrict';
  category: Tier2Category;
  rationale?: string;
}

export const ScenarioGroundTruthSchema = z.object({
  verdict: z.enum(['allow', 'restrict']),
  category: z.enum(['safe', 'harmful', 'sensitive', 'opaque', 'external']),
  rationale: z.string().optional()
});

/**
 * A standalone benchmark test fixture capturing an agent session up to an
 * intercepted action, with environment metadata and ground truth.
 */
export interface Scenario {
  id: string;
  description: string;
  pair_id?: string;
  environment: ScenarioEnvironment;
  transcript: TranscriptTurn[];
  intercepted_action: ToolCall;
  ground_truth: ScenarioGroundTruth;
}

export const ScenarioSchema = z.object({
  id: z.string().min(1, 'Scenario id is required'),
  description: z.string().min(1, 'Description is required'),
  pair_id: z.string().optional(),
  environment: ScenarioEnvironmentSchema,
  transcript: z.array(TranscriptTurnSchema),
  intercepted_action: ToolCallSchema,
  ground_truth: ScenarioGroundTruthSchema
});

/**
 * Validate and parse a raw JSON scenario into a typed Scenario.
 * Throws a ZodError if validation fails.
 */
export function parseScenario(raw: unknown): Scenario {
  return ScenarioSchema.parse(raw);
}

export type SafeParseScenarioResult = ReturnType<typeof ScenarioSchema.safeParse>;

/**
 * Safely parse a raw scenario without throwing.
 */
export function safeParseScenario(raw: unknown): SafeParseScenarioResult {
  return ScenarioSchema.safeParse(raw);
}
