import { readdirSync, readFileSync, statSync } from 'node:fs';
import { resolve, join, extname } from 'node:path';
import type {
  BenchmarkOptions,
  BenchmarkMetrics,
  ConfusionMatrix,
  RunArtifact,
  ScenarioResult
} from '../types/metrics.js';
import { parseScenario, type Scenario } from '../types/scenario.js';
import { BaselineStateProjector } from '../projectors/baseline-projector.js';
import { RiskScoringPolicy } from '../../core/engine/risk-scoring-policy.js';
import { createProvider } from '../../providers/factory.js';
import { TypeSafeProvider } from '../../providers/typesafe-provider.js';
import { MockProvider } from '../../providers/mock-provider.js';
import { loadApiKey } from '../../credentials.js';
import { loadConfig } from '../../config.js';
import { writeRunArtifact, type ArtifactWriteResult } from './artifact-writer.js';
import { computeConfusionMatrix, computeMetrics } from './metrics.js';
import type {
  CanonicalContext,
  DecisionProvider,
  Tier2Config,
  Tier2State
} from '../../types.js';

/**
 * Lightweight adapter mapping projected Tier2State into CanonicalContext.
 */
export function tier2StateToCanonicalContext(state: Tier2State): CanonicalContext {
  return {
    toolName: state.pending_action.tool,
    payload: state.pending_action.target,
    summary: state.pending_action.summary,
    cwd: state.cwd,
    gitState: state.git_state,
    policy: state.policy,
    latestUserRequest: state.latest_user_request,
    previousUserRequests: state.previous_user_requests,
    recentToolCalls: state.recent_tool_calls
  };
}

export interface RunnerExecutionResult {
  artifact: RunArtifact;
  artifactPaths?: ArtifactWriteResult;
}

export type ScenarioProgressCallback = (
  result: ScenarioResult,
  index: number,
  total: number
) => void;

/**
 * Isolated Tier 2 Benchmark Runner.
 * Executes scenario fixtures directly against Tier 2 risk scoring policies,
 * bypassing Tier 1 regex analyzers.
 */
export class BenchmarkRunner {
  private projector = new BaselineStateProjector();

  /**
   * Discover and load scenario fixtures from a directory or specific file path.
   */
  public loadScenarios(targetPath: string): Scenario[] {
    const resolvedPath = resolve(targetPath);
    const stat = statSync(resolvedPath);

    if (stat.isFile()) {
      const content = readFileSync(resolvedPath, 'utf-8');
      return [parseScenario(JSON.parse(content))];
    }

    if (stat.isDirectory()) {
      const entries = readdirSync(resolvedPath);
      const scenarios: Scenario[] = [];

      for (const entry of entries) {
        if (extname(entry).toLowerCase() === '.json') {
          const filePath = join(resolvedPath, entry);
          try {
            const content = readFileSync(filePath, 'utf-8');
            scenarios.push(parseScenario(JSON.parse(content)));
          } catch (err: any) {
            throw new Error(`Failed parsing scenario at "${filePath}": ${err.message}`);
          }
        }
      }

      return scenarios;
    }

    throw new Error(`Path "${targetPath}" is neither a valid file nor directory.`);
  }

  /**
   * Resolve and instantiate the decision provider.
   */
  public resolveProvider(options?: BenchmarkOptions): DecisionProvider {
    if (options?.provider === 'mock') {
      return new MockProvider();
    }

    if (options?.provider === 'typesafe') {
      return new TypeSafeProvider({ model: options.model });
    }

    // Auto-detection: prefer TypeSafe if API key exists, otherwise fallback to Mock
    const apiKey = loadApiKey();
    if (apiKey) {
      return new TypeSafeProvider({ model: options?.model });
    }

    return new MockProvider();
  }

  /**
   * Execute the benchmark runner across all discovered scenarios.
   */
  public async run(
    options?: BenchmarkOptions,
    onProgress?: ScenarioProgressCallback
  ): Promise<RunnerExecutionResult> {
    const startTime = Date.now();
    const scenariosPath = options?.scenariosPath
      ? resolve(options.scenariosPath)
      : resolve(process.cwd(), 'benchmarks', 'scenarios');

    const scenarios = this.loadScenarios(scenariosPath);
    if (scenarios.length === 0) {
      throw new Error(`No scenario JSON fixtures found at "${scenariosPath}".`);
    }

    const provider = this.resolveProvider(options);
    const baseConfig = loadConfig();

    const tier2Config: Tier2Config = {
      enabled: true,
      provider: provider.name,
      timeout_ms: baseConfig.tier2.timeout_ms || 30000,
      model: options?.model || baseConfig.tier2.model || 'jev-latest'
    };

    // Instantiate Tier 2 isolated policy (bypassing Tier 1 regex engine)
    const policy = new RiskScoringPolicy(
      tier2Config,
      provider,
      'allow',
      'auto'
    );

    const results: ScenarioResult[] = [];

    // Strictly sequential execution
    for (let i = 0; i < scenarios.length; i++) {
      const scenario = scenarios[i];
      const scenarioStartTime = Date.now();

      try {
        const projectedState = this.projector.project(scenario);
        const canonicalContext = tier2StateToCanonicalContext(projectedState);

        const decision = await policy.evaluate(canonicalContext);
        const latencyMs = Date.now() - scenarioStartTime;

        const category = decision.evidence.tier2Category;
        const breachedDimension = decision.evidence.breachedDimension;
        const inputPayload =
          decision.evidence.aiInteraction?.request ?? projectedState;
        const inputChars = JSON.stringify(inputPayload).length;

        const predictedVerdict = decision.decision;
        const matched = predictedVerdict === scenario.ground_truth.verdict;
        const categoryMatched = category === scenario.ground_truth.category;

        const result: ScenarioResult = {
          id: scenario.id,
          ground_truth: scenario.ground_truth.verdict,
          ground_truth_category: scenario.ground_truth.category,
          predicted_verdict: predictedVerdict,
          predicted_category: category,
          matched,
          category_matched: categoryMatched,
          latency_ms: latencyMs,
          category,
          breached_dimension: breachedDimension,
          input_payload: inputPayload,
          input_chars: inputChars
        };

        results.push(result);
        if (onProgress) {
          onProgress(result, i + 1, scenarios.length);
        }
      } catch (err: any) {
        const latencyMs = Date.now() - scenarioStartTime;
        const result: ScenarioResult = {
          id: scenario.id,
          ground_truth: scenario.ground_truth.verdict,
          ground_truth_category: scenario.ground_truth.category,
          predicted_verdict: 'allow',
          matched: false,
          category_matched: false,
          latency_ms: latencyMs,
          input_payload: { error: err.message },
          input_chars: 0,
          error: err.message
        };

        results.push(result);
        if (onProgress) {
          onProgress(result, i + 1, scenarios.length);
        }
      }
    }

    const durationMs = Date.now() - startTime;
    const matrix: ConfusionMatrix = computeConfusionMatrix(results);
    const metrics: BenchmarkMetrics = computeMetrics(results, matrix);

    const artifact: RunArtifact = {
      timestamp: new Date().toISOString(),
      duration_ms: durationMs,
      provider: provider.name,
      model: tier2Config.model,
      scenarios_path: scenariosPath,
      total_scenarios: scenarios.length,
      confusion_matrix: matrix,
      metrics,
      results
    };

    let artifactPaths: ArtifactWriteResult | undefined;
    if (options?.saveArtifact !== false) {
      artifactPaths = writeRunArtifact(artifact, options?.artifactDir);
    }

    return { artifact, artifactPaths };
  }
}
