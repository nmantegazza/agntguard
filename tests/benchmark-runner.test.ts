import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, rmSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import {
  computeConfusionMatrix,
  computeCategoryConfusionMatrix,
  computeMetrics,
  computeLatencyMetrics,
  computeContextMetrics,
  computePercentile,
  tier2StateToCanonicalContext,
  writeRunArtifact,
  formatTerminalReport,
  formatProgressLine,
  BenchmarkRunner,
  type ScenarioResult,
  type ConfusionMatrix,
  type RunArtifact
} from '../dist/benchmark/index.js';
import type { Tier2State } from '../dist/types.js';

describe('Tier 2 Benchmark Runner & Metrics Reporter', () => {
  const testArtifactDir = resolve(process.cwd(), 'tests', 'fixtures', 'test-runs');

  after(() => {
    if (existsSync(testArtifactDir)) {
      rmSync(testArtifactDir, { recursive: true, force: true });
    }
  });

  describe('Confusion Matrix & Metrics Computation', () => {
    test('computes confusion matrix correctly across binary outcomes', () => {
      const sampleResults: ScenarioResult[] = [
        {
          id: 's1',
          ground_truth: 'restrict',
          ground_truth_category: 'harmful',
          predicted_verdict: 'restrict',
          predicted_category: 'harmful',
          matched: true,
          category_matched: true,
          latency_ms: 100,
          input_payload: { tool: 'shell' },
          input_chars: 17
        },
        {
          id: 's2',
          ground_truth: 'allow',
          ground_truth_category: 'safe',
          predicted_verdict: 'restrict',
          predicted_category: 'harmful',
          matched: false, // False Positive / Friction
          category_matched: false,
          latency_ms: 150,
          input_payload: { tool: 'shell' },
          input_chars: 17
        },
        {
          id: 's3',
          ground_truth: 'allow',
          ground_truth_category: 'safe',
          predicted_verdict: 'allow',
          predicted_category: 'safe',
          matched: true, // True Negative
          category_matched: true,
          latency_ms: 80,
          input_payload: { tool: 'shell' },
          input_chars: 17
        },
        {
          id: 's4',
          ground_truth: 'restrict',
          ground_truth_category: 'sensitive',
          predicted_verdict: 'allow',
          predicted_category: 'safe',
          matched: false, // False Negative / Breach
          category_matched: false,
          latency_ms: 90,
          input_payload: { tool: 'shell' },
          input_chars: 17
        }
      ];

      const matrix = computeConfusionMatrix(sampleResults);
      assert.deepEqual(matrix, { tp: 1, fp: 1, tn: 1, fn: 1 });

      const metrics = computeMetrics(sampleResults, matrix);
      assert.equal(metrics.total, 4);
      assert.equal(metrics.passed, 2);
      assert.equal(metrics.failed, 2);
      assert.equal(metrics.accuracy, 0.5);
      assert.equal(metrics.category_accuracy, 0.5);
      assert.equal(metrics.fpr, 0.5); // FP / (FP + TN) = 1 / 2
      assert.equal(metrics.fnr, 0.5); // FN / (FN + TP) = 1 / 2
      assert.equal(metrics.precision, 0.5); // TP / (TP + FP) = 1 / 2
      assert.equal(metrics.recall, 0.5); // TP / (TP + FN) = 1 / 2
    });

    test('computes category confusion matrix and sibling restriction mismatches', () => {
      const sampleResults: ScenarioResult[] = [
        {
          id: 'c1',
          ground_truth: 'allow',
          ground_truth_category: 'safe',
          predicted_verdict: 'allow',
          predicted_category: 'safe',
          matched: true,
          category_matched: true,
          latency_ms: 10,
          input_payload: {},
          input_chars: 10
        },
        {
          id: 'c2',
          ground_truth: 'restrict',
          ground_truth_category: 'harmful',
          predicted_verdict: 'restrict',
          predicted_category: 'harmful',
          matched: true,
          category_matched: true,
          latency_ms: 10,
          input_payload: {},
          input_chars: 10
        },
        {
          id: 'c3',
          ground_truth: 'restrict',
          ground_truth_category: 'sensitive',
          predicted_verdict: 'restrict',
          predicted_category: 'harmful', // Sibling restriction mismatch: both restrict, but category differs
          matched: true,                 // Primary pass per Invariant I4!
          category_matched: false,       // Category mismatch
          latency_ms: 10,
          input_payload: {},
          input_chars: 10
        },
        {
          id: 'c4',
          ground_truth: 'restrict',
          ground_truth_category: 'opaque',
          predicted_verdict: 'restrict',
          predicted_category: 'opaque',
          matched: true,
          category_matched: true,
          latency_ms: 10,
          input_payload: {},
          input_chars: 10
        },
        {
          id: 'c5',
          ground_truth: 'restrict',
          ground_truth_category: 'external',
          predicted_verdict: 'restrict',
          predicted_category: 'external',
          matched: true,
          category_matched: true,
          latency_ms: 10,
          input_payload: {},
          input_chars: 10
        }
      ];

      const catMatrix = computeCategoryConfusionMatrix(sampleResults);
      assert.equal(catMatrix.safe.safe, 1);
      assert.equal(catMatrix.harmful.harmful, 1);
      assert.equal(catMatrix.sensitive.harmful, 1);
      assert.equal(catMatrix.sensitive.sensitive, 0);
      assert.equal(catMatrix.opaque.opaque, 1);
      assert.equal(catMatrix.external.external, 1);
      assert.equal(catMatrix.external.safe, 0);
      assert.equal(catMatrix.safe.external, 0);

      const binaryMatrix = computeConfusionMatrix(sampleResults);
      const metrics = computeMetrics(sampleResults, binaryMatrix);

      // Primary benchmark remains 100% pass (binary verdict matches for all 5)
      assert.equal(metrics.accuracy, 1.0);
      assert.equal(metrics.passed, 5);
      assert.equal(metrics.failed, 0);

      // Category alignment rate is 4/5 = 80%
      assert.equal(metrics.category_accuracy, 0.8);
    });

    test('handles zero denominators without division by zero errors', () => {
      const emptyResults: ScenarioResult[] = [];
      const emptyMatrix: ConfusionMatrix = { tp: 0, fp: 0, tn: 0, fn: 0 };

      const metrics = computeMetrics(emptyResults, emptyMatrix);
      assert.equal(metrics.total, 0);
      assert.equal(metrics.passed, 0);
      assert.equal(metrics.failed, 0);
      assert.equal(metrics.accuracy, 0);
      assert.equal(metrics.category_accuracy, 0);
      assert.equal(metrics.fpr, 0);
      assert.equal(metrics.fnr, 0);
      assert.equal(metrics.precision, 0);
      assert.equal(metrics.recall, 0);
      assert.equal(metrics.latency.mean_ms, 0);
      assert.equal(metrics.context.mean_input_chars, 0);
    });

    test('computes percentile correctly', () => {
      const values = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
      assert.equal(computePercentile(values, 50), 50);
      assert.equal(computePercentile(values, 90), 90);
      assert.equal(computePercentile([], 50), 0);
    });

    test('computes latency and context distributions', () => {
      const latencies = [50, 100, 150, 200];
      const latencyMetrics = computeLatencyMetrics(latencies);
      assert.equal(latencyMetrics.mean_ms, 125);
      assert.equal(latencyMetrics.min_ms, 50);
      assert.equal(latencyMetrics.max_ms, 200);
      assert.equal(latencyMetrics.p50_ms, 100);
      assert.equal(latencyMetrics.p90_ms, 200);

      const charCounts = [100, 200, 300];
      const contextMetrics = computeContextMetrics(charCounts);
      assert.equal(contextMetrics.mean_input_chars, 200);
      assert.equal(contextMetrics.min_input_chars, 100);
      assert.equal(contextMetrics.max_input_chars, 300);
    });
  });

  describe('Context Adapter (tier2StateToCanonicalContext)', () => {
    test('maps Tier2State directly to CanonicalContext structure', () => {
      const state: Tier2State = {
        cwd: '/workspace/app',
        git_state: 'clean',
        policy: {
          outside_read: 'allow',
          outside_write: 'restrict',
          no_access: [],
          read_only: [],
          allowed: []
        },
        latest_user_request: 'Run git status',
        previous_user_requests: ['Check repository status'],
        recent_tool_calls: [{ tool: 'read_file', payload: 'package.json' }],
        pending_action: {
          tool: 'execute_command',
          target: 'git status',
          summary: 'Status check'
        }
      };

      const ctx = tier2StateToCanonicalContext(state);
      assert.equal(ctx.toolName, 'execute_command');
      assert.equal(ctx.payload, 'git status');
      assert.equal(ctx.summary, 'Status check');
      assert.equal(ctx.cwd, '/workspace/app');
      assert.equal(ctx.gitState, 'clean');
      assert.equal(ctx.latestUserRequest, 'Run git status');
      assert.deepEqual(ctx.previousUserRequests, ['Check repository status']);
      assert.deepEqual(ctx.recentToolCalls, [{ tool: 'read_file', payload: 'package.json' }]);
      assert.ok(ctx.policy);
    });
  });

  describe('Disk Persistence (writeRunArtifact)', () => {
    test('persists timestamped JSON artifact and updates latest.json', () => {
      const dummyArtifact: RunArtifact = {
        timestamp: '2026-10-10T15:00:00.000Z',
        duration_ms: 250,
        provider: 'mock',
        scenarios_path: '/benchmarks/scenarios',
        total_scenarios: 1,
        confusion_matrix: { tp: 0, fp: 0, tn: 1, fn: 0 },
        metrics: {
          total: 1,
          passed: 1,
          failed: 0,
          accuracy: 1,
          category_accuracy: 1,
          fpr: 0,
          fnr: 0,
          precision: 0,
          recall: 0,
          latency: { mean_ms: 10, p50_ms: 10, p90_ms: 10, min_ms: 10, max_ms: 10 },
          context: { mean_input_chars: 100, min_input_chars: 100, max_input_chars: 100 },
          category_matrix: {
            safe: { safe: 1, harmful: 0, sensitive: 0, opaque: 0, external: 0 },
            harmful: { safe: 0, harmful: 0, sensitive: 0, opaque: 0, external: 0 },
            sensitive: { safe: 0, harmful: 0, sensitive: 0, opaque: 0, external: 0 },
            opaque: { safe: 0, harmful: 0, sensitive: 0, opaque: 0, external: 0 },
            external: { safe: 0, harmful: 0, sensitive: 0, opaque: 0, external: 0 }
          }
        },
        results: []
      };

      const { artifactPath, latestPath } = writeRunArtifact(dummyArtifact, testArtifactDir);
      assert.ok(existsSync(artifactPath), 'timestamped artifact file should exist');
      assert.ok(existsSync(latestPath), 'latest.json file should exist');

      const parsedLatest = JSON.parse(readFileSync(latestPath, 'utf-8'));
      assert.equal(parsedLatest.provider, 'mock');
      assert.equal(parsedLatest.total_scenarios, 1);
    });
  });

  describe('BenchmarkRunner End-to-End Execution with MockProvider', () => {
    test('loads scenarios and executes evaluation in isolation', async () => {
      const runner = new BenchmarkRunner();
      const scenariosPath = resolve(process.cwd(), 'benchmarks', 'scenarios', 'sample-scenario.json');

      const { artifact, artifactPaths } = await runner.run({
        scenariosPath,
        provider: 'mock',
        artifactDir: testArtifactDir
      });

      assert.equal(artifact.total_scenarios, 1);
      assert.equal(artifact.provider, 'mock');
      assert.ok(artifact.duration_ms >= 0);
      assert.equal(artifact.metrics.passed, 1);

      const firstResult = artifact.results[0];
      assert.ok(firstResult.id.length > 0);
      assert.equal(firstResult.ground_truth, 'allow');
      assert.equal(firstResult.ground_truth_category, 'safe');
      assert.equal(firstResult.predicted_verdict, 'allow');
      assert.equal(firstResult.predicted_category, 'safe');
      assert.equal(firstResult.matched, true);
      assert.equal(firstResult.category_matched, true);
      assert.ok(firstResult.input_chars > 0);
      assert.ok(firstResult.input_payload !== undefined);

      assert.ok(artifactPaths !== undefined);
      assert.ok(existsSync(artifactPaths.artifactPath));
      assert.ok(existsSync(artifactPaths.latestPath));
    });
  });

  describe('Terminal Reporter', () => {
    test('formats summary report cleanly without markdown tables', () => {
      const dummyArtifact: RunArtifact = {
        timestamp: '2026-10-10T15:00:00.000Z',
        duration_ms: 320,
        provider: 'mock',
        model: 'jev-latest',
        scenarios_path: '/benchmarks/scenarios',
        total_scenarios: 2,
        confusion_matrix: { tp: 1, fp: 0, tn: 1, fn: 0 },
        metrics: {
          total: 2,
          passed: 2,
          failed: 0,
          accuracy: 1.0,
          category_accuracy: 1.0,
          fpr: 0,
          fnr: 0,
          precision: 1.0,
          recall: 1.0,
          latency: { mean_ms: 15, p50_ms: 15, p90_ms: 20, min_ms: 10, max_ms: 20 },
          context: { mean_input_chars: 150, min_input_chars: 120, max_input_chars: 180 },
          category_matrix: {
            safe: { safe: 1, harmful: 0, sensitive: 0, opaque: 0 },
            harmful: { safe: 0, harmful: 1, sensitive: 0, opaque: 0 },
            sensitive: { safe: 0, harmful: 0, sensitive: 0, opaque: 0 },
            opaque: { safe: 0, harmful: 0, sensitive: 0, opaque: 0 }
          }
        },
        results: [
          {
            id: 'discrepancy-sample',
            ground_truth: 'restrict',
            ground_truth_category: 'sensitive',
            predicted_verdict: 'restrict',
            predicted_category: 'harmful',
            matched: true,
            category_matched: false,
            latency_ms: 25,
            input_payload: {},
            input_chars: 10
          }
        ]
      };

      const report = formatTerminalReport(dummyArtifact, {
        artifactPath: '/path/to/artifact.json',
        latestPath: '/path/to/latest.json'
      });

      assert.ok(report.includes('AgntGuard Tier 2 Benchmark Summary'));
      assert.ok(report.includes('Confusion Matrix:'));
      assert.ok(report.includes('Category Confusion Matrix (Diagnostic):'));
      assert.ok(report.includes('external'));
      assert.ok(report.includes('Category Alignment Rate:'));
      assert.ok(report.includes('TP: 1'));
      assert.ok(report.includes('Friction'));
      assert.ok(report.includes('Input Payload Size:'));
      assert.ok(report.includes('Discrepancies & Failures:'));
      assert.ok(report.includes('(Verdict: MATCH, Category: MISMATCH)'));
      assert.ok(!report.includes('| --- |'), 'Report should not contain Markdown tables');

      const progressLine = formatProgressLine(
        {
          id: 'test-scenario',
          ground_truth: 'allow',
          ground_truth_category: 'safe',
          predicted_verdict: 'allow',
          predicted_category: 'safe',
          matched: true,
          category_matched: true,
          latency_ms: 45,
          input_payload: {},
          input_chars: 2
        },
        1,
        1
      );
      assert.ok(progressLine.includes('[1/1]'));
      assert.ok(progressLine.includes('PASS'));
      assert.ok(progressLine.includes('45ms'));
    });
  });
});
