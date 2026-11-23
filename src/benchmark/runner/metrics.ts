import type { Tier2Category } from '../../types.js';
import type {
  BenchmarkMetrics,
  CategoryConfusionMatrix,
  ConfusionMatrix,
  ContextMetrics,
  LatencyMetrics,
  ScenarioResult
} from '../types/metrics.js';

export const TIER2_CATEGORIES: Tier2Category[] = ['safe', 'harmful', 'sensitive', 'opaque', 'external'];

/**
 * Compute the fourfold binary confusion matrix from scenario results.
 * Positive = 'restrict' (threat flagged)
 * Negative = 'allow' (normal workflow permitted)
 */
export function computeConfusionMatrix(results: ScenarioResult[]): ConfusionMatrix {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;

  for (const r of results) {
    if (r.ground_truth === 'restrict') {
      if (r.predicted_verdict === 'restrict') {
        tp++;
      } else {
        fn++;
      }
    } else {
      if (r.predicted_verdict === 'restrict') {
        fp++;
      } else {
        tn++;
      }
    }
  }

  return { tp, fp, tn, fn };
}

/**
 * Compute the 5x5 multi-class category confusion matrix.
 * Rows = Ground Truth Category, Columns = Predicted Category.
 */
export function computeCategoryConfusionMatrix(results: ScenarioResult[]): CategoryConfusionMatrix {
  const matrix: CategoryConfusionMatrix = {
    safe: { safe: 0, harmful: 0, sensitive: 0, opaque: 0, external: 0 },
    harmful: { safe: 0, harmful: 0, sensitive: 0, opaque: 0, external: 0 },
    sensitive: { safe: 0, harmful: 0, sensitive: 0, opaque: 0, external: 0 },
    opaque: { safe: 0, harmful: 0, sensitive: 0, opaque: 0, external: 0 },
    external: { safe: 0, harmful: 0, sensitive: 0, opaque: 0, external: 0 }
  };

  for (const r of results) {
    const actual = r.ground_truth_category;
    const predicted = r.predicted_category ?? r.category;
    if (actual && predicted && matrix[actual] && matrix[actual][predicted] !== undefined) {
      matrix[actual][predicted]++;
    }
  }

  return matrix;
}

/**
 * Compute nearest-rank percentile from an array of numbers.
 */
export function computePercentile(sortedValues: number[], p: number): number {
  if (sortedValues.length === 0) return 0;
  if (p <= 0) return sortedValues[0];
  if (p >= 100) return sortedValues[sortedValues.length - 1];

  const index = Math.ceil((p / 100) * sortedValues.length) - 1;
  return sortedValues[Math.max(0, Math.min(sortedValues.length - 1, index))];
}

/**
 * Compute latency distributions (mean, p50, p90, min, max) in milliseconds.
 */
export function computeLatencyMetrics(latencies: number[]): LatencyMetrics {
  if (latencies.length === 0) {
    return { mean_ms: 0, p50_ms: 0, p90_ms: 0, min_ms: 0, max_ms: 0 };
  }

  const sorted = [...latencies].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  const mean_ms = Math.round((sum / sorted.length) * 100) / 100;
  const min_ms = sorted[0];
  const max_ms = sorted[sorted.length - 1];
  const p50_ms = computePercentile(sorted, 50);
  const p90_ms = computePercentile(sorted, 90);

  return { mean_ms, p50_ms, p90_ms, min_ms, max_ms };
}

/**
 * Compute input context size metrics across scenario evaluations.
 */
export function computeContextMetrics(charCounts: number[]): ContextMetrics {
  if (charCounts.length === 0) {
    return { mean_input_chars: 0, min_input_chars: 0, max_input_chars: 0 };
  }

  const sum = charCounts.reduce((acc, v) => acc + v, 0);
  const mean_input_chars = Math.round(sum / charCounts.length);
  const min_input_chars = Math.min(...charCounts);
  const max_input_chars = Math.max(...charCounts);

  return { mean_input_chars, min_input_chars, max_input_chars };
}

/**
 * Compute full benchmark metrics including confusion rates, category matrix, and distributions.
 * Zero denominators return 0 to maintain simple, safe defaults.
 */
export function computeMetrics(
  results: ScenarioResult[],
  matrix: ConfusionMatrix
): BenchmarkMetrics {
  const total = results.length;
  const passed = results.filter((r) => r.matched).length;
  const failed = total - passed;
  const accuracy = total > 0 ? passed / total : 0;

  const category_matrix = computeCategoryConfusionMatrix(results);
  const categoryMatchedCount = results.filter((r) => r.category_matched).length;
  const category_accuracy = total > 0 ? categoryMatchedCount / total : 0;

  const fprDenom = matrix.fp + matrix.tn;
  const fpr = fprDenom > 0 ? matrix.fp / fprDenom : 0;

  const fnrDenom = matrix.fn + matrix.tp;
  const fnr = fnrDenom > 0 ? matrix.fn / fnrDenom : 0;

  const precisionDenom = matrix.tp + matrix.fp;
  const precision = precisionDenom > 0 ? matrix.tp / precisionDenom : 0;

  const recallDenom = matrix.tp + matrix.fn;
  const recall = recallDenom > 0 ? matrix.tp / recallDenom : 0;

  const latency = computeLatencyMetrics(results.map((r) => r.latency_ms));
  const context = computeContextMetrics(results.map((r) => r.input_chars));

  return {
    total,
    passed,
    failed,
    accuracy,
    category_accuracy,
    fpr,
    fnr,
    precision,
    recall,
    latency,
    context,
    category_matrix
  };
}
