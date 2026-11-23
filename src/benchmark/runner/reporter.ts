import type { RunArtifact, ScenarioResult } from '../types/metrics.js';
import type { Tier2Category } from '../../types.js';
import type { ArtifactWriteResult } from './artifact-writer.js';

function formatPercent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function padRight(str: string, length: number): string {
  return str.length >= length ? str : str + ' '.repeat(length - str.length);
}

/**
 * Format benchmark run results for clean CLI terminal output.
 */
export function formatTerminalReport(
  artifact: RunArtifact,
  artifactPaths?: ArtifactWriteResult
): string {
  const lines: string[] = [];

  lines.push('');
  lines.push('====================================================');
  lines.push('       AgntGuard Tier 2 Benchmark Summary          ');
  lines.push('====================================================');
  lines.push('');

  // Run Metadata
  lines.push('Configuration:');
  lines.push(`- Timestamp:    ${artifact.timestamp}`);
  lines.push(`- Provider:     ${artifact.provider}`);
  if (artifact.model) {
    lines.push(`- Model:        ${artifact.model}`);
  }
  lines.push(`- Scenarios:    ${artifact.total_scenarios}`);
  lines.push(`- Duration:     ${artifact.duration_ms}ms`);
  lines.push('');

  // Binary Confusion Matrix Block (Space-aligned)
  const m = artifact.confusion_matrix;
  lines.push('Confusion Matrix:');
  lines.push(
    `  TP: ${padRight(String(m.tp), 5)} (Threat Blocked)       FP: ${padRight(String(m.fp), 5)} (Friction / False Alarm)`
  );
  lines.push(
    `  FN: ${padRight(String(m.fn), 5)} (Safety Breach)        TN: ${padRight(String(m.tn), 5)} (Allowed Workflow)`
  );
  lines.push('');

  // Diagnostic 5x5 Category Confusion Matrix
  const cm = artifact.metrics.category_matrix;
  if (cm) {
    lines.push('Category Confusion Matrix (Diagnostic):');
    lines.push('  Actual \\ Pred      safe      harmful   sensitive opaque    external');
    const categories: Tier2Category[] = ['safe', 'harmful', 'sensitive', 'opaque', 'external'];
    for (const actual of categories) {
      const row = cm[actual] || { safe: 0, harmful: 0, sensitive: 0, opaque: 0, external: 0 };
      const s = padRight(String(row.safe ?? 0), 10);
      const h = padRight(String(row.harmful ?? 0), 10);
      const se = padRight(String(row.sensitive ?? 0), 10);
      const o = padRight(String(row.opaque ?? 0), 10);
      const e = padRight(String(row.external ?? 0), 10);
      lines.push(`  ${padRight(actual, 19)}${s}${h}${se}${o}${e}`);
    }
    lines.push('');
  }

  // Performance Metrics
  const met = artifact.metrics;
  lines.push('Performance & Safety Metrics:');
  lines.push(`- Accuracy:                  ${formatPercent(met.accuracy)} (${met.passed}/${met.total} passed)`);
  lines.push(`- Category Alignment Rate:   ${formatPercent(met.category_accuracy)} (diagnostic)`);
  lines.push(`- False Positive Rate (FPR): ${formatPercent(met.fpr)} (Developer friction)`);
  lines.push(`- False Negative Rate (FNR): ${formatPercent(met.fnr)} (Security leakage)`);
  lines.push(`- Precision:                 ${formatPercent(met.precision)}`);
  lines.push(`- Recall:                    ${formatPercent(met.recall)}`);
  lines.push('');

  // Context & Latency
  lines.push('Context & Latency:');
  lines.push(
    `- Input Payload Size:        mean ${met.context.mean_input_chars} chars (min: ${met.context.min_input_chars}, max: ${met.context.max_input_chars})`
  );
  lines.push(
    `- Evaluation Latency:        mean ${met.latency.mean_ms}ms (p50: ${met.latency.p50_ms}ms, p90: ${met.latency.p90_ms}ms)`
  );
  lines.push('');

  // Failure / Discrepancy Breakdown
  const discrepancies = artifact.results.filter((r) => !r.matched || !r.category_matched);
  if (discrepancies.length > 0) {
    lines.push('Discrepancies & Failures:');
    for (const f of discrepancies) {
      const verdictStatus = f.matched ? 'MATCH' : 'MISMATCH';
      const catStatus = f.category_matched ? 'MATCH' : 'MISMATCH';
      lines.push(`- [${f.id}] (Verdict: ${verdictStatus}, Category: ${catStatus})`);
      lines.push(`  Expected:  ${f.ground_truth}${f.ground_truth_category ? ` (${f.ground_truth_category})` : ''}`);
      lines.push(`  Predicted: ${f.predicted_verdict}${f.predicted_category || f.category ? ` (${f.predicted_category ?? f.category})` : ''}`);
      if (f.breached_dimension) {
        lines.push(`  Breached Dimension: ${f.breached_dimension}`);
      }
      if (f.error) {
        lines.push(`  Error:     ${f.error}`);
      }
    }
    lines.push('');
  }

  // Artifact Output Location
  if (artifactPaths) {
    lines.push('Artifacts:');
    lines.push(`- Run Artifact: ${artifactPaths.artifactPath}`);
    lines.push(`- Latest Run:   ${artifactPaths.latestPath}`);
    lines.push('');
  }

  lines.push('====================================================');
  return lines.join('\n');
}

/**
 * Format a single progress line for live CLI updates.
 */
export function formatProgressLine(
  result: ScenarioResult,
  index: number,
  total: number
): string {
  const status = result.matched ? 'PASS' : 'FAIL';
  const detail = result.matched
    ? `(${result.predicted_verdict})`
    : `(expected ${result.ground_truth}, got ${result.predicted_verdict})`;
  const latency = `${result.latency_ms}ms`;
  return `[${index}/${total}] ${padRight(result.id, 35)} ${status} ${detail} [${latency}]`;
}
