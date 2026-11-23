import type { Tier2Category } from '../../types.js';

export type CategoryConfusionMatrix = Record<Tier2Category, Record<Tier2Category, number>>;

/**
 * Fourfold categorization of benchmark outcomes.
 * Positive = 'restrict' (threat condition detected)
 * Negative = 'allow' (safe workflow condition)
 */
export interface ConfusionMatrix {
  tp: number; // Threat restricted (Ground truth: restrict, Predicted: restrict)
  fp: number; // Safe action restricted / Friction (Ground truth: allow, Predicted: restrict)
  tn: number; // Safe action allowed / Workflow (Ground truth: allow, Predicted: allow)
  fn: number; // Threat allowed / Security breach (Ground truth: restrict, Predicted: allow)
}

export interface LatencyMetrics {
  mean_ms: number;
  p50_ms: number;
  p90_ms: number;
  min_ms: number;
  max_ms: number;
}

export interface ContextMetrics {
  mean_input_chars: number;
  min_input_chars: number;
  max_input_chars: number;
}

export interface BenchmarkMetrics {
  total: number;
  passed: number;
  failed: number;
  accuracy: number;
  category_accuracy: number;
  fpr: number; // False Positive Rate: FP / (FP + TN)
  fnr: number; // False Negative Rate: FN / (FN + TP)
  precision: number; // TP / (TP + FP)
  recall: number; // TP / (TP + FN)
  latency: LatencyMetrics;
  context: ContextMetrics;
  category_matrix: CategoryConfusionMatrix;
}

export interface ScenarioResult {
  id: string;
  ground_truth: 'allow' | 'restrict';
  ground_truth_category: Tier2Category;
  predicted_verdict: 'allow' | 'restrict';
  predicted_category?: Tier2Category;
  matched: boolean;
  category_matched: boolean;
  latency_ms: number;
  category?: Tier2Category;
  breached_dimension?: string;
  input_payload: unknown;
  input_chars: number;
  error?: string;
}

export interface RunArtifact {
  timestamp: string;
  duration_ms: number;
  provider: string;
  model?: string;
  scenarios_path: string;
  total_scenarios: number;
  confusion_matrix: ConfusionMatrix;
  metrics: BenchmarkMetrics;
  results: ScenarioResult[];
}

export interface BenchmarkOptions {
  scenariosPath?: string;
  provider?: 'mock' | 'typesafe';
  model?: string;
  saveArtifact?: boolean;
  artifactDir?: string;
}
