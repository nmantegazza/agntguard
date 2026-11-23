import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import type { RunArtifact } from '../types/metrics.js';

export interface ArtifactWriteResult {
  artifactPath: string;
  latestPath: string;
}

/**
 * Persist a RunArtifact to disk as formatted JSON.
 * Writes a unique timestamped file and updates `latest.json`.
 */
export function writeRunArtifact(
  artifact: RunArtifact,
  customDir?: string
): ArtifactWriteResult {
  const targetDir = customDir
    ? resolve(customDir)
    : resolve(process.cwd(), 'benchmarks', 'runs');

  mkdirSync(targetDir, { recursive: true });

  const sanitizedTimestamp = artifact.timestamp.replace(/[:.]/g, '-');
  const filename = `${sanitizedTimestamp}-${artifact.provider}.json`;
  const artifactPath = join(targetDir, filename);
  const latestPath = join(targetDir, 'latest.json');

  const jsonContent = JSON.stringify(artifact, null, 2);

  writeFileSync(artifactPath, jsonContent, 'utf-8');
  writeFileSync(latestPath, jsonContent, 'utf-8');

  return { artifactPath, latestPath };
}
