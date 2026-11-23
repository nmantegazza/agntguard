#!/usr/bin/env node
import { BenchmarkRunner } from './runner.js';
import { formatProgressLine, formatTerminalReport } from './reporter.js';
import type { BenchmarkOptions } from '../types/metrics.js';

function parseCliArgs(args: string[]): { options: BenchmarkOptions; showHelp: boolean } {
  const options: BenchmarkOptions = {};
  let showHelp = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--help' || arg === '-h') {
      showHelp = true;
    } else if (arg === '--scenarios' && i + 1 < args.length) {
      options.scenariosPath = args[++i];
    } else if (arg === '--provider' && i + 1 < args.length) {
      const p = args[++i].toLowerCase();
      if (p === 'mock' || p === 'typesafe') {
        options.provider = p;
      }
    } else if (arg === '--model' && i + 1 < args.length) {
      options.model = args[++i];
    } else if (arg === '--artifact-dir' && i + 1 < args.length) {
      options.artifactDir = args[++i];
    } else if (arg === '--no-artifact') {
      options.saveArtifact = false;
    } else if (arg === '--save-artifact') {
      options.saveArtifact = true;
    }
  }

  return { options, showHelp };
}

function printHelp(): void {
  console.log(`
AgntGuard Benchmark Harness - Tier 2 Isolated Evaluation

Usage:
  npm run benchmark -- [options]
  node --experimental-strip-types src/benchmark/runner/cli.ts [options]

Options:
  --scenarios <path>      Path to scenario file or directory (default: benchmarks/scenarios)
  --provider <name>       Decision provider: 'typesafe' or 'mock' (default: auto-detected)
  --model <model>         Model name override (e.g. jev-latest)
  --artifact-dir <path>   Directory to store timestamped run artifacts (default: benchmarks/runs)
  --no-artifact           Disable persisting run artifacts to disk
  --help, -h              Display this help message
`);
}

async function main(): Promise<void> {
  const rawArgs = process.argv.slice(2);
  const { options, showHelp } = parseCliArgs(rawArgs);

  if (showHelp) {
    printHelp();
    process.exit(0);
  }

  console.log('Starting AgntGuard Tier 2 Benchmark Suite...');
  const runner = new BenchmarkRunner();

  try {
    const { artifact, artifactPaths } = await runner.run(
      options,
      (result, index, total) => {
        console.log(formatProgressLine(result, index, total));
      }
    );

    const report = formatTerminalReport(artifact, artifactPaths);
    console.log(report);

    if (artifact.metrics.failed > 0) {
      console.error(`Benchmark completed with ${artifact.metrics.failed} failure(s).`);
      process.exit(1);
    }

    console.log('All benchmark scenarios passed successfully.');
    process.exit(0);
  } catch (err: any) {
    console.error(`\nBenchmark execution failed: ${err.message}\n`);
    process.exit(1);
  }
}

main();
