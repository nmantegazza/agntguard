import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  isAntigravityDetected,
  inspectAntigravityHealth,
  enableAntigravity,
  disableAntigravity,
  getAntigravityPluginDir
} from './antigravity-link.js';
import {
  isOpenCodeDetected,
  inspectOpenCodeHealth,
  enableOpenCode,
  disableOpenCode,
  getOpenCodeConfigPath
} from './opencode-link.js';
import {
  isPiDetected,
  inspectPiHealth,
  enablePi,
  disablePi,
  getPiExtensionDir
} from './pi-link.js';

export const SUPPORTED_AGENTS = ['antigravity', 'opencode', 'pi'] as const;
export type AgentName = (typeof SUPPORTED_AGENTS)[number];

export interface AgentHealthInfo {
  name: AgentName;
  detected: boolean;
  status: 'enabled' | 'disabled' | 'broken';
  hookPath: string;
}

export function getRuntimeDistPath(): string {
  if (process.env.AGNTGUARD_RUNTIME_DIST) {
    return path.resolve(process.env.AGNTGUARD_RUNTIME_DIST);
  }

  const customAgntGuardDir = process.env.AGNTGUARD_DIR || process.env.AGNTGUARD_HOME;
  if (customAgntGuardDir) {
    const candidate = path.join(path.resolve(customAgntGuardDir), 'runtime', 'dist');
    if (fs.existsSync(candidate)) return candidate;
  }

  const globalDir = path.join(os.homedir(), '.agntguard', 'runtime', 'dist');
  if (fs.existsSync(globalDir)) return globalDir;

  const currentFilePath = fileURLToPath(import.meta.url);
  const packageRoot = path.resolve(path.dirname(currentFilePath), '../../..');
  return path.join(packageRoot, 'dist');
}

export function detectAgents(): AgentName[] {
  const detected: AgentName[] = [];
  if (isAntigravityDetected()) detected.push('antigravity');
  if (isOpenCodeDetected()) detected.push('opencode');
  if (isPiDetected()) detected.push('pi');
  return detected;
}

export function inspectHealth(): Record<AgentName, AgentHealthInfo> {
  const runtimeDist = getRuntimeDistPath();

  return {
    antigravity: {
      name: 'antigravity',
      detected: isAntigravityDetected(),
      status: inspectAntigravityHealth(runtimeDist),
      hookPath: getAntigravityPluginDir()
    },
    opencode: {
      name: 'opencode',
      detected: isOpenCodeDetected(),
      status: inspectOpenCodeHealth(runtimeDist),
      hookPath: getOpenCodeConfigPath()
    },
    pi: {
      name: 'pi',
      detected: isPiDetected(),
      status: inspectPiHealth(runtimeDist),
      hookPath: getPiExtensionDir()
    }
  };
}

export function enableAgent(name: AgentName): void {
  const runtimeDist = getRuntimeDistPath();
  switch (name) {
    case 'antigravity':
      enableAntigravity(runtimeDist);
      break;
    case 'opencode':
      enableOpenCode(runtimeDist);
      break;
    case 'pi':
      enablePi(runtimeDist);
      break;
    default:
      throw new Error(`Unsupported agent: "${name}"`);
  }
}

export function disableAgent(name: AgentName): void {
  switch (name) {
    case 'antigravity':
      disableAntigravity();
      break;
    case 'opencode':
      disableOpenCode();
      break;
    case 'pi':
      disablePi();
      break;
    default:
      throw new Error(`Unsupported agent: "${name}"`);
  }
}
