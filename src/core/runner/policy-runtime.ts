import fs from 'node:fs';
import { loadConfig, getDefaultConfigPath } from '../../config.js';
import { getDefaultCredentialsPath } from '../../credentials.js';
import { createProvider } from '../../providers/factory.js';
import { PermissionEngine } from '../engine/permission-engine.js';
import { TelemetryLogger } from '../telemetry/logger.js';
import { PolicyRunner } from './policy-runner.js';
import type { PolicyConfig } from '../../types.js';

export class PolicyRuntime {
  private configPath: string;
  private credentialsPath: string;
  private cachedConfig?: PolicyConfig;
  private cachedEngine?: PermissionEngine;
  private cachedTelemetry?: TelemetryLogger;
  private cachedConfigMtimeMs = 0;
  private cachedCredentialsMtimeMs = 0;

  constructor(configPath?: string, credentialsPath?: string) {
    this.configPath = configPath ?? getDefaultConfigPath();
    this.credentialsPath = credentialsPath ?? getDefaultCredentialsPath();
  }

  public getConfig(): PolicyConfig {
    this.refreshIfModified();
    return this.cachedConfig!;
  }

  public getRunner(signal?: AbortSignal): PolicyRunner {
    this.refreshIfModified();
    return new PolicyRunner({
      config: this.cachedConfig!,
      engine: this.cachedEngine!,
      telemetry: this.cachedTelemetry!,
      signal
    });
  }

  private statMtimeMs(path: string): number {
    try {
      return fs.statSync(path).mtimeMs;
    } catch {
      return 0;
    }
  }

  private refreshIfModified(): void {
    const configMtime = this.statMtimeMs(this.configPath);
    const credsMtime = this.statMtimeMs(this.credentialsPath);
    const stale =
      !this.cachedConfig ||
      !this.cachedEngine ||
      !this.cachedTelemetry ||
      configMtime !== this.cachedConfigMtimeMs ||
      credsMtime !== this.cachedCredentialsMtimeMs;
    if (!stale) return;
    try {
      const config = loadConfig(this.configPath);
      this.cachedConfig = config;
      const provider = createProvider(config.tier2);
      this.cachedEngine = new PermissionEngine(config, provider);
      this.cachedTelemetry = new TelemetryLogger(config);
      this.cachedConfigMtimeMs = configMtime;
      this.cachedCredentialsMtimeMs = credsMtime;
    } catch {

      if (!this.cachedConfig || !this.cachedEngine || !this.cachedTelemetry) {
        throw new Error(`Unable to load policy configuration at ${this.configPath}`);
      }
      // Keep existing cache during atomic writes that fail mid-read.
    }
  }
}
