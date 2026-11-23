import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { executeInitFlow } from '../dist/cli/commands/init.js';
import { loadConfig, saveConfig } from '../dist/config.js';
import { loadApiKey } from '../dist/credentials.js';
import { inspectHealth } from '../dist/cli/agents/registry.js';
import { DEFAULT_SEED_USER_CONFIG } from '../dist/core/defaults/system-rules.js';

const execFileAsync = promisify(execFile);

describe('agntguard init command & onboarding flow', () => {
  let tmpBase: string;
  let testConfigPath: string;
  let testCredentialsPath: string;
  let geminiConfigDir: string;
  let opencodeConfigDir: string;
  let piDir: string;
  let runtimeDistDir: string;
  const cliScript = path.resolve('dist/cli.js');

  beforeEach(() => {
    tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'agntguard-init-test-'));
    testConfigPath = path.join(tmpBase, 'config.json');
    testCredentialsPath = path.join(tmpBase, 'credentials.json');
    geminiConfigDir = path.join(tmpBase, 'gemini', 'config');
    opencodeConfigDir = path.join(tmpBase, 'opencode');
    piDir = path.join(tmpBase, 'pi');
    runtimeDistDir = path.join(tmpBase, 'runtime_dist');

    // Create directories
    fs.mkdirSync(geminiConfigDir, { recursive: true });
    fs.mkdirSync(opencodeConfigDir, { recursive: true });
    fs.mkdirSync(piDir, { recursive: true });
    fs.mkdirSync(path.join(runtimeDistDir, 'agents'), { recursive: true });

    // Seed dummy adapters
    fs.writeFileSync(path.join(runtimeDistDir, 'agents', 'antigravity-adapter.js'), '// antigravity\n');
    fs.writeFileSync(path.join(runtimeDistDir, 'agents', 'opencode-adapter.js'), '// opencode\n');
    fs.writeFileSync(path.join(runtimeDistDir, 'agents', 'pi-adapter.js'), '// pi\n');

    // Seed initial config
    saveConfig(structuredClone(DEFAULT_SEED_USER_CONFIG), testConfigPath);

    // Environment overrides
    process.env.AGNTGUARD_CONFIG = testConfigPath;
    process.env.AGNTGUARD_CREDENTIALS = testCredentialsPath;
    process.env.AGNTGUARD_DIR = tmpBase;
    process.env.ANTIGRAVITY_CONFIG_DIR = geminiConfigDir;
    process.env.OPENCODE_CONFIG_DIR = opencodeConfigDir;
    delete process.env.OPENCODE_CONFIG_FILE;
    process.env.PI_DIR = piDir;
    delete process.env.PI_EXTENSION_DIR;
    process.env.AGNTGUARD_RUNTIME_DIST = runtimeDistDir;
  });

  afterEach(() => {
    delete process.env.AGNTGUARD_CONFIG;
    delete process.env.AGNTGUARD_CREDENTIALS;
    delete process.env.AGNTGUARD_DIR;
    delete process.env.ANTIGRAVITY_CONFIG_DIR;
    delete process.env.OPENCODE_CONFIG_DIR;
    delete process.env.OPENCODE_CONFIG_FILE;
    delete process.env.PI_DIR;
    delete process.env.PI_EXTENSION_DIR;
    delete process.env.AGNTGUARD_RUNTIME_DIST;
    fs.rmSync(tmpBase, { recursive: true, force: true });
  });

  test('init command exits with code 1 in non-interactive environment (non-TTY)', async () => {
    const env = {
      ...process.env,
      AGNTGUARD_CONFIG: testConfigPath,
      AGNTGUARD_CREDENTIALS: testCredentialsPath,
      AGNTGUARD_DIR: tmpBase
    };

    await assert.rejects(
      execFileAsync('node', [cliScript, 'init'], { env }),
      (err: any) => {
        assert.equal(err.code, 1);
        assert.match(
          err.stderr,
          /agntguard init requires an interactive terminal\. Use agntguard enable <agent> to configure non-interactively\./
        );
        return true;
      }
    );
  });

  test('executeInitFlow configures policy mode, Tier 2 API key, and agent hooks', () => {
    // Execute onboarding flow
    executeInitFlow({
      agents: ['antigravity', 'pi'],
      mode: 'ask',
      apiKey: 'ts_test_key_live'
    });

    // Verify config
    const config = loadConfig(testConfigPath);
    assert.equal(config.mode, 'ask');
    assert.equal(config.tier2.enabled, true);

    // Verify credentials
    const apiKey = loadApiKey(testCredentialsPath);
    assert.equal(apiKey, 'ts_test_key_live');

    // Verify agent hooks status
    const health = inspectHealth();
    assert.equal(health.antigravity.status, 'enabled');
    assert.equal(health.pi.status, 'enabled');
    assert.equal(health.opencode.status, 'disabled');

    // Now re-run onboarding flow with different agents and omitting API key (keeps existing)
    executeInitFlow({
      agents: ['antigravity', 'opencode'],
      mode: 'auto'
    });

    const configAfter = loadConfig(testConfigPath);
    assert.equal(configAfter.mode, 'auto');
    assert.equal(configAfter.tier2.enabled, true); // Stays true because existing key is preserved

    const healthAfter = inspectHealth();
    assert.equal(healthAfter.antigravity.status, 'enabled');
    assert.equal(healthAfter.opencode.status, 'enabled');
    assert.equal(healthAfter.pi.status, 'disabled'); // pi was unselected and disabled
  });
});
