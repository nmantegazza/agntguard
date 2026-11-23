import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  getGlobalConfigDir,
  getGlobalLogDir,
  getDefaultConfigPath,
  saveConfig,
  loadConfig
} from '../dist/config.js';
import {
  getDefaultCredentialsPath,
  saveApiKey,
  loadApiKey,
  getHookRoot
} from '../dist/credentials.js';
import { AntigravityAgent } from '../dist/agents/antigravity-adapter.js';
import { OpencodeAgent } from '../dist/agents/opencode-adapter.js';
import { PolicyRunner } from '../dist/core/runner/policy-runner.js';
import { TelemetryLogger } from '../dist/core/telemetry/logger.js';
import type { PolicyConfig, CanonicalContext, PolicyDecision } from '../src/types.js';

describe('Unified Multi-Agent Policy Engine Configuration', () => {
  let tmpDir: string;
  let fakeXdgHome: string;
  const originalEnv = { ...process.env };

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'unified-config-test-'));
    fakeXdgHome = path.join(tmpDir, 'fake-xdg');
    fs.mkdirSync(fakeXdgHome, { recursive: true });

    delete process.env.AGNTGUARD_CONFIG;
    delete process.env.AGNTGUARD_CREDENTIALS;
    process.env.XDG_CONFIG_HOME = fakeXdgHome;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('getGlobalConfigDir respects AGNTGUARD_DIR, XDG_CONFIG_HOME and falls back to ~/.agntguard', () => {
    assert.equal(getGlobalConfigDir(), path.join(fakeXdgHome, 'agntguard'));
    assert.equal(getGlobalLogDir(), path.join(fakeXdgHome, 'agntguard', 'logs'));

    process.env.AGNTGUARD_DIR = path.join(tmpDir, 'custom-ag-dir');
    assert.equal(getGlobalConfigDir(), path.join(tmpDir, 'custom-ag-dir'));
    assert.equal(getGlobalLogDir(), path.join(tmpDir, 'custom-ag-dir', 'logs'));
    delete process.env.AGNTGUARD_DIR;

    delete process.env.XDG_CONFIG_HOME;
    assert.equal(getGlobalConfigDir(), path.join(os.homedir(), '.agntguard'));
    assert.equal(getGlobalLogDir(), path.join(os.homedir(), '.agntguard', 'logs'));
  });

  test('getDefaultConfigPath follows priority: AGNTGUARD_CONFIG > global file > package-local', () => {
    const localFallback = path.join(getHookRoot(), 'config.json');
    const globalConfigPath = path.join(fakeXdgHome, 'agntguard', 'config.json');
    const customAgntGuardPath = path.join(tmpDir, 'custom-ag.json');

    // 3rd priority: When env vars are unset and global file does NOT exist -> local fallback
    assert.equal(getDefaultConfigPath(), localFallback);

    // 2nd priority: When global file exists and env vars unset -> global config
    fs.mkdirSync(path.dirname(globalConfigPath), { recursive: true });
    fs.writeFileSync(globalConfigPath, '{}', 'utf8');
    assert.equal(getDefaultConfigPath(), globalConfigPath);

    // 1st priority: AGNTGUARD_CONFIG overrides global file
    process.env.AGNTGUARD_CONFIG = customAgntGuardPath;
    assert.equal(getDefaultConfigPath(), path.resolve(customAgntGuardPath));
  });

  test('getDefaultCredentialsPath follows priority: AGNTGUARD_CREDENTIALS > global file > package-local', () => {
    const localFallback = path.join(getHookRoot(), 'credentials.json');
    const globalCredsPath = path.join(fakeXdgHome, 'agntguard', 'credentials.json');
    const customAgCreds = path.join(tmpDir, 'creds-ag.json');

    // 3rd priority: Unset env and missing global file -> local fallback
    assert.equal(getDefaultCredentialsPath(), localFallback);

    // 2nd priority: Global file exists
    fs.mkdirSync(path.dirname(globalCredsPath), { recursive: true });
    fs.writeFileSync(globalCredsPath, '{}', 'utf8');
    assert.equal(getDefaultCredentialsPath(), globalCredsPath);

    // 1st priority: AGNTGUARD_CREDENTIALS overrides global file
    process.env.AGNTGUARD_CREDENTIALS = customAgCreds;
    assert.equal(getDefaultCredentialsPath(), path.resolve(customAgCreds));
  });

  test('saveConfig writes to global config directory by default', () => {
    const globalConfigFile = path.join(fakeXdgHome, 'agntguard', 'config.json');
    assert.equal(fs.existsSync(globalConfigFile), false);

    const testConfig: PolicyConfig = {
      mode: 'auto',
      rules: {
        restrict: [{ tool: 'execute_command', pattern: '^dangerous-cmd$', dimension: 'harmful' }],
        allow: [{ tool: 'execute_command', pattern: '^safe-cmd$' }]
      },
      tier2: {
        enabled: false,
        provider: 'typesafe',
        timeout_ms: 500
      },
      telemetry: {
        enabled: true,
        log_dir: 'logs'
      }
    };

    saveConfig(testConfig);
    assert.equal(fs.existsSync(globalConfigFile), true);

    const loaded = loadConfig(globalConfigFile);
    assert.equal(loaded.mode, 'auto');
    assert.ok(loaded.rules.restrict.some((r: any) => r.tool === 'execute_command' && r.pattern === '^dangerous-cmd$'));
  });

  test('saveApiKey writes to global credentials file with 0600 permissions', () => {
    const globalCredsFile = path.join(fakeXdgHome, 'agntguard', 'credentials.json');
    assert.equal(fs.existsSync(globalCredsFile), false);

    const saved = saveApiKey('unified_test_api_key_789');
    assert.equal(saved, globalCredsFile);
    assert.equal(fs.existsSync(globalCredsFile), true);

    const loadedKey = loadApiKey(globalCredsFile);
    assert.equal(loadedKey, 'unified_test_api_key_789');

    if (process.platform !== 'win32') {
      const mode = fs.statSync(globalCredsFile).mode & 0o777;
      assert.equal(mode, 0o600);
    }
  });

  test('normalizers tag agent correctly and TelemetryLogger attributes both agents', () => {
    const loggerDir = path.join(tmpDir, 'telemetry-test');
    const config: PolicyConfig = {
      rules: { restrict: [], allow: [] },
      tier2: {
        enabled: false,
        provider: 'mock',
        timeout_ms: 500
      },
      telemetry: {
        enabled: true,
        log_dir: loggerDir
      }
    };

    const logger = new TelemetryLogger(config, loggerDir);

    // 1. Antigravity context normalization & logging
    const agContext: CanonicalContext = {
      agent: 'antigravity',
      toolName: 'execute_command',
      payload: 'echo antigravity'
    };
    const agResult: PolicyDecision = {
      decision: 'allow',
      reason: 'Allowed',
      tierMatched: 'tier1',
      evidence: {}
    };
    logger.log(agContext, agResult);

    // 2. OpenCode context normalization & logging
    const ocContext: CanonicalContext = {
      agent: 'opencode',
      toolName: 'execute_command',
      payload: 'echo opencode'
    };
    const ocResult: PolicyDecision = {
      decision: 'restrict',
      reason: 'Denied',
      tierMatched: 'tier1',
      evidence: {}
    };
    logger.log(ocContext, ocResult);

    const decisionsFile = logger.getDecisionsLogFilePath();
    assert.equal(fs.existsSync(decisionsFile), true);

    const lines = fs.readFileSync(decisionsFile, 'utf8').trim().split('\n');
    assert.equal(lines.length, 2);

    const agRecord = JSON.parse(lines[0]);
    assert.equal(agRecord.agent, 'antigravity');
    assert.equal(agRecord.action.payload, 'echo antigravity');
    assert.equal(agRecord.outcome.verdict, 'allow');

    const ocRecord = JSON.parse(lines[1]);
    assert.equal(ocRecord.agent, 'opencode');
    assert.equal(ocRecord.action.payload, 'echo opencode');
    assert.equal(ocRecord.outcome.verdict, 'restrict');
  });

  test('Antigravity and OpenCode evaluate against the unified policy engine identically', async () => {
    const unifiedPolicy: PolicyConfig = {
      mode: 'auto',
      rules: {
        restrict: [
          { tool: 'execute_command', pattern: '^rm\\s+-rf\\s+.*', dimension: 'harmful' },
          { tool: 'execute_command', pattern: 'git\\s+push\\s+--force', dimension: 'harmful' }
        ],
        allow: [{ tool: 'execute_command', pattern: '^git\\s+status$' }]
      },
      tier2: {
        enabled: false,
        provider: 'mock',
        timeout_ms: 500
      },
      telemetry: { enabled: false, log_dir: 'logs' }
    };

    const runner = new PolicyRunner({ config: unifiedPolicy });

    // 1. Antigravity format input for safe command
    const agRawSafe = JSON.stringify({
      toolCall: { name: 'run_command', args: { CommandLine: 'git status' } }
    });
    const agCtxSafe = (await AntigravityAgent.normalize(agRawSafe)) as CanonicalContext;
    const agOutcomeSafe = await runner.run(agCtxSafe);
    assert.equal(agOutcomeSafe.decision, 'allow');

    // 2. OpenCode format input for the same safe command
    const ocRawSafe = { action: 'shell', resources: ['git status'] };
    const ocCtxSafe = (await OpencodeAgent.normalize(ocRawSafe)) as CanonicalContext;
    const ocOutcomeSafe = await runner.run(ocCtxSafe);
    assert.equal(ocOutcomeSafe.decision, 'allow');

    // 3. Antigravity format input for dangerous command
    const agRawDeny = JSON.stringify({
      toolCall: { name: 'run_command', args: { CommandLine: 'rm -rf /some/dir' } }
    });
    const agCtxDeny = (await AntigravityAgent.normalize(agRawDeny)) as CanonicalContext;
    const agOutcomeDeny = await runner.run(agCtxDeny);
    assert.equal(agOutcomeDeny.decision, 'restrict');

    // 4. OpenCode format input for the same dangerous command
    const ocRawDeny = { action: 'shell', resources: ['rm -rf /some/dir'] };
    const ocCtxDeny = (await OpencodeAgent.normalize(ocRawDeny)) as CanonicalContext;
    const ocOutcomeDeny = await runner.run(ocCtxDeny);
    assert.equal(ocOutcomeDeny.decision, 'restrict');
  });
});
