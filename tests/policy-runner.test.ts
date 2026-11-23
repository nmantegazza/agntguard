import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { PolicyRunner, fallbackDecision } from '../dist/core/runner/policy-runner.js';
import { PolicyRuntime } from '../dist/core/runner/policy-runtime.js';
import { MockProvider } from '../dist/providers/mock-provider.js';
import { PermissionEngine } from '../dist/core/engine/permission-engine.js';
import { TelemetryLogger } from '../dist/core/telemetry/logger.js';
import type { PolicyConfig, CanonicalContext } from '../src/types.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

function makeConfig(overrides: Partial<PolicyConfig> = {}): PolicyConfig {
  return {
    mode: 'auto',
    agent: 'antigravity',
    unmapped_tool_verdict: 'allow',
    rules: {
      restrict: [{ tool: 'execute_command', pattern: '^rm -rf /', dimension: 'harmful' }],
      allow: [
        { tool: 'execute_command', pattern: '^ls' },
        { tool: 'read_file', pattern: '.*' }
      ]
    },
    tier2: {
      enabled: false,
      provider: 'mock',
      timeout_ms: 500
    },
    telemetry: { enabled: false, log_dir: 'logs' },
    ...overrides
  };
}

describe('fallbackDecision (pure)', () => {
  test('with allow verdict', () => {
    const out = fallbackDecision('allow', 'boom', 'auto');
    assert.equal(out.decision, 'allow');
    assert.equal(out.tierMatched, 'fallback');
    assert.deepEqual(out.evidence, { mode: 'auto', fallbackVerdict: 'allow' });
    assert.match(out.reason, /permitted by fallback policy/);
  });

  test('with restrict verdict, one mode-directed reason', () => {
    const auto = fallbackDecision('restrict', 'boom', 'auto');
    assert.equal(auto.decision, 'restrict');
    assert.equal(auto.tierMatched, 'fallback');
    assert.match(auto.reason, /restricted by fallback policy/);

    const ask = fallbackDecision('restrict', 'boom', 'ask');
    assert.match(ask.reason, /requires user approval/);
  });
});

describe('PolicyRunner', () => {
  test('evaluates deterministic Tier 1 allow', async () => {
    const config = makeConfig();
    const runner = new PolicyRunner({ config, engine: new PermissionEngine(config) });
    const out = await runner.run({ toolName: 'execute_command', payload: 'ls -la', cwd: process.cwd() });
    assert.equal(out.decision, 'allow');
    assert.equal(out.tierMatched, 'tier1');
  });

  test('tolerates git inspection failure', async () => {
    const config = makeConfig();
    const runner = new PolicyRunner({
      config,
      engine: new PermissionEngine(config),
      inspectGit: async () => {
        throw new Error('git down');
      }
    });
    const out = await runner.run({ toolName: 'execute_command', payload: 'ls', cwd: process.cwd() });
    assert.equal(out.decision, 'allow');
  });

  test('wraps engine throw into default allow fallback', async () => {
    const config = makeConfig();
    const broken = {
      evaluate: async () => {
        throw new Error('engine exploded');
      }
    } as unknown as PermissionEngine;
    const runner = new PolicyRunner({ config, engine: broken });
    const out = await runner.run({ toolName: 'execute_command', payload: 'ls' });
    assert.equal(out.decision, 'allow');
    assert.equal(out.tierMatched, 'fallback');
    assert.match(out.reason, /engine exploded/);
  });

  test('setting fallback_verdict: restrict preserves fail-closed behavior on throw', async () => {
    const config = makeConfig({ fallback_verdict: 'restrict' });
    const broken = {
      evaluate: async () => {
        throw new Error('engine exploded');
      }
    } as unknown as PermissionEngine;
    const runner = new PolicyRunner({ config, engine: broken });
    const out = await runner.run({ toolName: 'execute_command', payload: 'ls' });
    assert.equal(out.decision, 'restrict');
    assert.equal(out.tierMatched, 'fallback');
    assert.match(out.reason, /engine exploded/);
  });

  test('forwards AbortSignal to Tier 2 (aborted signal falls back to configured fallback_verdict)', async () => {
    const config = makeConfig({
      fallback_verdict: 'allow',
      tier2: {
        enabled: true,
        provider: 'mock',
        timeout_ms: 2000
      }
    });
    const slow = new MockProvider('safe', 5000);
    const runner = new PolicyRunner({ config, engine: new PermissionEngine(config, slow) });
    // execute_command 'custom_runner_cmd' matches no Tier 1 rule, forcing Tier 2.
    const ctx: CanonicalContext = { toolName: 'execute_command', payload: 'custom_runner_cmd' };
    const controller = new AbortController();
    controller.abort();
    const out = await runner.run(ctx);
    // Abort races the provider; outcome is a fallback to allow by default.
    assert.equal(out.decision, 'allow');
    assert.equal(out.tierMatched, 'fallback');

    // With configured restrict:
    const restrictConfig = makeConfig({
      fallback_verdict: 'restrict',
      tier2: config.tier2
    });
    const restrictRunner = new PolicyRunner({ config: restrictConfig, engine: new PermissionEngine(restrictConfig, slow) });
    const restrictController = new AbortController();
    restrictController.abort();
    const restrictOut = await restrictRunner.run(ctx);
    assert.equal(restrictOut.decision, 'restrict');
    assert.equal(restrictOut.tierMatched, 'fallback');
  });
});

describe('PolicyRuntime mtime cache', () => {
  test('reloads config when config.json changes', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rt-'));
    const cfgPath = path.join(dir, 'config.json');
    fs.writeFileSync(cfgPath, JSON.stringify(makeConfig({ mode: 'auto' })));
    const rt = new PolicyRuntime(cfgPath, path.join(dir, 'credentials.json'));
    const r1 = await rt.getRunner().run({ toolName: 'execute_command', payload: 'ls', cwd: dir });
    assert.equal(r1.decision, 'allow');
    // Flip Tier 1: restrict everything matching ls.
    const cfg2 = makeConfig({ mode: 'auto' });
    cfg2.rules.restrict = [{ tool: 'execute_command', pattern: '^ls' }];
    cfg2.rules.allow = [];
    fs.writeFileSync(cfgPath, JSON.stringify(cfg2));
    // Ensure mtime advances (filesystem granularity).
    await new Promise((r) => setTimeout(r, 15));
    const r2 = await rt.getRunner().run({ toolName: 'execute_command', payload: 'ls', cwd: dir });
    assert.equal(r2.decision, 'restrict');
  });

  test('telemetry logger is invoked via runner', async () => {
    const config = makeConfig({ telemetry: { enabled: true, log_dir: 'logs' } });
    let logged = 0;
    const logger = new TelemetryLogger(config);
    const orig = logger.log.bind(logger);
    logger.log = ((ctx: CanonicalContext, res: Parameters<typeof orig>[1]) => {
      logged++;
      return orig(ctx, res);
    }) as typeof logger.log;
    const runner = new PolicyRunner({ config, engine: new PermissionEngine(config), telemetry: logger });
    await runner.run({ toolName: 'execute_command', payload: 'ls', cwd: process.cwd() });
    assert.equal(logged, 1);
  });
});
