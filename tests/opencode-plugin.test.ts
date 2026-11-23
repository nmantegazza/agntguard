import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// The transport is an OpenCode plugin module importing @opencode/plugin.
// Exercise it in-process with a stubbed ctx instead of spawning subprocesses.
describe('OpenCode in-process plugin transport', () => {
  let dir: string;
  let configPath: string;
  let prevEnv: string | undefined;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oc-plugin-'));
    configPath = path.join(dir, 'config.json');
    prevEnv = process.env.AGNTGUARD_CONFIG;
  });

  afterEach(() => {
    if (prevEnv === undefined) delete process.env.AGNTGUARD_CONFIG;
    else process.env.AGNTGUARD_CONFIG = prevEnv;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function writeConfig(mode = 'auto', telemetryEnabled = false) {
    fs.writeFileSync(
      configPath,
      JSON.stringify({
        mode,
        agent: 'opencode',
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
        telemetry: { enabled: telemetryEnabled, log_dir: path.join(dir, 'logs') }
      })
    );
  }

  async function loadPlugin() {
    return (await import('../dist/agents/opencode-adapter.js')).default;
  }

  function stubCtx(overrides: Record<string, unknown> = {}) {
    const hooks: Array<(event: Record<string, unknown>) => Promise<void>> = [];
    return {
      ctx: {
        options: { configPath, enrichSessionContext: false, ...overrides },
        location: { directory: dir },
        session: { context: async () => [] },
        permission: {
          hook: async (_name: string, fn: (event: Record<string, unknown>) => Promise<void>) => {
            hooks.push(fn);
            return { dispose: () => {} };
          }
        }
      },
      hooks
    };
  }

  test('allow effect for Tier 1 allow match', async () => {
    writeConfig();
    const plugin = await loadPlugin();
    const { ctx, hooks } = stubCtx();
    let disposed = false;
    const cleanup = await plugin.setup({
      ...ctx,
      permission: {
        hook: async (_n: string, fn: never) => {
          hooks.push(fn as never);
          return { dispose: () => { disposed = true; } };
        }
      }
    } as never);
    const event: Record<string, unknown> = {
      sessionID: 's1',
      action: 'shell',
      resources: ['ls -la'],
      effect: 'ask'
    };
    await hooks[0](event);
    assert.equal(event.effect, 'allow');
    assert.ok(typeof event.message === 'string' && event.message.length > 0);
    (cleanup as () => void)();
    assert.equal(disposed, true);
  });

  test('deny effect for Tier 1 restrict match in auto mode', async () => {
    writeConfig('auto');
    const plugin = await loadPlugin();
    const { ctx, hooks } = stubCtx();
    await plugin.setup(ctx as never);
    const event: Record<string, unknown> = {
      sessionID: 's1',
      action: 'shell',
      resources: ['rm -rf /'],
      effect: 'allow'
    };
    await hooks[0](event);
    assert.equal(event.effect, 'deny');
  });

  test('ask effect for Tier 1 restrict match in ask mode', async () => {
    writeConfig('ask');
    const plugin = await loadPlugin();
    const { ctx, hooks } = stubCtx();
    await plugin.setup(ctx as never);
    const event: Record<string, unknown> = {
      sessionID: 's1',
      action: 'shell',
      resources: ['rm -rf /'],
      effect: 'allow'
    };
    await hooks[0](event);
    assert.equal(event.effect, 'ask');
  });

  test('multi-resource worst-case combination (restrict wins)', async () => {
    writeConfig('auto');
    const plugin = await loadPlugin();
    const { ctx, hooks } = stubCtx();
    await plugin.setup(ctx as never);
    const event: Record<string, unknown> = {
      sessionID: 's1',
      action: 'shell',
      resources: ['ls', 'rm -rf /'],
      effect: 'allow'
    };
    await hooks[0](event);
    assert.equal(event.effect, 'deny');
  });

  test('multi-resource evaluation logs separate telemetry records per evaluated resource and short-circuits', async () => {
    writeConfig('auto', true);
    const plugin = await loadPlugin();
    const { ctx, hooks } = stubCtx();
    await plugin.setup(ctx as never);
    const event: Record<string, unknown> = {
      sessionID: 's-multi-telemetry',
      action: 'shell',
      resources: ['ls', 'rm -rf /', 'pwd'],
      effect: 'allow'
    };
    await hooks[0](event);
    assert.equal(event.effect, 'deny');

    const logDir = path.join(dir, 'logs');
    const dayDirs = fs.readdirSync(logDir);
    assert.equal(dayDirs.length, 1);
    const decisionsPath = path.join(logDir, dayDirs[0], 'decisions.jsonl');
    assert.ok(fs.existsSync(decisionsPath));

    const records = fs
      .readFileSync(decisionsPath, 'utf8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line));

    // 'ls' allowed (row 1), 'rm -rf /' restricted (row 2), 'pwd' short-circuited (never evaluated)
    assert.equal(records.length, 2);
    assert.equal(records[0].action.payload, 'ls');
    assert.equal(records[0].outcome.verdict, 'allow');
    assert.equal(records[0].action.resources, undefined);

    assert.equal(records[1].action.payload, 'rm -rf /');
    assert.equal(records[1].outcome.verdict, 'restrict');
    assert.equal(records[1].action.resources, undefined);
  });

  test('zero-config allow when config is missing', async () => {
    const plugin = await loadPlugin();
    const missing = path.join(dir, 'missing.json');
    const { ctx, hooks } = stubCtx({ configPath: missing });
    await plugin.setup(ctx as never);
    const event: Record<string, unknown> = {
      sessionID: 's1',
      action: 'shell',
      resources: ['ls'],
      effect: 'deny'
    };
    await hooks[0](event);
    assert.equal(event.effect, 'allow');
    assert.match(String(event.message), /Permitted by Tier 1 allow pattern/);
  });

  test('fallback allow when config is corrupted', async () => {
    const plugin = await loadPlugin();
    const corrupt = path.join(dir, 'corrupt.json');
    fs.writeFileSync(corrupt, '{ invalid json');
    const { ctx, hooks } = stubCtx({ configPath: corrupt });
    await plugin.setup(ctx as never);
    const event: Record<string, unknown> = {
      sessionID: 's1',
      action: 'shell',
      resources: ['ls'],
      effect: 'deny'
    };
    await hooks[0](event);
    assert.equal(event.effect, 'allow');
    assert.match(String(event.message), /Auto-permissions fallback/);
  });
});
