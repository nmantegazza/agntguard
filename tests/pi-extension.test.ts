import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import agntguardExtension, { PiAdapter } from '../dist/agents/pi-adapter.js';
import type {
  PiToolCallEvent,
  PiExtensionContext,
  PiToolCallEventResult,
  PiHandleOptions
} from '../dist/agents/pi-adapter.js';
import { userRejectedReason, reasonFor } from '../dist/core/engine/reason-catalog.js';

describe('Pi in-process extension transport', () => {
  let dir: string;
  let configPath: string;
  let prevEnv: string | undefined;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pi-ext-'));
    configPath = path.join(dir, 'config.json');
    prevEnv = process.env.AGNTGUARD_CONFIG;
  });

  afterEach(() => {
    if (prevEnv === undefined) delete process.env.AGNTGUARD_CONFIG;
    else process.env.AGNTGUARD_CONFIG = prevEnv;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function writeConfig(options: {
    mode?: 'auto' | 'ask';
    telemetryEnabled?: boolean;
    fallbackVerdict?: 'allow' | 'restrict';
  } = {}) {
    const mode = options.mode ?? 'auto';
    const fallbackVerdict = options.fallbackVerdict ?? 'allow';
    const telemetryEnabled = options.telemetryEnabled ?? false;

    fs.writeFileSync(
      configPath,
      JSON.stringify({
        mode,
        agent: 'pi',
        fallback_verdict: fallbackVerdict,
        unmapped_tool_verdict: 'allow',
        rules: {
          restrict: [
            { tool: 'execute_command', pattern: '^rm -rf /', dimension: 'harmful' },
            { tool: 'execute_command', pattern: '^format c:', dimension: 'harmful' },
            { tool: 'read_file', pattern: '(^|/)\\.env($|\\.)', dimension: 'sensitive' },
            { tool: 'read_file', pattern: '.*id_rsa.*', dimension: 'sensitive' },
            { tool: 'write_file', pattern: '^/etc/hosts', dimension: 'harmful' }
          ],
          allow: [
            { tool: 'execute_command', pattern: '^git status' },
            { tool: 'execute_command', pattern: '^dir' },
            { tool: 'read_file', pattern: '^safe\\.txt$' },
            { tool: 'read_file', pattern: '^\\.$' },
            { tool: 'read_file', pattern: '^/project$' },
            { tool: 'read_file', pattern: '.*\\.ts$' },
            { tool: 'write_file', pattern: '^safe-out\\.txt$' }
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

  function setupExtension(handleOptions?: PiHandleOptions) {
    const handlers: Array<(event: PiToolCallEvent, ctx: PiExtensionContext) => Promise<PiToolCallEventResult | undefined>> = [];
    const pi = {
      on: (event: string, fn: any) => {
        if (event === 'tool_call') handlers.push(fn);
      }
    };
    agntguardExtension(pi, { configPath, ...handleOptions });
    assert.equal(handlers.length, 1);
    return handlers[0];
  }

  test('1. Tier 1 allow and restrict verdicts across all supported tools', async () => {
    writeConfig({ mode: 'auto' });
    const onToolCall = setupExtension();
    const ctx: PiExtensionContext = { hasUI: false };

    // bash
    const bashAllow = await onToolCall({ type: 'tool_call', toolName: 'bash', input: { command: 'git status' } }, ctx);
    assert.equal(bashAllow, undefined);
    const bashBlock = await onToolCall({ type: 'tool_call', toolName: 'bash', input: { command: 'rm -rf /' } }, ctx);
    assert.equal(bashBlock?.block, true);
    assert.match(String(bashBlock?.reason), /Denied by agntguard/);

    // powershell
    const psAllow = await onToolCall({ type: 'tool_call', toolName: 'powershell', input: { command: 'dir' } }, ctx);
    assert.equal(psAllow, undefined);
    const psBlock = await onToolCall({ type: 'tool_call', toolName: 'powershell', input: { command: 'format c:' } }, ctx);
    assert.equal(psBlock?.block, true);

    // read
    const readAllow = await onToolCall({ type: 'tool_call', toolName: 'read', input: { path: 'safe.txt' } }, ctx);
    assert.equal(readAllow, undefined);
    const readBlock = await onToolCall({ type: 'tool_call', toolName: 'read', input: { path: '.env' } }, ctx);
    assert.equal(readBlock?.block, true);

    // write
    const writeAllow = await onToolCall({ type: 'tool_call', toolName: 'write', input: { path: 'safe-out.txt' } }, ctx);
    assert.equal(writeAllow, undefined);
    const writeBlock = await onToolCall({ type: 'tool_call', toolName: 'write', input: { path: '/etc/hosts' } }, ctx);
    assert.equal(writeBlock?.block, true);

    // edit
    const editAllow = await onToolCall({ type: 'tool_call', toolName: 'edit', input: { path: 'safe-out.txt' } }, ctx);
    assert.equal(editAllow, undefined);
    const editBlock = await onToolCall({ type: 'tool_call', toolName: 'edit', input: { path: '/etc/hosts' } }, ctx);
    assert.equal(editBlock?.block, true);

    // ls
    const lsAllow = await onToolCall({ type: 'tool_call', toolName: 'ls', input: { path: '/project' } }, ctx);
    assert.equal(lsAllow, undefined);
    const lsBlock = await onToolCall({ type: 'tool_call', toolName: 'ls', input: { path: '.env' } }, ctx);
    assert.equal(lsBlock?.block, true);

    // find
    const findAllow = await onToolCall({ type: 'tool_call', toolName: 'find', input: { path: '/project' } }, ctx);
    assert.equal(findAllow, undefined);
    const findBlock = await onToolCall({ type: 'tool_call', toolName: 'find', input: { path: '.env' } }, ctx);
    assert.equal(findBlock?.block, true);

    // grep
    const grepAllow = await onToolCall({ type: 'tool_call', toolName: 'grep', input: { path: '/project' } }, ctx);
    assert.equal(grepAllow, undefined);
    const grepBlock = await onToolCall({ type: 'tool_call', toolName: 'grep', input: { path: '.env' } }, ctx);
    assert.equal(grepBlock?.block, true);
  });

  test('2. Default payload fallback to "." for ls, find, and grep', async () => {
    writeConfig({ mode: 'auto' });
    const onToolCall = setupExtension();
    const ctx: PiExtensionContext = { hasUI: false };

    // ls with empty input falls back to "." which matches allow rule "^\\.$"
    const lsDefault = await onToolCall({ type: 'tool_call', toolName: 'ls', input: {} }, ctx);
    assert.equal(lsDefault, undefined);

    // find with empty input falls back to "."
    const findDefault = await onToolCall({ type: 'tool_call', toolName: 'find', input: {} }, ctx);
    assert.equal(findDefault, undefined);

    // grep with empty input falls back to "."
    const grepDefault = await onToolCall({ type: 'tool_call', toolName: 'grep', input: {} }, ctx);
    assert.equal(grepDefault, undefined);
  });

  test('3. Multi-resource short-circuiting for find and grep', async () => {
    writeConfig({ mode: 'auto' });
    const onToolCall = setupExtension();
    const ctx: PiExtensionContext = { hasUI: false };

    // find with safe path but sensitive pattern is blocked
    const findMixed = await onToolCall(
      { type: 'tool_call', toolName: 'find', input: { path: '/project', pattern: '.env' } },
      ctx
    );
    assert.equal(findMixed?.block, true);
    assert.match(String(findMixed?.reason), /denied by agntguard/i);

    // grep with safe path but sensitive glob is blocked
    const grepMixed = await onToolCall(
      { type: 'tool_call', toolName: 'grep', input: { path: '/project', glob: 'id_rsa' } },
      ctx
    );
    assert.equal(grepMixed?.block, true);
    assert.match(String(grepMixed?.reason), /denied by agntguard/i);

    // find with both safe is allowed
    const findBothSafe = await onToolCall(
      { type: 'tool_call', toolName: 'find', input: { path: '/project', pattern: 'safe.txt' } },
      ctx
    );
    assert.equal(findBothSafe, undefined);
  });

  test('4. Active-branch session enrichment populates context and telemetry', async () => {
    writeConfig({ mode: 'auto', telemetryEnabled: true });
    const onToolCall = setupExtension();

    const ctx: PiExtensionContext = {
      hasUI: false,
      sessionManager: {
        getSessionId: () => 'pi-session-xyz',
        getBranch: () => [
          { role: 'user', content: 'Initial user objective' },
          {
            role: 'assistant',
            parts: [{ type: 'tool_call', name: 'read', input: { path: 'safe.txt' } }]
          },
          { role: 'user', content: 'Latest instruction update' }
        ]
      }
    };

    // Verify CanonicalContext enrichment
    const canonicalCtx = await PiAdapter.buildContext(
      { type: 'tool_call', toolName: 'bash', input: { command: 'git status' } },
      ctx
    );
    assert.equal(canonicalCtx.agent, 'pi');
    assert.equal(canonicalCtx.conversationId, 'pi-session-xyz');
    assert.equal(canonicalCtx.latestUserRequest, 'Latest instruction update');
    assert.deepEqual(canonicalCtx.previousUserRequests, ['Initial user objective']);
    assert.deepEqual(canonicalCtx.recentToolCalls, [{ tool: 'read_file', payload: 'safe.txt' }]);

    // Verify extension execution and telemetry recording
    const res = await onToolCall(
      { type: 'tool_call', toolName: 'bash', input: { command: 'git status' } },
      ctx
    );
    assert.equal(res, undefined);

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

    assert.equal(records.length, 1);
    assert.equal(records[0].agent, 'pi');
    assert.equal(records[0].conversationId, 'pi-session-xyz');
    assert.equal(records[0].outcome.verdict, 'allow');
  });


  test('5. Operating mode enforcement: auto vs ask (interactive approval, decline, headless)', async () => {
    // 5a. Auto mode immediately denies
    writeConfig({ mode: 'auto' });
    let onToolCall = setupExtension();
    let res = await onToolCall(
      { type: 'tool_call', toolName: 'bash', input: { command: 'rm -rf /' } },
      { hasUI: false }
    );
    assert.equal(res?.block, true);
    assert.match(String(res?.reason), /^Denied by agntguard:/);

    // 5b. Ask mode with UI: user approves
    writeConfig({ mode: 'ask' });
    onToolCall = setupExtension();

    let confirmPromptReceived = '';
    const uiApproved = {
      confirm: async (_title: string, message: string) => {
        confirmPromptReceived = message;
        return true;
      }
    };
    res = await onToolCall(
      { type: 'tool_call', toolName: 'bash', input: { command: 'rm -rf /' } },
      { hasUI: true, ui: uiApproved }
    );
    assert.equal(res, undefined);
    assert.match(confirmPromptReceived, /Do you want to authorize this operation\?/);

    // 5c. Ask mode with UI: user declines
    let confirmPromptDecline = '';
    const uiDeclined = {
      confirm: async (_title: string, message: string) => {
        confirmPromptDecline = message;
        return false;
      }
    };
    res = await onToolCall(
      { type: 'tool_call', toolName: 'bash', input: { command: 'rm -rf /' } },
      { hasUI: true, ui: uiDeclined }
    );
    assert.equal(res?.block, true);
    assert.equal(res?.reason, userRejectedReason());
    assert.match(confirmPromptDecline, /Do you want to authorize this operation\?/);

    // 5d. Ask mode without UI: automatic block with generic refusal without calling ui.confirm
    let confirmCalled = false;
    const uiHeadless = {
      confirm: async () => {
        confirmCalled = true;
        return true;
      }
    };
    res = await onToolCall(
      { type: 'tool_call', toolName: 'bash', input: { command: 'rm -rf /' } },
      { hasUI: false, ui: uiHeadless }
    );
    assert.equal(res?.block, true);
    assert.equal(confirmCalled, false);
    assert.equal(res?.reason, reasonFor(undefined, 'auto'));
  });

  test('6. Fail-safe fallback when error occurs', async () => {
    // 6a. Fallback verdict allow: returns undefined on corrupted config
    writeConfig({ fallbackVerdict: 'allow' });
    fs.writeFileSync(configPath, '{ corrupted json');
    let onToolCall = setupExtension();

    let res = await onToolCall(
      { type: 'tool_call', toolName: 'bash', input: { command: 'ls' } },
      { hasUI: false }
    );
    assert.equal(res, undefined);

    // 6b. Fallback verdict restrict: returns block: true when evaluation throws
    const throwingRuntime = {
      getConfig: () => ({ mode: 'auto' as const, fallback_verdict: 'restrict' as const }),
      getRunner: () => {
        throw new Error('Internal evaluation failure');
      }
    };
    onToolCall = setupExtension({ runtime: throwingRuntime as any });

    res = await onToolCall(
      { type: 'tool_call', toolName: 'bash', input: { command: 'ls' } },
      { hasUI: false }
    );
    assert.equal(res?.block, true);
    assert.match(String(res?.reason), /restricted by fallback policy/);
  });


  test('7. Turn abort signal cleanly triggers fallback', async () => {
    writeConfig({ fallbackVerdict: 'allow' });
    const onToolCall = setupExtension();

    const controller = new AbortController();
    controller.abort();

    const res = await onToolCall(
      { type: 'tool_call', toolName: 'bash', input: { command: 'git status' } },
      { hasUI: false, signal: controller.signal }
    );
    assert.equal(res, undefined);
  });
});
