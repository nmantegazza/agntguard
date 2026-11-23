import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';

describe('Antigravity stdio transport', () => {
  let dir: string;
  let configPath: string;
  let prevEnv: string | undefined;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-stdio-'));
    configPath = path.join(dir, 'config.json');
    prevEnv = process.env.AGNTGUARD_CONFIG;
    process.env.AGNTGUARD_CONFIG = configPath;
    fs.writeFileSync(
      configPath,
      JSON.stringify({
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
        telemetry: { enabled: false, log_dir: path.join(dir, 'logs') }
      })
    );
  });

  afterEach(() => {
    if (prevEnv === undefined) delete process.env.AGNTGUARD_CONFIG;
    else process.env.AGNTGUARD_CONFIG = prevEnv;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  async function runTransport(payload: unknown): Promise<{ stdout: string; exitCode: number }> {
    const transport = path.resolve('dist/agents/antigravity-adapter.js');
    const input = typeof payload === 'string' ? payload : JSON.stringify(payload);
    return new Promise((resolve) => {
      const child = spawn(process.execPath, [transport], { timeout: 15000 });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => { stdout += String(d); });
      child.stderr.on('data', (d) => { stderr += String(d); });
      child.on('error', (err) => resolve({ stdout: `SPAWN_ERROR: ${err.message} ${stderr}`, exitCode: 1 }));
      child.on('close', (code) => resolve({ stdout, exitCode: code ?? 1 }));
      child.stdin.on('error', () => {});
      child.stdin.end(input);
    });
  }

  test('allow verdict for safe command', async () => {
    const { stdout, exitCode } = await runTransport({
      toolCall: { name: 'run_command', args: { CommandLine: 'ls -la', Cwd: dir } },
      workspacePaths: [dir]
    });
    assert.equal(exitCode, 0);
    const parsed = JSON.parse(stdout.trim());
    assert.equal(parsed.decision, 'allow');
    assert.deepEqual(parsed.permissionOverrides, ['command(ls -la)']);
  });

  test('allow verdict for read_file, write_file, and edit_file with Path argument', async () => {
    const { stdout: readOut, exitCode: readCode } = await runTransport({
      toolCall: { name: 'read_file', args: { Path: path.join(dir, 'safe.txt') } },
      workspacePaths: [dir]
    });
    assert.equal(readCode, 0);
    const readParsed = JSON.parse(readOut.trim());
    assert.equal(readParsed.decision, 'allow');
    assert.match(readParsed.reason, /Permitted by Tier 1 allow pattern/);

    const { stdout: writeOut, exitCode: writeCode } = await runTransport({
      toolCall: { name: 'write_file', args: { Path: path.join(dir, 'safe.txt'), Content: 'hi' } },
      workspacePaths: [dir]
    });
    assert.equal(writeCode, 0);
    const writeParsed = JSON.parse(writeOut.trim());
    assert.equal(writeParsed.decision, 'allow');

    const { stdout: editOut, exitCode: editCode } = await runTransport({
      toolCall: { name: 'edit_file', args: { Path: path.join(dir, 'safe.txt'), Target: 'h', Replacement: 'b' } },
      workspacePaths: [dir]
    });
    assert.equal(editCode, 0);
    const editParsed = JSON.parse(editOut.trim());
    assert.equal(editParsed.decision, 'allow');
  });

  test('deny verdict for destructive command in auto mode', async () => {
    const { stdout, exitCode } = await runTransport({
      toolCall: { name: 'run_command', args: { CommandLine: 'rm -rf /', Cwd: dir } },
      workspacePaths: [dir]
    });
    assert.equal(exitCode, 0);
    const parsed = JSON.parse(stdout.trim());
    assert.equal(parsed.decision, 'deny');
  });

  test('ask verdict for destructive command in ask mode', async () => {
    const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    cfg.mode = 'ask';
    fs.writeFileSync(configPath, JSON.stringify(cfg));

    const { stdout, exitCode } = await runTransport({
      toolCall: { name: 'run_command', args: { CommandLine: 'rm -rf /', Cwd: dir } },
      workspacePaths: [dir]
    });
    assert.equal(exitCode, 0);
    const parsed = JSON.parse(stdout.trim());
    assert.equal(parsed.decision, 'ask');
  });

  test('transport fallback behavior matches configured fallback_verdict on empty input', async () => {
    // 1. By default, fallback_verdict is allow
    const { stdout: defaultOut, exitCode: defaultCode } = await runTransport('');
    assert.equal(defaultCode, 0);
    const defaultParsed = JSON.parse(defaultOut.trim());
    assert.equal(defaultParsed.decision, 'allow');
    assert.match(defaultParsed.reason, /Empty input payload/);

    // 2. When configured to restrict (in auto mode -> deny)
    const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    cfg.fallback_verdict = 'restrict';
    fs.writeFileSync(configPath, JSON.stringify(cfg));

    const { stdout: denyOut, exitCode: denyCode } = await runTransport('');
    assert.equal(denyCode, 0);
    const denyParsed = JSON.parse(denyOut.trim());
    assert.equal(denyParsed.decision, 'deny');
    assert.match(denyParsed.reason, /Empty input payload/);
  });
});
