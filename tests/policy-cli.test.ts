import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { saveConfig } from '../dist/config.js';
import type { PolicyConfig } from '../src/types.js';

const execFileAsync = promisify(execFile);

describe('Policy Management CLI', () => {
  let tmpDir: string;
  let testConfigPath: string;
  let testCredentialsPath: string;
  const cliScript = path.resolve('dist/cli.js');

  const baseTestConfig: PolicyConfig = {
    mode: 'auto',
    fallback_verdict: 'allow',
    unmapped_tool_verdict: 'allow',
    paths: {
      outside_read: 'allow',
      outside_write: 'restrict',
      no_access: ['/custom/secret'],
      read_only: ['/custom/readonly'],
      allowed: ['/custom/allowed']
    },
    adapter: {
      name: 'antigravity',
      tool_mappings: {}
    },
    rules: {
      restrict: [{ tool: 'execute_command', pattern: '^rm\\s+(-rf|-fr|--recursive\\s+--force)\\s+[/~]', dimension: 'harmful' }],
      allow: [{ tool: 'execute_command', pattern: '^git\\s+status$' }]
    },
    tier2: {
      enabled: false,
      provider: 'typesafe',
      timeout_ms: 800,
      model: 'jev-latest'
    },
    telemetry: {
      enabled: true,
      log_dir: 'logs'
    }
  };

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agntguard-cli-'));
    testConfigPath = path.join(tmpDir, 'config.json');
    testCredentialsPath = path.join(tmpDir, 'credentials.json');
    saveConfig(structuredClone(baseTestConfig), testConfigPath);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('rule add and rule remove modifies configuration for default tool', async () => {
    const env = { ...process.env, AGNTGUARD_CONFIG: testConfigPath, NO_COLOR: '1' };

    // 1. Add rule
    const { stdout: addOut } = await execFileAsync(
      'node',
      [cliScript, 'rule', 'add', '--list', 'restrict', '--pattern', '^bad-command$', '--dimension', 'harmful'],
      { env }
    );
    assert.match(addOut, /Added pattern to \[restrict\] \(execute_command\)/);

    const configAfterAdd = JSON.parse(fs.readFileSync(testConfigPath, 'utf8'));
    assert.ok(configAfterAdd.rules.restrict.some((r: any) => r.tool === 'execute_command' && r.pattern === '^bad-command$'));

    // 2. Remove rule
    const { stdout: removeOut } = await execFileAsync(
      'node',
      [cliScript, 'rule', 'remove', '--list', 'restrict', '--pattern', '^bad-command$'],
      { env }
    );
    assert.match(removeOut, /Removed pattern from \[restrict\] \(execute_command\)/);

    const configAfterRemove = JSON.parse(fs.readFileSync(testConfigPath, 'utf8'));
    assert.ok(!configAfterRemove.rules.restrict.some((r: any) => r.tool === 'execute_command' && r.pattern === '^bad-command$'));
  });

  test('rule add and rule remove with explicit --tool', async () => {
    const env = { ...process.env, AGNTGUARD_CONFIG: testConfigPath, NO_COLOR: '1' };

    // 1. Add rule for read_file
    const { stdout: addOut } = await execFileAsync(
      'node',
      [cliScript, 'rule', 'add', '--tool', 'read_file', '--list', 'restrict', '--pattern', '\\.env$', '--dimension', 'sensitive'],
      { env }
    );
    assert.match(addOut, /Added pattern to \[restrict\] \(read_file\)/);

    const configAfterAdd = JSON.parse(fs.readFileSync(testConfigPath, 'utf8'));
    assert.ok(configAfterAdd.rules.restrict.some((r: any) => r.tool === 'read_file' && r.pattern === '\\.env$'));

    // 2. Remove rule for read_file
    const { stdout: removeOut } = await execFileAsync(
      'node',
      [cliScript, 'rule', 'remove', '--tool', 'read_file', '--list', 'restrict', '--pattern', '\\.env$'],
      { env }
    );
    assert.match(removeOut, /Removed pattern from \[restrict\] \(read_file\)/);

    const configAfterRemove = JSON.parse(fs.readFileSync(testConfigPath, 'utf8'));
    assert.ok(!configAfterRemove.rules.restrict.some((r: any) => r.tool === 'read_file' && r.pattern === '\\.env$'));
  });

  test('rule list summarizes system rules by default and expands with --system', async () => {
    const env = { ...process.env, AGNTGUARD_CONFIG: testConfigPath, NO_COLOR: '1' };

    // Default: system rules collapsed
    const { stdout: collapsedOut } = await execFileAsync('node', [cliScript, 'rule', 'list'], { env });
    assert.match(collapsedOut, /Active Config:/);
    assert.match(collapsedOut, /Operating Mode:\s+auto/);
    assert.match(collapsedOut, /=== Rules ===/);
    assert.match(collapsedOut, /Tool: execute_command/);
    assert.match(collapsedOut, /built-in patterns active \(--system to expand\)/);
    assert.match(collapsedOut, /\[User\]/);

    // Expanded with --system
    const { stdout: expandedOut } = await execFileAsync('node', [cliScript, 'rule', 'list', '--system'], { env });
    assert.match(expandedOut, /\[System\]/);
    assert.match(expandedOut, /curl.*ba.*sh/);
  });

  test('rule remove rejects deletion of system rules with exit code 1', async () => {
    const env = { ...process.env, AGNTGUARD_CONFIG: testConfigPath, NO_COLOR: '1' };
    const systemPattern = 'curl\\s+.*\\|\\s*(ba)?sh';

    await assert.rejects(
      execFileAsync(
        'node',
        [cliScript, 'rule', 'remove', '--list', 'restrict', '--pattern', systemPattern],
        { env }
      ),
      (err: any) => {
        assert.equal(err.code, 1);
        assert.match(
          err.stderr,
          /Cannot remove system rule ".*"\. System rules are built-in security guardrails and cannot be deleted\./
        );
        return true;
      }
    );
  });

  test('path add, path remove, and path list functionality', async () => {
    const env = { ...process.env, AGNTGUARD_CONFIG: testConfigPath, NO_COLOR: '1' };

    // 1. Path add
    const { stdout: addOut } = await execFileAsync(
      'node',
      [cliScript, 'path', 'add', '--list', 'no_access', '--pattern', '/custom/new_secret'],
      { env }
    );
    assert.match(addOut, /Added path to \[no_access\]: \/custom\/new_secret/);

    const configAfterAdd = JSON.parse(fs.readFileSync(testConfigPath, 'utf8'));
    assert.ok(configAfterAdd.paths.no_access.includes('/custom/new_secret'));

    // 2. Path list collapsed by default
    const { stdout: listOut } = await execFileAsync('node', [cliScript, 'path', 'list'], { env });
    assert.match(listOut, /=== Path Policy \(Gate 2\)/);
    assert.match(listOut, /outside_read: allow/);
    assert.match(listOut, /outside_write: restrict/);
    assert.match(listOut, /built-in paths protected \(--system to expand\)/);
    assert.match(listOut, /\[User\] \/custom\/new_secret/);

    // 3. Path list expanded with --system
    const { stdout: listExpandedOut } = await execFileAsync('node', [cliScript, 'path', 'list', '--system'], { env });
    assert.match(listExpandedOut, /\[System\]/);
    assert.match(listExpandedOut, /ssh/);

    // 4. Path remove user path
    const { stdout: removeOut } = await execFileAsync(
      'node',
      [cliScript, 'path', 'remove', '--list', 'no_access', '--pattern', '/custom/new_secret'],
      { env }
    );
    assert.match(removeOut, /Removed path from \[no_access\]: \/custom\/new_secret/);

    const configAfterRemove = JSON.parse(fs.readFileSync(testConfigPath, 'utf8'));
    assert.ok(!configAfterRemove.paths.no_access.includes('/custom/new_secret'));
  });

  test('path remove rejects deletion of system paths with exit code 1', async () => {
    const env = { ...process.env, AGNTGUARD_CONFIG: testConfigPath, NO_COLOR: '1' };
    const { SYSTEM_PATHS } = await import('../dist/core/defaults/system-rules.js');

    await assert.rejects(
      execFileAsync(
        'node',
        [cliScript, 'path', 'remove', '--list', 'no_access', '--pattern', SYSTEM_PATHS.noAccess[0]],
        { env }
      ),
      (err: any) => {
        assert.equal(err.code, 1);
        assert.match(
          err.stderr,
          /Cannot remove system path ".*"\. System rules are built-in security guardrails and cannot be deleted\./
        );
        return true;
      }
    );
  });

  test('config get and config set updates configuration values', async () => {
    const env = { ...process.env, AGNTGUARD_CONFIG: testConfigPath, NO_COLOR: '1' };

    // Set tier2.timeout_ms to 1234
    await execFileAsync('node', [cliScript, 'config', 'set', 'tier2.timeout_ms', '1234'], { env });

    const { stdout: getOut } = await execFileAsync('node', [cliScript, 'config', 'get', 'tier2.timeout_ms'], { env });
    assert.equal(getOut.trim(), '1234');

    // Set mode to ask
    await execFileAsync('node', [cliScript, 'config', 'set', 'mode', 'ask'], { env });
    const { stdout: getModeOut } = await execFileAsync('node', [cliScript, 'config', 'get', 'mode'], { env });
    assert.equal(getModeOut.trim(), 'ask');

    // Set fallback_verdict to restrict
    await execFileAsync('node', [cliScript, 'config', 'set', 'fallback_verdict', 'restrict'], { env });
    const { stdout: getFallbackOut } = await execFileAsync('node', [cliScript, 'config', 'get', 'fallback_verdict'], { env });
    assert.equal(getFallbackOut.trim(), 'restrict');
  });

  test('config set whitelist schema validation rejects invalid keys and values', async () => {
    const env = { ...process.env, AGNTGUARD_CONFIG: testConfigPath, NO_COLOR: '1' };

    // 1. Unknown key
    await assert.rejects(
      execFileAsync('node', [cliScript, 'config', 'set', 'invalid.key', 'true'], { env }),
      (err: any) => {
        assert.equal(err.code, 1);
        assert.match(err.stderr, /Unknown configuration key "invalid\.key"/);
        return true;
      }
    );

    // 2. Invalid enum for mode
    await assert.rejects(
      execFileAsync('node', [cliScript, 'config', 'set', 'mode', 'turbo'], { env }),
      (err: any) => {
        assert.equal(err.code, 1);
        assert.match(err.stderr, /Invalid value "turbo" for key "mode"/);
        return true;
      }
    );

    // 3. Out-of-range integer for tier2.timeout_ms
    await assert.rejects(
      execFileAsync('node', [cliScript, 'config', 'set', 'tier2.timeout_ms', '50'], { env }),
      (err: any) => {
        assert.equal(err.code, 1);
        assert.match(err.stderr, /below minimum 100/);
        return true;
      }
    );
  });

  test('config reset --yes restores default configuration', async () => {
    const env = { ...process.env, AGNTGUARD_CONFIG: testConfigPath, NO_COLOR: '1' };

    // Modify a value
    await execFileAsync('node', [cliScript, 'config', 'set', 'mode', 'ask'], { env });

    // Reset config
    const { stdout: resetOut } = await execFileAsync('node', [cliScript, 'config', 'reset', '--yes'], { env });
    assert.match(resetOut, /Successfully reset configuration/);

    const { stdout: getModeOut } = await execFileAsync('node', [cliScript, 'config', 'get', 'mode'], { env });
    assert.equal(getModeOut.trim(), 'auto');
  });

  test('key set and key remove manages credentials', async () => {
    const env = {
      ...process.env,
      AGNTGUARD_CONFIG: testConfigPath,
      AGNTGUARD_CREDENTIALS: testCredentialsPath
    };

    // 1. Set key
    const { stdout: setOut } = await execFileAsync(
      'node',
      [cliScript, 'key', 'set', 'ts_live_secret123'],
      { env }
    );
    assert.match(setOut, /Successfully stored API key/);
    assert.ok(fs.existsSync(testCredentialsPath));

    // Verify 0600 file mode
    const stat = fs.statSync(testCredentialsPath);
    const mode = stat.mode & 0o777;
    assert.equal(mode, 0o600);

    // 2. Remove key
    const { stdout: removeOut } = await execFileAsync(
      'node',
      [cliScript, 'key', 'remove', '--yes'],
      { env }
    );
    assert.match(removeOut, /Successfully removed API key/);
    assert.ok(!fs.existsSync(testCredentialsPath));
  });
});
