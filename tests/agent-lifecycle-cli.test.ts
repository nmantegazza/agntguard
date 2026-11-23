import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  enableAntigravity,
  disableAntigravity,
  inspectAntigravityHealth
} from '../dist/cli/agents/antigravity-link.js';
import {
  enableOpenCode,
  disableOpenCode,
  inspectOpenCodeHealth,
  getOpenCodeShimDir
} from '../dist/cli/agents/opencode-link.js';
import {
  enablePi,
  disablePi,
  inspectPiHealth
} from '../dist/cli/agents/pi-link.js';
import { inspectHealth } from '../dist/cli/agents/registry.js';

const execFileAsync = promisify(execFile);

describe('Agent Hook Lifecycle & Operational Status CLI', () => {
  let tmpBase: string;
  let geminiConfigDir: string;
  let opencodeConfigDir: string;
  let piDir: string;
  let runtimeDistDir: string;
  let agntguardDir: string;
  const cliScript = path.resolve('dist/cli.js');

  beforeEach(() => {
    tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'agntguard-lifecycle-'));
    geminiConfigDir = path.join(tmpBase, 'gemini', 'config');
    opencodeConfigDir = path.join(tmpBase, 'opencode');
    piDir = path.join(tmpBase, 'pi');
    runtimeDistDir = path.join(tmpBase, 'runtime_dist');
    agntguardDir = path.join(tmpBase, '.agntguard');

    // Create directories
    fs.mkdirSync(geminiConfigDir, { recursive: true });
    fs.mkdirSync(opencodeConfigDir, { recursive: true });
    fs.mkdirSync(piDir, { recursive: true });
    fs.mkdirSync(path.join(runtimeDistDir, 'agents'), { recursive: true });
    fs.mkdirSync(agntguardDir, { recursive: true });

    // Create dummy adapter scripts in runtimeDistDir
    fs.writeFileSync(path.join(runtimeDistDir, 'agents', 'antigravity-adapter.js'), '// antigravity adapter\n');
    fs.writeFileSync(path.join(runtimeDistDir, 'agents', 'opencode-adapter.js'), '// opencode adapter\n');
    fs.writeFileSync(path.join(runtimeDistDir, 'agents', 'pi-adapter.js'), '// pi adapter\n');

    // Set environment overrides
    process.env.ANTIGRAVITY_CONFIG_DIR = geminiConfigDir;
    process.env.OPENCODE_CONFIG_DIR = opencodeConfigDir;
    delete process.env.OPENCODE_CONFIG_FILE;
    process.env.PI_DIR = piDir;
    delete process.env.PI_EXTENSION_DIR;
    process.env.AGNTGUARD_RUNTIME_DIST = runtimeDistDir;
    process.env.AGNTGUARD_DIR = agntguardDir;
  });

  afterEach(() => {
    delete process.env.ANTIGRAVITY_CONFIG_DIR;
    delete process.env.OPENCODE_CONFIG_DIR;
    delete process.env.OPENCODE_CONFIG_FILE;
    delete process.env.PI_DIR;
    delete process.env.PI_EXTENSION_DIR;
    delete process.env.AGNTGUARD_RUNTIME_DIST;
    delete process.env.AGNTGUARD_DIR;
    fs.rmSync(tmpBase, { recursive: true, force: true });
  });

  test('Antigravity shim creation, deletion, and health check', () => {
    assert.equal(inspectAntigravityHealth(runtimeDistDir), 'disabled');

    // Enable Antigravity
    enableAntigravity(runtimeDistDir);
    const pluginJsonPath = path.join(geminiConfigDir, 'plugins', 'agntguard', 'plugin.json');
    const hooksJsonPath = path.join(geminiConfigDir, 'plugins', 'agntguard', 'hooks.json');

    assert.ok(fs.existsSync(pluginJsonPath));
    assert.ok(fs.existsSync(hooksJsonPath));

    const hooks = JSON.parse(fs.readFileSync(hooksJsonPath, 'utf8'));
    assert.match(hooks.agntguard.PreToolUse[0].hooks[0].command, /antigravity-adapter\.js/);
    assert.equal(inspectAntigravityHealth(runtimeDistDir), 'enabled');

    // Disable Antigravity
    disableAntigravity();
    assert.ok(!fs.existsSync(hooksJsonPath));
    assert.equal(inspectAntigravityHealth(runtimeDistDir), 'disabled');
  });

  test('OpenCode shim package creation, opencode.json registration, and disable', () => {
    const opencodeJsonPath = path.join(opencodeConfigDir, 'opencode.json');
    fs.writeFileSync(opencodeJsonPath, JSON.stringify({ theme: 'dark' }, null, 2));

    assert.equal(inspectOpenCodeHealth(runtimeDistDir), 'disabled');

    // Enable OpenCode
    enableOpenCode(runtimeDistDir);
    const shimDir = getOpenCodeShimDir();
    assert.ok(fs.existsSync(path.join(shimDir, 'package.json')));
    assert.ok(fs.existsSync(path.join(shimDir, 'index.js')));

    const updatedConfig = JSON.parse(fs.readFileSync(opencodeJsonPath, 'utf8'));
    assert.equal(updatedConfig.theme, 'dark');
    assert.ok(Array.isArray(updatedConfig.plugins));
    assert.equal(updatedConfig.plugins[0].package, shimDir);
    assert.equal(inspectOpenCodeHealth(runtimeDistDir), 'enabled');

    // Disable OpenCode
    disableOpenCode();
    const disabledConfig = JSON.parse(fs.readFileSync(opencodeJsonPath, 'utf8'));
    assert.equal(disabledConfig.plugins.length, 0);
    assert.ok(!fs.existsSync(shimDir));
    assert.equal(inspectOpenCodeHealth(runtimeDistDir), 'disabled');
  });

  test('OpenCode preserves JSONC files with comments without overwriting', () => {
    const opencodeJsoncPath = path.join(opencodeConfigDir, 'opencode.jsonc');
    const initialContent = '// User configuration comments\n{\n  /* custom theme */\n  "theme": "nord"\n}\n';
    fs.writeFileSync(opencodeJsoncPath, initialContent);

    // Run enableOpenCode
    enableOpenCode(runtimeDistDir);

    // Verify file content was not overwritten
    const contentAfter = fs.readFileSync(opencodeJsoncPath, 'utf8');
    assert.equal(contentAfter, initialContent);
  });

  test('Pi extension shim creation, deletion, and health check', () => {
    assert.equal(inspectPiHealth(runtimeDistDir), 'disabled');

    // Enable Pi
    enablePi(runtimeDistDir);
    const extDir = path.join(piDir, 'agent', 'extensions', 'agntguard');
    assert.ok(fs.existsSync(path.join(extDir, 'package.json')));
    assert.ok(fs.existsSync(path.join(extDir, 'index.js')));

    const indexJs = fs.readFileSync(path.join(extDir, 'index.js'), 'utf8');
    assert.match(indexJs, /export \{ default \} from '.*pi-adapter\.js';/);
    assert.equal(inspectPiHealth(runtimeDistDir), 'enabled');

    // Disable Pi
    disablePi();
    assert.ok(!fs.existsSync(extDir));
    assert.equal(inspectPiHealth(runtimeDistDir), 'disabled');
  });

  test('detects broken hook when shim exists but target adapter is missing', () => {
    enableAntigravity(runtimeDistDir);
    enablePi(runtimeDistDir);

    assert.equal(inspectAntigravityHealth(runtimeDistDir), 'enabled');
    assert.equal(inspectPiHealth(runtimeDistDir), 'enabled');

    // Delete adapter files
    fs.unlinkSync(path.join(runtimeDistDir, 'agents', 'antigravity-adapter.js'));
    fs.unlinkSync(path.join(runtimeDistDir, 'agents', 'pi-adapter.js'));

    assert.equal(inspectAntigravityHealth(runtimeDistDir), 'broken');
    assert.equal(inspectPiHealth(runtimeDistDir), 'broken');

    const health = inspectHealth();
    assert.equal(health.antigravity.status, 'broken');
    assert.equal(health.pi.status, 'broken');
  });

  test('CLI enable, status, and disable commands end-to-end', async () => {
    const env = {
      ...process.env,
      ANTIGRAVITY_CONFIG_DIR: geminiConfigDir,
      OPENCODE_CONFIG_DIR: opencodeConfigDir,
      PI_DIR: piDir,
      AGNTGUARD_RUNTIME_DIST: runtimeDistDir,
      AGNTGUARD_DIR: agntguardDir
    };

    // 1. Enable specific agents
    const { stdout: enableOut } = await execFileAsync(
      'node',
      [cliScript, 'enable', 'antigravity', 'pi'],
      { env }
    );
    assert.match(enableOut, /Enabled AgntGuard hook for antigravity/);
    assert.match(enableOut, /Enabled AgntGuard hook for pi/);

    // 2. Status dashboard
    const { stdout: statusOut } = await execFileAsync('node', [cliScript, 'status'], { env });
    assert.match(statusOut, /AgntGuard Operational Dashboard/);
    assert.match(statusOut, /antigravity/);
    assert.match(statusOut, /● enabled/);
    assert.match(statusOut, /○ disabled/); // opencode is still disabled
    assert.match(statusOut, /Operating Mode:/);
    assert.match(statusOut, /Gate 2 Path Rules:/);
    assert.match(statusOut, /Gate 3 Regex Rules:/);

    // 3. Disable all agents
    const { stdout: disableOut } = await execFileAsync(
      'node',
      [cliScript, 'disable', '--all'],
      { env }
    );
    assert.match(disableOut, /Disabled AgntGuard hook for antigravity/);
    assert.match(disableOut, /Disabled AgntGuard hook for pi/);

    // 4. Status reflects all disabled
    const { stdout: statusAfterOut } = await execFileAsync('node', [cliScript, 'status'], { env });
    assert.doesNotMatch(statusAfterOut, /● enabled/);
  });
});
