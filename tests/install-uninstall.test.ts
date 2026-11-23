import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const REPO_ROOT = process.cwd();
const INSTALL_SCRIPT = path.join(REPO_ROOT, 'install.sh');
const UNINSTALL_SCRIPT = path.join(REPO_ROOT, 'uninstall.sh');

describe('install.sh and uninstall.sh lifecycle', () => {
  let tmpBase: string;
  let agntguardDir: string;
  let binDir: string;

  beforeEach(() => {
    tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'agntguard-lifecycle-test-'));
    agntguardDir = path.join(tmpBase, '.agntguard');
    binDir = path.join(tmpBase, 'bin');
  });

  afterEach(() => {
    fs.rmSync(tmpBase, { recursive: true, force: true });
  });

  test('install.sh --help exits 0 and unknown flags exit 1', async () => {
    const { stdout } = await execFileAsync('bash', [INSTALL_SCRIPT, '--help']);
    assert.match(stdout, /Usage: \.\/install\.sh/);
    assert.match(stdout, /AGNTGUARD_DIR/);

    await assert.rejects(
      () => execFileAsync('bash', [INSTALL_SCRIPT, '--agent', 'pi']),
      (err: any) => err.code === 1 && /Unknown option/.test(err.stderr)
    );
  });

  test('install.sh fails on unsupported OS and Node < 20', async () => {
    const mockBin = path.join(tmpBase, 'mock-bin');
    fs.mkdirSync(mockBin, { recursive: true });

    // Mock uname returning MINGW64_NT-10.0
    const mockUname = path.join(mockBin, 'uname');
    fs.writeFileSync(mockUname, '#!/usr/bin/env bash\necho "MINGW64_NT-10.0"\n', { mode: 0o755 });

    await assert.rejects(
      () =>
        execFileAsync('bash', [INSTALL_SCRIPT], {
          env: { ...process.env, PATH: `${mockBin}:${process.env.PATH}`, NO_COLOR: '1' }
        }),
      (err: any) => err.code === 1 && /not supported/i.test(err.stderr)
    );

    fs.rmSync(mockUname);

    // Mock node returning v18.19.0
    const mockNode = path.join(mockBin, 'node');
    fs.writeFileSync(mockNode, '#!/usr/bin/env bash\necho "v18.19.0"\n', { mode: 0o755 });

    await assert.rejects(
      () =>
        execFileAsync('bash', [INSTALL_SCRIPT], {
          env: { ...process.env, PATH: `${mockBin}:${process.env.PATH}`, NO_COLOR: '1' }
        }),
      (err: any) => err.code === 1 && /Node\.js >= 20 is required/.test(err.stderr)
    );
  });

  test('install.sh installs runtime, prod dependencies, launcher, and symlink without creating config.json', async () => {
    const env = {
      ...process.env,
      AGNTGUARD_DIR: agntguardDir,
      AGNTGUARD_BIN_DIR: binDir,
      NO_COLOR: '1'
    };

    const { stdout } = await execFileAsync('bash', [INSTALL_SCRIPT], { env });
    assert.match(stdout, /agntguard init/);
    assert.match(stdout, /export PATH=/);

    assert.ok(fs.existsSync(path.join(agntguardDir, 'runtime', 'dist', 'cli.js')));
    assert.ok(fs.existsSync(path.join(agntguardDir, 'runtime', 'package.json')));
    assert.ok(fs.existsSync(path.join(agntguardDir, 'runtime', 'node_modules')));
    assert.ok(fs.existsSync(path.join(agntguardDir, 'bin', 'agntguard')));
    assert.ok(!fs.existsSync(path.join(agntguardDir, 'config.json')), 'Must not pre-seed config.json');

    const symlinkPath = path.join(binDir, 'agntguard');
    assert.ok(fs.lstatSync(symlinkPath).isSymbolicLink());

    const { stdout: cliHelp } = await execFileAsync(symlinkPath, ['--help'], { env });
    assert.match(cliHelp, /agntguard/);
  });

  test('install.sh builds automatically when dist/cli.js is missing in local checkout', async () => {
    const tmpCheckout = path.join(tmpBase, 'checkout');
    fs.mkdirSync(tmpCheckout, { recursive: true });
    fs.cpSync(path.join(REPO_ROOT, 'src'), path.join(tmpCheckout, 'src'), { recursive: true });
    fs.copyFileSync(path.join(REPO_ROOT, 'package.json'), path.join(tmpCheckout, 'package.json'));
    fs.copyFileSync(path.join(REPO_ROOT, 'package-lock.json'), path.join(tmpCheckout, 'package-lock.json'));
    fs.copyFileSync(path.join(REPO_ROOT, 'tsconfig.json'), path.join(tmpCheckout, 'tsconfig.json'));
    fs.copyFileSync(INSTALL_SCRIPT, path.join(tmpCheckout, 'install.sh'));
    fs.symlinkSync(path.join(REPO_ROOT, 'node_modules'), path.join(tmpCheckout, 'node_modules'));

    const env = {
      ...process.env,
      AGNTGUARD_DIR: agntguardDir,
      AGNTGUARD_BIN_DIR: binDir,
      NO_COLOR: '1'
    };

    const { stdout } = await execFileAsync('bash', [path.join(tmpCheckout, 'install.sh')], { env });
    assert.match(stdout, /Building runtime from source/);
    assert.ok(fs.existsSync(path.join(tmpCheckout, 'dist', 'cli.js')));
    assert.ok(fs.existsSync(path.join(agntguardDir, 'runtime', 'dist', 'cli.js')));
  });

  test('uninstall.sh --help exits 0 and unknown flags exit 1', async () => {
    const { stdout } = await execFileAsync('bash', [UNINSTALL_SCRIPT, '--help']);
    assert.match(stdout, /Usage: \.\/uninstall\.sh/);
    assert.match(stdout, /--keep-config/);

    await assert.rejects(
      () => execFileAsync('bash', [UNINSTALL_SCRIPT, '--purge']),
      (err: any) => err.code === 1 && /Unknown option/.test(err.stderr)
    );
  });

  test('uninstall.sh performs full teardown and detaches all agent hooks', async () => {
    const antigravityDir = path.join(tmpBase, 'antigravity');
    const piExtDir = path.join(tmpBase, 'pi-ext');
    const opencodeDir = path.join(tmpBase, 'opencode');
    const env = {
      ...process.env,
      AGNTGUARD_DIR: agntguardDir,
      AGNTGUARD_BIN_DIR: binDir,
      ANTIGRAVITY_CONFIG_DIR: antigravityDir,
      PI_EXTENSION_DIR: piExtDir,
      OPENCODE_CONFIG_DIR: opencodeDir,
      NO_COLOR: '1'
    };

    await execFileAsync('bash', [INSTALL_SCRIPT], { env });

    // Create mock agent hooks & OpenCode config
    const agPluginDir = path.join(antigravityDir, 'plugins', 'agntguard');
    fs.mkdirSync(agPluginDir, { recursive: true });
    fs.writeFileSync(path.join(agPluginDir, 'hooks.json'), '{}');

    fs.mkdirSync(piExtDir, { recursive: true });
    fs.writeFileSync(path.join(piExtDir, 'index.js'), '');

    const ocShimDir = path.join(agntguardDir, 'adapters', 'opencode');
    fs.mkdirSync(ocShimDir, { recursive: true });
    fs.mkdirSync(opencodeDir, { recursive: true });
    const ocConfigPath = path.join(opencodeDir, 'opencode.json');
    fs.writeFileSync(
      ocConfigPath,
      JSON.stringify({ plugins: [{ package: ocShimDir }, 'other-plugin'] }, null, 2)
    );

    const { stdout } = await execFileAsync('bash', [UNINSTALL_SCRIPT], { env });
    assert.match(stdout, /AgntGuard uninstalled/);

    assert.ok(!fs.existsSync(agntguardDir));
    assert.ok(!fs.existsSync(path.join(binDir, 'agntguard')));
    assert.ok(!fs.existsSync(agPluginDir));
    assert.ok(!fs.existsSync(piExtDir));

    const updatedOc = JSON.parse(fs.readFileSync(ocConfigPath, 'utf8'));
    assert.deepEqual(updatedOc.plugins, ['other-plugin']);
  });

  test('uninstall.sh --keep-config preserves config.json, credentials.json, and logs/', async () => {
    const env = {
      ...process.env,
      AGNTGUARD_DIR: agntguardDir,
      AGNTGUARD_BIN_DIR: binDir,
      NO_COLOR: '1'
    };

    await execFileAsync('bash', [INSTALL_SCRIPT], { env });

    fs.writeFileSync(path.join(agntguardDir, 'config.json'), '{"mode":"ask"}\n');
    fs.writeFileSync(path.join(agntguardDir, 'credentials.json'), '{"apiKey":"test"}\n');
    fs.mkdirSync(path.join(agntguardDir, 'logs'), { recursive: true });
    fs.writeFileSync(path.join(agntguardDir, 'logs', 'decisions.jsonl'), '{}\n');

    await execFileAsync('bash', [UNINSTALL_SCRIPT, '--keep-config'], { env });

    assert.ok(!fs.existsSync(path.join(agntguardDir, 'runtime')));
    assert.ok(!fs.existsSync(path.join(agntguardDir, 'bin')));
    assert.ok(!fs.existsSync(path.join(binDir, 'agntguard')));

    assert.ok(fs.existsSync(path.join(agntguardDir, 'config.json')));
    assert.ok(fs.existsSync(path.join(agntguardDir, 'credentials.json')));
    assert.ok(fs.existsSync(path.join(agntguardDir, 'logs', 'decisions.jsonl')));
  });

  test('uninstall.sh defensive fallback detaches hooks even when runtime CLI is missing', async () => {
    const antigravityDir = path.join(tmpBase, 'antigravity');
    const piExtDir = path.join(tmpBase, 'pi-ext');
    const opencodeDir = path.join(tmpBase, 'opencode');
    const env = {
      ...process.env,
      AGNTGUARD_DIR: agntguardDir,
      AGNTGUARD_BIN_DIR: binDir,
      ANTIGRAVITY_CONFIG_DIR: antigravityDir,
      PI_EXTENSION_DIR: piExtDir,
      OPENCODE_CONFIG_DIR: opencodeDir,
      NO_COLOR: '1'
    };

    await execFileAsync('bash', [INSTALL_SCRIPT], { env });
    fs.rmSync(path.join(agntguardDir, 'runtime', 'dist', 'cli.js'));

    const agPluginDir = path.join(antigravityDir, 'plugins', 'agntguard');
    fs.mkdirSync(agPluginDir, { recursive: true });
    fs.mkdirSync(piExtDir, { recursive: true });

    const ocShimDir = path.join(agntguardDir, 'adapters', 'opencode');
    fs.mkdirSync(ocShimDir, { recursive: true });
    fs.mkdirSync(opencodeDir, { recursive: true });
    const ocConfigPath = path.join(opencodeDir, 'opencode.json');
    fs.writeFileSync(ocConfigPath, JSON.stringify({ plugins: [ocShimDir] }, null, 2));

    await execFileAsync('bash', [UNINSTALL_SCRIPT], { env });

    assert.ok(!fs.existsSync(agntguardDir));
    assert.ok(!fs.existsSync(agPluginDir));
    assert.ok(!fs.existsSync(piExtDir));
    const updatedOc = JSON.parse(fs.readFileSync(ocConfigPath, 'utf8'));
    assert.deepEqual(updatedOc.plugins, []);
  });
});
