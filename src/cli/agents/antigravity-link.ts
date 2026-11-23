import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export function getAntigravityConfigDir(): string {
  if (process.env.ANTIGRAVITY_CONFIG_DIR) {
    return path.resolve(process.env.ANTIGRAVITY_CONFIG_DIR);
  }
  return path.join(os.homedir(), '.gemini', 'config');
}

export function getAntigravityPluginDir(): string {
  return path.join(getAntigravityConfigDir(), 'plugins', 'agntguard');
}

export function isAntigravityDetected(): boolean {
  if (process.env.ANTIGRAVITY_CONFIG_DIR) {
    return fs.existsSync(process.env.ANTIGRAVITY_CONFIG_DIR);
  }
  return fs.existsSync(path.join(os.homedir(), '.gemini'));
}

export function inspectAntigravityHealth(runtimeDist: string): 'enabled' | 'disabled' | 'broken' {
  const pluginDir = getAntigravityPluginDir();
  const hooksPath = path.join(pluginDir, 'hooks.json');

  if (!fs.existsSync(hooksPath)) {
    return 'disabled';
  }

  try {
    const raw = fs.readFileSync(hooksPath, 'utf8');
    const parsed = JSON.parse(raw);
    const cmd = parsed?.agntguard?.PreToolUse?.[0]?.hooks?.[0]?.command;
    if (typeof cmd === 'string') {
      const match = cmd.match(/^node\s+(.*)$/);
      const targetScript = match ? match[1].trim() : null;
      if (targetScript && fs.existsSync(targetScript)) {
        return 'enabled';
      }
    }
  } catch {
    return 'broken';
  }

  // Also verify expected adapter in runtimeDist exists
  const expectedAdapter = path.join(runtimeDist, 'agents', 'antigravity-adapter.js');
  if (fs.existsSync(expectedAdapter)) {
    return 'enabled';
  }

  return 'broken';
}

export function enableAntigravity(runtimeDist: string): void {
  const pluginDir = getAntigravityPluginDir();
  if (!fs.existsSync(pluginDir)) {
    fs.mkdirSync(pluginDir, { recursive: true });
  }

  const adapterPath = path.join(runtimeDist, 'agents', 'antigravity-adapter.js');

  const pluginManifest = {
    name: 'agntguard'
  };

  const hooksConfig = {
    agntguard: {
      PreToolUse: [
        {
          matcher: '*',
          hooks: [
            {
              type: 'command',
              command: `node ${adapterPath}`,
              timeout: 30
            }
          ]
        }
      ]
    }
  };

  fs.writeFileSync(path.join(pluginDir, 'plugin.json'), JSON.stringify(pluginManifest, null, 2) + '\n', 'utf8');
  fs.writeFileSync(path.join(pluginDir, 'hooks.json'), JSON.stringify(hooksConfig, null, 2) + '\n', 'utf8');
}

export function disableAntigravity(): void {
  const pluginDir = getAntigravityPluginDir();
  if (fs.existsSync(pluginDir)) {
    fs.rmSync(pluginDir, { recursive: true, force: true });
  }
}
