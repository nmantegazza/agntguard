import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { getGlobalConfigDir, getDefaultConfigPath } from '../../config.js';

export function getOpenCodeConfigDir(): string {
  if (process.env.OPENCODE_CONFIG_DIR) {
    return path.resolve(process.env.OPENCODE_CONFIG_DIR);
  }
  const xdg = process.env.XDG_CONFIG_HOME;
  if (xdg && xdg.trim()) {
    return path.join(xdg.trim(), 'opencode');
  }
  return path.join(os.homedir(), '.config', 'opencode');
}

export function getOpenCodeConfigPath(): string {
  if (process.env.OPENCODE_CONFIG_FILE) {
    return path.resolve(process.env.OPENCODE_CONFIG_FILE);
  }
  const baseDir = getOpenCodeConfigDir();
  const jsonc = path.join(baseDir, 'opencode.jsonc');
  if (fs.existsSync(jsonc)) return jsonc;
  const json = path.join(baseDir, 'opencode.json');
  if (fs.existsSync(json)) return json;
  return json;
}

export function getOpenCodeShimDir(): string {
  return path.join(getGlobalConfigDir(), 'adapters', 'opencode');
}

export function isOpenCodeDetected(): boolean {
  if (process.env.OPENCODE_CONFIG_FILE && fs.existsSync(process.env.OPENCODE_CONFIG_FILE)) {
    return true;
  }
  if (process.env.OPENCODE_CONFIG_DIR && fs.existsSync(process.env.OPENCODE_CONFIG_DIR)) {
    return true;
  }
  const baseDir = getOpenCodeConfigDir();
  return fs.existsSync(baseDir);
}

function stripComments(content: string): string {
  return content.replace(/\/\*[\s\S]*?\*\/|([^\\:]|^)\/\/.*$/gm, '$1');
}

function hasComments(content: string): boolean {
  return /\/\*[\s\S]*?\*\/|\/\/.*/.test(content);
}

function readParsedOpenCodeConfig(filePath: string): any {
  if (!fs.existsSync(filePath)) return null;
  const raw = fs.readFileSync(filePath, 'utf8');
  try {
    return JSON.parse(stripComments(raw));
  } catch {
    return null;
  }
}

export function inspectOpenCodeHealth(runtimeDist: string): 'enabled' | 'disabled' | 'broken' {
  const configPath = getOpenCodeConfigPath();
  const parsed = readParsedOpenCodeConfig(configPath);
  const shimDir = getOpenCodeShimDir();

  if (!parsed || !Array.isArray(parsed.plugins)) {
    return 'disabled';
  }

  const isRegistered = parsed.plugins.some((p: any) => {
    if (typeof p === 'string') return p === shimDir;
    return p?.package === shimDir;
  });

  if (!isRegistered) {
    return 'disabled';
  }

  const shimIndex = path.join(shimDir, 'index.js');
  const targetAdapter = path.join(runtimeDist, 'agents', 'opencode-adapter.js');

  if (fs.existsSync(shimIndex) && fs.existsSync(targetAdapter)) {
    return 'enabled';
  }

  return 'broken';
}

export function enableOpenCode(runtimeDist: string): void {
  const shimDir = getOpenCodeShimDir();
  if (!fs.existsSync(shimDir)) {
    fs.mkdirSync(shimDir, { recursive: true });
  }

  const targetAdapter = path.join(runtimeDist, 'agents', 'opencode-adapter.js');
  const targetConfig = getDefaultConfigPath();

  // 1. Create lightweight ESM shim package
  const pkgJson = {
    name: 'agntguard-opencode-shim',
    type: 'module',
    main: './index.js'
  };

  const indexJs = `export { default } from '${targetAdapter}';\nexport * from '${targetAdapter}';\n`;

  fs.writeFileSync(path.join(shimDir, 'package.json'), JSON.stringify(pkgJson, null, 2) + '\n', 'utf8');
  fs.writeFileSync(path.join(shimDir, 'index.js'), indexJs, 'utf8');

  // 2. Register in opencode.json(c)
  const configPath = getOpenCodeConfigPath();
  const configDir = path.dirname(configPath);
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
  }

  const pluginEntry = {
    package: shimDir,
    options: {
      configPath: targetConfig
    }
  };

  if (!fs.existsSync(configPath)) {
    const newConfig = {
      plugins: [pluginEntry]
    };
    fs.writeFileSync(configPath, JSON.stringify(newConfig, null, 2) + '\n', 'utf8');
    return;
  }

  const raw = fs.readFileSync(configPath, 'utf8');
  if (hasComments(raw)) {
    const parsed = readParsedOpenCodeConfig(configPath);
    const alreadyRegistered = parsed?.plugins?.some((p: any) => p?.package === shimDir || p === shimDir);
    if (!alreadyRegistered) {
      console.warn(`Notice: "${configPath}" contains comments. To preserve comments, please manually add AgntGuard to your "plugins" list:`);
      console.warn(JSON.stringify(pluginEntry, null, 2));
    }
    return;
  }

  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch (err: any) {
    throw new Error(`Failed to parse ${configPath}: ${err.message}`);
  }

  if (!parsed || typeof parsed !== 'object') {
    parsed = {};
  }
  if (!Array.isArray(parsed.plugins)) {
    parsed.plugins = [];
  }

  const existingIdx = parsed.plugins.findIndex((p: any) => p?.package === shimDir || p === shimDir);
  if (existingIdx === -1) {
    parsed.plugins.push(pluginEntry);
    fs.writeFileSync(configPath, JSON.stringify(parsed, null, 2) + '\n', 'utf8');
  }
}

export function disableOpenCode(): void {
  const shimDir = getOpenCodeShimDir();
  if (fs.existsSync(shimDir)) {
    fs.rmSync(shimDir, { recursive: true, force: true });
  }

  const configPath = getOpenCodeConfigPath();
  if (!fs.existsSync(configPath)) return;

  const raw = fs.readFileSync(configPath, 'utf8');
  if (hasComments(raw)) {
    console.warn(`Notice: "${configPath}" contains comments. To disable AgntGuard, remove the entry referencing "${shimDir}" from your plugins array.`);
    return;
  }

  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed.plugins)) {
      parsed.plugins = parsed.plugins.filter((p: any) => p?.package !== shimDir && p !== shimDir);
      fs.writeFileSync(configPath, JSON.stringify(parsed, null, 2) + '\n', 'utf8');
    }
  } catch {
    // If invalid JSON, ignore
  }
}
