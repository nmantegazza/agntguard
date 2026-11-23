import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export function getPiConfigDir(): string {
  if (process.env.PI_DIR) {
    return path.resolve(process.env.PI_DIR);
  }
  return path.join(os.homedir(), '.pi');
}

export function getPiExtensionDir(): string {
  if (process.env.PI_EXTENSION_DIR) {
    return path.resolve(process.env.PI_EXTENSION_DIR);
  }
  return path.join(getPiConfigDir(), 'agent', 'extensions', 'agntguard');
}

export function isPiDetected(): boolean {
  if (process.env.PI_EXTENSION_DIR && fs.existsSync(process.env.PI_EXTENSION_DIR)) {
    return true;
  }
  const baseDir = getPiConfigDir();
  return fs.existsSync(baseDir);
}

export function inspectPiHealth(runtimeDist: string): 'enabled' | 'disabled' | 'broken' {
  const extDir = getPiExtensionDir();
  const indexJs = path.join(extDir, 'index.js');

  if (!fs.existsSync(indexJs)) {
    return 'disabled';
  }

  const targetAdapter = path.join(runtimeDist, 'agents', 'pi-adapter.js');
  if (fs.existsSync(targetAdapter)) {
    return 'enabled';
  }

  return 'broken';
}

export function enablePi(runtimeDist: string): void {
  const extDir = getPiExtensionDir();
  if (!fs.existsSync(extDir)) {
    fs.mkdirSync(extDir, { recursive: true });
  }

  const targetAdapter = path.join(runtimeDist, 'agents', 'pi-adapter.js');

  const pkgJson = {
    name: 'agntguard-pi-extension',
    type: 'module',
    main: './index.js'
  };

  const indexJs = `export { default } from '${targetAdapter}';\n`;

  fs.writeFileSync(path.join(extDir, 'package.json'), JSON.stringify(pkgJson, null, 2) + '\n', 'utf8');
  fs.writeFileSync(path.join(extDir, 'index.js'), indexJs, 'utf8');
}

export function disablePi(): void {
  const extDir = getPiExtensionDir();
  if (fs.existsSync(extDir)) {
    fs.rmSync(extDir, { recursive: true, force: true });
  }
}
