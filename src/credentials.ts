import fs from 'node:fs';
import path from 'node:path';
import { getGlobalConfigDir } from './config.js';

export function getHookRoot(): string {
  return path.resolve(import.meta.dirname, '..');
}

export function getGlobalCredentialsPath(): string {
  return path.join(getGlobalConfigDir(), 'credentials.json');
}

export function getDefaultCredentialsPath(): string {
  if (process.env.AGNTGUARD_CREDENTIALS) {
    return path.resolve(process.env.AGNTGUARD_CREDENTIALS);
  }

  const globalPath = getGlobalCredentialsPath();
  if (fs.existsSync(globalPath)) {
    return globalPath;
  }

  return path.join(getHookRoot(), 'credentials.json');
}

export function loadApiKey(customPath?: string): string | null {
  const credPath = customPath || getDefaultCredentialsPath();
  if (!fs.existsSync(credPath)) {
    return null;
  }

  try {
    const content = fs.readFileSync(credPath, 'utf8').trim();
    if (!content) {
      return null;
    }

    const parsed = JSON.parse(content);
    const key = parsed?.apiKey ?? parsed?.TYPESAFE_API_KEY;
    if (typeof key === 'string' && key.trim()) {
      return key.trim();
    }
  } catch {
    return null;
  }

  return null;
}

export function saveApiKey(key: string, customPath?: string): string {
  const cleanKey = key.trim();
  if (!cleanKey) {
    throw new Error('API key cannot be empty');
  }

  const credPath = customPath
    ? path.resolve(customPath)
    : (process.env.AGNTGUARD_CREDENTIALS
        ? path.resolve(process.env.AGNTGUARD_CREDENTIALS)
        : getGlobalCredentialsPath());
  const dirPath = path.dirname(credPath);

  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }

  const content = JSON.stringify({ apiKey: cleanKey }, null, 2) + '\n';
  fs.writeFileSync(credPath, content, { encoding: 'utf8', mode: 0o600 });
  try {
    fs.chmodSync(credPath, 0o600);
  } catch {
    // Ignore if chmod fails (e.g., on Windows)
  }

  return credPath;
}
