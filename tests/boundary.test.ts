import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

function listFilesRecursive(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listFilesRecursive(full));
    else if (entry.name.endsWith('.ts')) out.push(full);
  }
  return out;
}

describe('architectural boundary invariants', () => {
  const srcRoot = path.resolve('src');
  const coreFiles = listFilesRecursive(path.join(srcRoot, 'core'));

  test('core has no transport primitives', () => {
    const violations: string[] = [];
    for (const file of coreFiles) {
      const content = fs.readFileSync(file, 'utf8');
      for (const token of ['process.exit', 'process.stdin', 'process.stdout', 'process.env']) {
        if (content.includes(token)) violations.push(`${path.relative(srcRoot, file)} contains ${token}`);
      }
    }
    assert.deepEqual(violations, []);
  });

  test('core has no agent names', () => {
    const violations: string[] = [];
    for (const file of coreFiles) {
      const rel = path.relative(srcRoot, file);
      if (rel === path.join('core', 'defaults', 'system-rules.ts')) continue;
      const content = fs.readFileSync(file, 'utf8').toLowerCase();
      for (const name of ['antigravity', 'opencode']) {
        if (content.includes(name)) violations.push(`${rel} mentions ${name}`);
      }
    }
    assert.deepEqual(violations, []);
  });

  test('fallback invariant strings live only in the reason catalog', () => {
    const needle1 = 'restricted by fallback policy';
    const needle2 = 'requires user approval';
    const needle3 = 'permitted by fallback policy';
    const allFiles = listFilesRecursive(srcRoot);
    const holders = new Set<string>();
    for (const file of allFiles) {
      const content = fs.readFileSync(file, 'utf8');
      if (content.includes(needle1) || content.includes(needle2) || content.includes(needle3)) {
        holders.add(path.relative(srcRoot, file));
      }
    }
    assert.deepEqual([...holders].sort(), ['core/engine/reason-catalog.ts']);
  });

  test('no subprocess bridge remains', () => {
    const allFiles = listFilesRecursive(srcRoot);
    const names = allFiles.map((f) => path.relative(srcRoot, f));
    assert.ok(!names.some((n) => n.includes('bridge')), 'bridge.ts must be deleted');
    assert.ok(!names.some((n) => n.startsWith('adapters/')), 'src/adapters/ must be deleted');
    assert.ok(!names.includes('hook.ts'), 'src/hook.ts must be deleted');
    assert.ok(!names.some((n) => n.startsWith('opencode-plugin/')), 'src/opencode-plugin/ must be deleted');
  });
});
