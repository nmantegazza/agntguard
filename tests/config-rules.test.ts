import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { RulesConfig } from '../src/types.js';
import {
  SYSTEM_RESTRICT_RULES,
  SYSTEM_ALLOW_RULES,
  SYSTEM_PATHS,
  PROTECTED_PATHS,
  PURE_READ_ALLOW_RULES,
  SAFE_MUTATION_ALLOW_RULES
} from '../dist/core/defaults/system-rules.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const configPath = path.join(here, '..', 'config.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const rules: RulesConfig = config.rules;

describe('shipped policy configuration', () => {
  test('every configured regex compiles (rules fail open on bad patterns)', () => {
    let checked = 0;
    const allRules = [
      ...SYSTEM_RESTRICT_RULES,
      ...SYSTEM_ALLOW_RULES,
      ...(rules.restrict || []),
      ...(rules.allow || [])
    ];
    for (const rule of allRules) {
      assert.doesNotThrow(
        () => new RegExp(rule.pattern),
        `${rule.tool} does not compile: ${rule.pattern}`
      );
      checked += 1;
    }
    assert.ok(checked > 0, 'expected to check at least one rule');
  });

  test('SYSTEM_PATHS (and PROTECTED_PATHS alias) compile cleanly standalone and with Gate 2 boundary wrappers', () => {
    assert.deepEqual(PROTECTED_PATHS, SYSTEM_PATHS);
    const allPaths = [...SYSTEM_PATHS.noAccess, ...SYSTEM_PATHS.readOnly, ...SYSTEM_PATHS.allowed];
    assert.ok(SYSTEM_PATHS.noAccess.length > 0);
    assert.ok(SYSTEM_PATHS.readOnly.length > 0);
    assert.ok(SYSTEM_PATHS.allowed.length > 0);

    for (const p of allPaths) {
      assert.doesNotThrow(() => new RegExp(p), `System path does not compile: ${p}`);
      assert.doesNotThrow(
        () => new RegExp(`^(?:\\S*/)?(?:${p})$`),
        `AST token path wrapper failed to compile: ${p}`
      );
      assert.doesNotThrow(
        () => new RegExp(`(?:^|/)(?:${p})$`),
        `Path boundary wrapper failed to compile: ${p}`
      );
    }
  });

  test('config.json includes default paths configuration', () => {
    assert.deepEqual(config.paths, {
      outside_read: 'allow',
      outside_write: 'restrict',
      no_access: [],
      read_only: [],
      allowed: []
    });
  });

  test('SYSTEM_ALLOW_RULES equals [...PURE_READ_ALLOW_RULES, ...SAFE_MUTATION_ALLOW_RULES]', () => {
    assert.deepEqual(SYSTEM_ALLOW_RULES, [
      ...PURE_READ_ALLOW_RULES,
      ...SAFE_MUTATION_ALLOW_RULES
    ]);
  });

  test('SYSTEM_RESTRICT_RULES contains zero read_file rules and only behavioral rules', () => {
    const readFileRules = SYSTEM_RESTRICT_RULES.filter(r => r.tool === 'read_file');
    assert.equal(readFileRules.length, 0, 'SYSTEM_RESTRICT_RULES must not contain read_file rules');

    const writeFileRules = SYSTEM_RESTRICT_RULES.filter(r => r.tool === 'write_file');
    assert.equal(writeFileRules.length, 0, 'SYSTEM_RESTRICT_RULES must not contain write_file rules');
  });

  test('config.json tier2 does not contain thresholds', () => {
    assert.equal(config.tier2.thresholds, undefined);
  });

  test('SYSTEM_RESTRICT_RULES dimensions belong to harmful, sensitive, opaque, or external', () => {
    const validDimensions = new Set(['harmful', 'sensitive', 'opaque', 'external']);
    for (const rule of SYSTEM_RESTRICT_RULES) {
      if (rule.dimension) {
        assert.ok(
          validDimensions.has(rule.dimension),
          `Rule ${rule.pattern} has invalid dimension: ${rule.dimension}`
        );
      }
    }
  });
});
