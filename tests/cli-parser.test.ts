import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseCliArgs } from '../dist/cli/parser.js';
import { renderRail, badgeHealth, badgeVerdict, badgeScope, isColorEnabled } from '../dist/cli/theme.js';

describe('CLI Argument Parser & Theme', () => {
  describe('parseCliArgs', () => {
    test('parses empty args as help command', () => {
      const parsed = parseCliArgs([]);
      assert.equal(parsed.resource, 'help');
      assert.deepEqual(parsed.positional, []);
      assert.deepEqual(parsed.flags, {});
    });

    test('parses help flag with no resource as help', () => {
      const parsed = parseCliArgs(['--help']);
      assert.equal(parsed.resource, 'help');
      assert.equal(parsed.flags.help, true);

      const parsedShort = parseCliArgs(['-h']);
      assert.equal(parsedShort.resource, 'help');
      assert.equal(parsedShort.flags.help, true);
      assert.equal(parsedShort.flags.h, true);
    });

    test('parses single verb commands (init, status)', () => {
      const init = parseCliArgs(['init']);
      assert.equal(init.resource, 'init');
      assert.equal(init.subcommand, undefined);
      assert.deepEqual(init.positional, []);

      const status = parseCliArgs(['status']);
      assert.equal(status.resource, 'status');
      assert.equal(status.subcommand, undefined);
      assert.deepEqual(status.positional, []);
    });

    test('parses enable and disable with agent positionals or flags', () => {
      const enable = parseCliArgs(['enable', 'antigravity', 'pi']);
      assert.equal(enable.resource, 'enable');
      assert.equal(enable.subcommand, undefined);
      assert.deepEqual(enable.positional, ['antigravity', 'pi']);

      const enableAll = parseCliArgs(['enable', '--all']);
      assert.equal(enableAll.resource, 'enable');
      assert.equal(enableAll.flags.all, true);
      assert.deepEqual(enableAll.positional, []);

      const disable = parseCliArgs(['disable', 'opencode']);
      assert.equal(disable.resource, 'disable');
      assert.deepEqual(disable.positional, ['opencode']);
    });

    test('parses grouped subcommands and flags (rule, path, config, key)', () => {
      const ruleList = parseCliArgs(['rule', 'list', '--tool', 'execute_command', '--system']);
      assert.equal(ruleList.resource, 'rule');
      assert.equal(ruleList.subcommand, 'list');
      assert.equal(ruleList.flags.tool, 'execute_command');
      assert.equal(ruleList.flags.system, true);

      const ruleAdd = parseCliArgs([
        'rule',
        'add',
        '--list',
        'restrict',
        '--pattern',
        '^curl\\s',
        '--dimension',
        'external'
      ]);
      assert.equal(ruleAdd.resource, 'rule');
      assert.equal(ruleAdd.subcommand, 'add');
      assert.equal(ruleAdd.flags.list, 'restrict');
      assert.equal(ruleAdd.flags.pattern, '^curl\\s');
      assert.equal(ruleAdd.flags.dimension, 'external');

      const pathAdd = parseCliArgs(['path', 'add', '--list', 'no_access', '--pattern', '/etc/shadow']);
      assert.equal(pathAdd.resource, 'path');
      assert.equal(pathAdd.subcommand, 'add');
      assert.equal(pathAdd.flags.list, 'no_access');
      assert.equal(pathAdd.flags.pattern, '/etc/shadow');

      const configSet = parseCliArgs(['config', 'set', 'mode', 'ask']);
      assert.equal(configSet.resource, 'config');
      assert.equal(configSet.subcommand, 'set');
      assert.deepEqual(configSet.positional, ['mode', 'ask']);

      const configReset = parseCliArgs(['config', 'reset', '--yes']);
      assert.equal(configReset.resource, 'config');
      assert.equal(configReset.subcommand, 'reset');
      assert.equal(configReset.flags.yes, true);

      const keySet = parseCliArgs(['key', 'set', 'test-key-123']);
      assert.equal(keySet.resource, 'key');
      assert.equal(keySet.subcommand, 'set');
      assert.deepEqual(keySet.positional, ['test-key-123']);
    });

    test('handles boolean flags with explicit true/false or inline equals', () => {
      const parsedTrue = parseCliArgs(['config', 'set', '--system=true', '--tool=read_file']);
      assert.equal(parsedTrue.flags.system, true);
      assert.equal(parsedTrue.flags.tool, 'read_file');

      const parsedFalse = parseCliArgs(['rule', 'list', '--system=false']);
      assert.equal(parsedFalse.flags.system, false);
    });

    test('parses help with target command', () => {
      const helpRule = parseCliArgs(['help', 'rule']);
      assert.equal(helpRule.resource, 'help');
      assert.deepEqual(helpRule.positional, ['rule']);

      const ruleHelp = parseCliArgs(['rule', '--help']);
      assert.equal(ruleHelp.resource, 'rule');
      assert.equal(ruleHelp.flags.help, true);
    });
  });

  describe('theme visual primitives & NO_COLOR fallback', () => {
    test('renders rail with title and lines', () => {
      const output = renderRail('Test Title', ['Line 1', 'Line 2']);
      assert.match(output, /Test Title/);
      assert.match(output, /Line 1/);
      assert.match(output, /Line 2/);
      assert.match(output, /┌/);
      assert.match(output, /│/);
      assert.match(output, /└/);
    });

    test('produces badges for health, verdict, and scope', () => {
      assert.match(badgeHealth('enabled'), /● enabled/);
      assert.match(badgeHealth('disabled'), /○ disabled/);
      assert.match(badgeHealth('broken'), /⚠ broken/);
      assert.match(badgeHealth('missing key'), /⚠ missing key/);

      assert.match(badgeVerdict('allow'), /● allow/);
      assert.match(badgeVerdict('restrict'), /■ restrict/);

      assert.match(badgeScope('user'), /\[User\]/);
      assert.match(badgeScope('system'), /\[System\]/);
    });

    test('respects NO_COLOR=1 environment variable', () => {
      const originalNoColor = process.env.NO_COLOR;
      try {
        process.env.NO_COLOR = '1';
        assert.equal(isColorEnabled(), false);

        const health = badgeHealth('enabled');
        // Must contain no ANSI escape sequences (\x1b[)
        assert.doesNotMatch(health, /\x1b\[/);
        assert.equal(health, '● enabled');

        const rail = renderRail('Box', ['Content']);
        assert.doesNotMatch(rail, /\x1b\[/);
      } finally {
        if (originalNoColor === undefined) {
          delete process.env.NO_COLOR;
        } else {
          process.env.NO_COLOR = originalNoColor;
        }
      }
    });
  });
});
