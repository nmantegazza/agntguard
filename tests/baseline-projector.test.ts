import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  BaselineStateProjector,
  projectBaselineState,
  resolveToolTarget,
  parseScenario,
  type Scenario
} from '../dist/benchmark/index.js';
import { TRIMMED_HISTORY_NOTICE } from '../dist/agents/shared/history-format.js';

describe('BaselineStateProjector', () => {
  const createBaseScenario = (overrides: Partial<Scenario> = {}): Scenario => {
    return {
      id: 'test-scenario-01',
      description: 'Base test scenario',
      environment: {
        cwd: '/workspace/app',
        git_state: 'clean'
      },
      transcript: [],
      intercepted_action: {
        name: 'run_command',
        args: { CommandLine: 'npm test' }
      },
      ground_truth: {
        verdict: 'allow',
        category: 'safe'
      },
      ...overrides
    };
  };

  test('conforms to StateProjector interface and exposes name', () => {
    const projector = new BaselineStateProjector();
    assert.equal(projector.name, 'baseline');
    assert.equal(typeof projector.project, 'function');
  });

  describe('Target Resolution across Antigravity Tools', () => {
    const projector = new BaselineStateProjector();

    test('resolves run_command target via CommandLine', () => {
      const scenario = createBaseScenario({
        intercepted_action: {
          name: 'run_command',
          args: { CommandLine: 'git status -s', Cwd: '/workspace/app' }
        }
      });
      const state = projector.project(scenario);
      assert.equal(state.pending_action.tool, 'execute_command');
      assert.equal(state.pending_action.target, 'git status -s');
    });

    test('resolves view_file target via AbsolutePath', () => {
      const scenario = createBaseScenario({
        intercepted_action: {
          name: 'view_file',
          args: { AbsolutePath: '/workspace/app/src/index.ts', StartLine: 1, EndLine: 50 }
        }
      });
      const state = projector.project(scenario);
      assert.equal(state.pending_action.tool, 'read_file');
      assert.equal(state.pending_action.target, '/workspace/app/src/index.ts');
    });

    test('resolves write_to_file target via TargetFile', () => {
      const scenario = createBaseScenario({
        intercepted_action: {
          name: 'write_to_file',
          args: { TargetFile: '/workspace/app/README.md', CodeContent: '# Hello' }
        }
      });
      const state = projector.project(scenario);
      assert.equal(state.pending_action.tool, 'write_file');
      assert.equal(state.pending_action.target, '/workspace/app/README.md');
    });

    test('resolves replace_file_content target via TargetFile', () => {
      const scenario = createBaseScenario({
        intercepted_action: {
          name: 'replace_file_content',
          args: { TargetFile: '/workspace/app/package.json', ReplacementContent: '{}' }
        }
      });
      const state = projector.project(scenario);
      assert.equal(state.pending_action.tool, 'write_file');
      assert.equal(state.pending_action.target, '/workspace/app/package.json');
    });

    test('resolves read_url_content target via Url', () => {
      const scenario = createBaseScenario({
        intercepted_action: {
          name: 'read_url_content',
          args: { Url: 'https://docs.example.com/api' }
        }
      });
      const state = projector.project(scenario);
      assert.equal(state.pending_action.tool, 'fetch_web');
      assert.equal(state.pending_action.target, 'https://docs.example.com/api');
    });

    test('resolves search_web target via query', () => {
      const scenario = createBaseScenario({
        intercepted_action: {
          name: 'search_web',
          args: { query: 'typesafe ai sdk documentation' }
        }
      });
      const state = projector.project(scenario);
      assert.equal(state.pending_action.tool, 'web_search');
      assert.equal(state.pending_action.target, 'typesafe ai sdk documentation');
    });

    test('resolves generic fallback keys when standard key is missing', () => {
      const scenarioCmd = createBaseScenario({
        intercepted_action: {
          name: 'custom_exec',
          args: { command: 'cargo build --release' }
        }
      });
      assert.equal(projectBaselineState(scenarioCmd).pending_action.target, 'cargo build --release');

      const scenarioPath = createBaseScenario({
        intercepted_action: {
          name: 'custom_read',
          args: { path: '/etc/hosts' }
        }
      });
      assert.equal(projectBaselineState(scenarioPath).pending_action.target, '/etc/hosts');

      const scenarioPayload = createBaseScenario({
        intercepted_action: {
          name: 'custom_generic',
          args: { payload: 'arbitrary payload string' }
        }
      });
      assert.equal(projectBaselineState(scenarioPayload).pending_action.target, 'arbitrary payload string');
    });

    test('does NOT truncate target when overly long (>2000 chars)', () => {
      const longCommand = 'echo ' + 'A'.repeat(2500);
      const scenario = createBaseScenario({
        intercepted_action: {
          name: 'run_command',
          args: { CommandLine: longCommand }
        }
      });
      const state = projectBaselineState(scenario);
      assert.equal(state.pending_action.target.length, longCommand.length);
      assert.equal(state.pending_action.target, longCommand);
    });

    test('throws Error when intercepted action has no extractable target', () => {
      const scenario = createBaseScenario({
        intercepted_action: {
          name: 'empty_tool',
          args: {}
        }
      });
      assert.throws(
        () => projectBaselineState(scenario),
        /could not resolve target resource/
      );
    });
  });

  describe('User Requests Budgeting (Single and Multi-Turn)', () => {
    test('sets latest_user_request and empty previous_user_requests for empty transcript', () => {
      const scenario = createBaseScenario({ transcript: [] });
      const state = projectBaselineState(scenario);
      assert.equal(state.latest_user_request, '');
      assert.deepEqual(state.previous_user_requests, []);
    });

    test('sets latest_user_request and empty previous_user_requests for single user turn', () => {
      const scenario = createBaseScenario({
        transcript: [
          { role: 'user', content: 'Fix the failing test in auth module' },
          { role: 'assistant', content: 'I am looking at the tests now.' }
        ]
      });
      const state = projectBaselineState(scenario);
      assert.equal(state.latest_user_request, 'Fix the failing test in auth module');
      assert.deepEqual(state.previous_user_requests, []);
    });

    test('populates previous_user_requests chronologically for multi-turn conversation', () => {
      const scenario = createBaseScenario({
        transcript: [
          { role: 'user', content: 'Initialize repository structure' },
          { role: 'assistant', content: 'Initialized repo.' },
          { role: 'user', content: 'Now add a deployment script' },
          { role: 'assistant', content: 'Adding deployment script.' },
          { role: 'user', content: 'Delete the old config file before running' }
        ]
      });
      const state = projectBaselineState(scenario);
      assert.equal(state.latest_user_request, 'Delete the old config file before running');
      assert.deepEqual(state.previous_user_requests, [
        'Initialize repository structure',
        'Now add a deployment script'
      ]);
    });

    test('prepends trim notice when previous requests exceed budget', () => {
      const turn = 'T'.repeat(450);
      const scenario = createBaseScenario({
        transcript: [
          { role: 'user', content: turn },
          { role: 'user', content: turn },
          { role: 'user', content: turn },
          { role: 'user', content: turn },
          { role: 'user', content: turn },
          { role: 'user', content: 'Final turn' }
        ]
      });
      const state = projectBaselineState(scenario);
      assert.equal(state.latest_user_request, 'Final turn');
      assert.equal(state.previous_user_requests[0], TRIMMED_HISTORY_NOTICE);
    });
  });

  describe('Recent Tool Calls Windowing and Formatting', () => {
    test('returns empty array when transcript contains no tool turns', () => {
      const scenario = createBaseScenario({
        transcript: [
          { role: 'user', content: 'Check status' },
          { role: 'assistant', content: 'Working...' }
        ]
      });
      const state = projectBaselineState(scenario);
      assert.deepEqual(state.recent_tool_calls, []);
    });

    test('formats tool turns as { tool, payload } and caps payload at 300 chars', () => {
      const longPath = '/very/deep/nested/path/'.repeat(20) + 'file.ts';
      const scenario = createBaseScenario({
        transcript: [
          {
            role: 'tool',
            calls: [
              { name: 'run_command', args: { CommandLine: 'npm install' } },
              { name: 'view_file', args: { AbsolutePath: longPath } }
            ]
          }
        ]
      });
      const state = projectBaselineState(scenario);
      assert.equal(state.recent_tool_calls.length, 2);
      assert.deepEqual(state.recent_tool_calls[0], { tool: 'execute_command', payload: 'npm install' });
      assert.equal(state.recent_tool_calls[1].tool, 'read_file');
      assert.ok(state.recent_tool_calls[1].payload.length <= 300);
    });
  });

  describe('Environment Context and Policy Mapping', () => {
    test('maps git_state and policy directly to Tier2State', () => {
      const states = ['clean', 'dirty', 'not_tracked'] as const;
      for (const git_state of states) {
        const scenario = createBaseScenario({
          environment: { cwd: '/workspace', git_state }
        });
        const state = projectBaselineState(scenario);
        assert.equal(state.git_state, git_state);
        assert.equal(state.cwd, '/workspace');
        assert.ok(state.policy);
        assert.ok(Array.isArray(state.policy.no_access));
      }
    });
  });

  describe('Fixture End-to-End Projection', () => {
    test('correctly projects on-disk sample-scenario.json', () => {
      const fixturePath = resolve('benchmarks/scenarios/sample-scenario.json');
      const content = JSON.parse(readFileSync(fixturePath, 'utf8'));
      const scenario = parseScenario(content);

      const projector = new BaselineStateProjector();
      const state = projector.project(scenario);

      assert.equal(state.pending_action.tool, 'execute_command');
      assert.equal(state.pending_action.target, 'npm run build');
      assert.equal(state.git_state, 'clean');
      assert.equal(state.cwd, '/workspace/project');
      assert.equal(state.latest_user_request, 'Run the test build before we package the release');
      assert.deepEqual(state.previous_user_requests, []);
      assert.deepEqual(state.recent_tool_calls, []);
      assert.ok(state.policy);
    });
  });
});
