import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { RiskScoringPolicy } from '../dist/core/engine/risk-scoring-policy.js';
import { MockProvider } from '../dist/providers/mock-provider.js';
import { buildTier2State } from '../dist/providers/typesafe-provider.js';
import { reasonFor } from '../dist/core/engine/reason-catalog.js';
import type {
  CanonicalContext,
  OperatingMode,
  PathsConfig,
  Tier2Category,
  Tier2Config,
  Verdict
} from '../src/types.js';

const baseConfig: Tier2Config = {
  enabled: true,
  provider: 'mock',
  timeout_ms: 100
};

const dummyContext: CanonicalContext = { toolName: 'run_command', payload: 'pytest' };

const policy = (
  category: Tier2Category = 'safe',
  mode: OperatingMode = 'auto',
  fallbackVerdict: Verdict = 'allow',
  config: Tier2Config = baseConfig,
  delayMs = 0,
  shouldFail = false,
  userPaths?: PathsConfig
) =>
  new RiskScoringPolicy(config, new MockProvider(category, delayMs, shouldFail), fallbackVerdict, mode, userPaths);

describe('RiskScoringPolicy (Tier 2 zero-threshold categorical choice)', () => {
  test('allows action when category is safe', async () => {
    const res = await policy('safe').evaluate(dummyContext);

    assert.equal(res.decision, 'allow');
    assert.equal(res.tierMatched, 'tier2');
    assert.equal(res.evidence.tier2Category, 'safe');
    assert.equal(res.evidence.breachedDimension, undefined);
    assert.equal(res.evidence.mode, 'auto');
    assert.match(res.reason, /safe/);
  });

  test('restricts action and sets evidence when category is harmful, sensitive, opaque, or external', async () => {
    const categories: Array<'harmful' | 'sensitive' | 'opaque' | 'external'> = ['harmful', 'sensitive', 'opaque', 'external'];

    for (const cat of categories) {
      const autoRes = await policy(cat, 'auto').evaluate(dummyContext);
      assert.equal(autoRes.decision, 'restrict');
      assert.equal(autoRes.tierMatched, 'tier2');
      assert.equal(autoRes.evidence.tier2Category, cat);
      assert.equal(autoRes.evidence.breachedDimension, cat);
      assert.equal(autoRes.reason, reasonFor(cat, 'auto'));

      const askRes = await policy(cat, 'ask').evaluate(dummyContext);
      assert.equal(askRes.decision, 'restrict');
      assert.equal(askRes.tierMatched, 'tier2');
      assert.equal(askRes.evidence.tier2Category, cat);
      assert.equal(askRes.evidence.breachedDimension, cat);
      assert.equal(askRes.reason, reasonFor(cat, 'ask'));
    }
  });

  test('populates context.policy from SYSTEM_PATHS + userPaths when evaluating provider', async () => {
    let capturedContext: CanonicalContext | undefined;
    const inspectingProvider = {
      name: 'inspector',
      evaluate: async (ctx: CanonicalContext) => {
        capturedContext = ctx;
        return 'safe' as Tier2Category;
      }
    };
    const customUserPaths: PathsConfig = {
      outside_read: 'restrict',
      outside_write: 'restrict',
      no_access: ['/secret/custom'],
      read_only: ['/ro/custom'],
      allowed: ['/app/data']
    };
    const p = new RiskScoringPolicy(baseConfig, inspectingProvider, 'allow', 'auto', customUserPaths);
    await p.evaluate(dummyContext);

    assert.ok(capturedContext);
    assert.ok(capturedContext.policy);
    assert.equal(capturedContext.policy.outside_read, 'restrict');
    assert.equal(capturedContext.policy.outside_write, 'restrict');
    assert.ok(capturedContext.policy.no_access.includes('/secret/custom'));
    assert.ok(capturedContext.policy.read_only.includes('/ro/custom'));
    assert.ok(capturedContext.policy.allowed.includes('/app/data'));
  });

  test('buildTier2State preserves untruncated target, summary, and context fields', () => {
    const longTarget = 'rm -rf ' + 'a/'.repeat(1500) + 'test';
    assert.ok(longTarget.length > 2000);

    const ctx: CanonicalContext = {
      toolName: 'execute_command',
      payload: longTarget,
      summary: 'Clean nested directory',
      cwd: '/workspace/app',
      gitState: 'clean',
      latestUserRequest: 'Deploy the app',
      previousUserRequests: ['Prepare release', 'Run build'],
      recentToolCalls: [{ tool: 'execute_command', payload: 'npm test' }]
    };

    const state = buildTier2State(ctx);
    assert.equal(state.pending_action.tool, 'execute_command');
    assert.equal(state.pending_action.target, longTarget);
    assert.equal(state.pending_action.summary, 'Clean nested directory');
    assert.equal(state.cwd, '/workspace/app');
    assert.equal(state.git_state, 'clean');
    assert.equal(state.latest_user_request, 'Deploy the app');
    assert.deepEqual(state.previous_user_requests, ['Prepare release', 'Run build']);
    assert.deepEqual(state.recent_tool_calls, [{ tool: 'execute_command', payload: 'npm test' }]);
    assert.ok(state.policy);
  });

  test('when disabled, returns configured fallback verdict (default: allow)', async () => {
    const disabledConfig: Tier2Config = { ...baseConfig, enabled: false };

    const autoRes = await policy('harmful', 'auto', 'allow', disabledConfig).evaluate(dummyContext);
    assert.equal(autoRes.decision, 'allow');
    assert.equal(autoRes.tierMatched, 'fallback');
    assert.equal(autoRes.evidence.fallbackVerdict, 'allow');
    assert.match(autoRes.reason, /provider is disabled/);

    const askRes = await policy('harmful', 'ask', 'allow', disabledConfig).evaluate(dummyContext);
    assert.equal(askRes.decision, 'allow');
    assert.equal(askRes.tierMatched, 'fallback');

    const restrictRes = await policy('harmful', 'auto', 'restrict', disabledConfig).evaluate(dummyContext);
    assert.equal(restrictRes.decision, 'restrict');
    assert.equal(restrictRes.tierMatched, 'fallback');
    assert.equal(restrictRes.evidence.fallbackVerdict, 'restrict');
    assert.match(restrictRes.reason, /restricted by fallback policy/);

    const restrictAsk = await policy('harmful', 'ask', 'restrict', disabledConfig).evaluate(dummyContext);
    assert.match(restrictAsk.reason, /requires user approval/);
  });

  test('missing target falls back without calling the provider', async () => {
    const res = await policy('harmful').evaluate({ toolName: 'run_command' });

    assert.equal(res.decision, 'allow');
    assert.equal(res.tierMatched, 'fallback');
    assert.match(res.reason, /requires a target resource/);
    assert.equal(res.evidence.aiInteraction?.error, 'missing target');
  });

  test('fail-safe timeout: falls back to configured fallback verdict (default: allow)', async () => {
    const timeoutConfig: Tier2Config = { ...baseConfig, timeout_ms: 50 };

    const autoRes = await policy('safe', 'auto', 'allow', timeoutConfig, 250).evaluate(dummyContext);
    assert.equal(autoRes.decision, 'allow');
    assert.equal(autoRes.tierMatched, 'fallback');
    assert.match(autoRes.reason, /timed out/);

    const askRes = await policy('safe', 'ask', 'allow', timeoutConfig, 250).evaluate(dummyContext);
    assert.equal(askRes.decision, 'allow');
    assert.match(askRes.reason, /timed out/);

    const restrictRes = await policy('safe', 'auto', 'restrict', timeoutConfig, 250).evaluate(dummyContext);
    assert.equal(restrictRes.decision, 'restrict');
    assert.equal(restrictRes.tierMatched, 'fallback');
  });

  test('fail-safe error: falls back to configured fallback verdict (default: allow)', async () => {
    const autoRes = await policy('safe', 'auto', 'allow', baseConfig, 0, true).evaluate(dummyContext);
    assert.equal(autoRes.decision, 'allow');
    assert.equal(autoRes.tierMatched, 'fallback');
    assert.match(autoRes.reason, /provider error/i);

    const askRes = await policy('safe', 'ask', 'allow', baseConfig, 0, true).evaluate(dummyContext);
    assert.equal(askRes.decision, 'allow');
    assert.match(askRes.reason, /provider error/i);

    const restrictRes = await policy('safe', 'auto', 'restrict', baseConfig, 0, true).evaluate(dummyContext);
    assert.equal(restrictRes.decision, 'restrict');
    assert.equal(restrictRes.tierMatched, 'fallback');
  });

  test('aborted signal falls back instead of hanging until timeout', async () => {
    const controller = new AbortController();
    controller.abort();
    const res = await policy('safe', 'auto', 'allow', { ...baseConfig, timeout_ms: 5000 }, 5000).evaluate(dummyContext, controller.signal);

    assert.equal(res.tierMatched, 'fallback');
    assert.equal(res.evidence.aiInteraction?.error, 'The agntguard provider was aborted');
  });

  test('unconfigured provider falls back gracefully with telemetry record', async () => {
    const unconfiguredPolicy = new RiskScoringPolicy(baseConfig, undefined, 'allow', 'auto');
    const res = await unconfiguredPolicy.evaluate(dummyContext);

    assert.equal(res.decision, 'allow');
    assert.equal(res.tierMatched, 'fallback');
    assert.equal(res.evidence.aiInteraction?.provider, 'none');
    assert.equal(res.evidence.aiInteraction?.error, 'No decision provider configured');
  });
});
