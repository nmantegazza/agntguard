import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { TelemetryLogger } from '../dist/core/telemetry/logger.js';
import type { PolicyConfig, CanonicalContext, PolicyDecision } from '../src/types.js';

describe('Telemetry Logger', () => {
  let tmpDir: string;
  let logDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auto-perm-telemetry-'));
    logDir = path.join(tmpDir, 'logs');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  const sampleContext: CanonicalContext = {
    agent: 'antigravity',
    toolName: 'run_command',
    payload: 'git status',
    cwd: '/workspace'
  };

  const sampleResult: PolicyDecision = {
    decision: 'allow',
    reason: 'Safe command',
    tierMatched: 'tier1',
    evidence: { tier1List: 'allow', tier1Pattern: '^git status$' }
  };

  test('appends valid decision jsonl record with daily rotation when telemetry is enabled', () => {
    const config: PolicyConfig = {
      rules: { restrict: [], allow: [] },
      tier2: {
        enabled: false,
        provider: 'mock',
        timeout_ms: 800
      },
      telemetry: {
        enabled: true,
        log_dir: logDir
      }
    };

    const logger = new TelemetryLogger(config, logDir);
    logger.log(sampleContext, sampleResult);

    const decisionsFile = logger.getDecisionsLogFilePath();
    const outputsFile = logger.getOutputsLogFilePath();

    assert.equal(fs.existsSync(decisionsFile), true);
    assert.equal(path.basename(decisionsFile), 'decisions.jsonl');
    assert.match(path.basename(path.dirname(decisionsFile)), /^\d{4}-\d{2}-\d{2}$/);
    // When no aiInteraction, outputs log is not written
    assert.equal(fs.existsSync(outputsFile), false);

    const content = fs.readFileSync(decisionsFile, 'utf8').trim();
    const record = JSON.parse(content);

    assert.equal(record.agent, 'antigravity');
    assert.equal(record.outcome.verdict, 'allow');
    assert.equal(record.outcome.reason, 'Safe command');
    assert.equal(record.action.payload, 'git status');
    assert.equal(record.action.commandLine, undefined);
    assert.equal(record.evaluation.tierMatched, 'tier1');
    // JSONL schema is frozen: evaluation keys stay flat, and the set of keys
    // that may appear is unchanged (undefined fields are dropped by JSON).
    const FROZEN_EVALUATION_KEYS = [
      'breachedDimension',
      'tier1List',
      'tier1Pattern',
      'tier2Category',
      'tier2LatencyMs',
      'tierMatched'
    ];
    for (const key of Object.keys(record.evaluation)) {
      assert.ok(FROZEN_EVALUATION_KEYS.includes(key), `unexpected evaluation key in JSONL: ${key}`);
    }
    assert.deepEqual(Object.keys(record.evaluation).sort(), ['tier1List', 'tier1Pattern', 'tierMatched']);
    assert.equal(record.evaluation.tier1List, 'allow');
    assert.equal(record.evaluation.tier1Pattern, '^git status$');
    assert.ok(record.timestamp);
  });

  test('logs separate AI outputs record when Tier 2 AI interaction is present', () => {
    const config: PolicyConfig = {
      rules: { restrict: [], allow: [] },
      tier2: {
        enabled: true,
        provider: 'typesafe',
        timeout_ms: 800
      },
      telemetry: {
        enabled: true,
        log_dir: logDir
      }
    };

    const logger = new TelemetryLogger(config, logDir);
    const contextWithConv: CanonicalContext = {
      ...sampleContext,
      conversationId: 'conv-ai-test',
      stepIdx: 12
    };

    const resultWithAI: PolicyDecision = {
      decision: 'allow',
      reason: 'Low risk',
      tierMatched: 'tier2',
      evidence: {
        tier2Category: 'safe',
        tier2LatencyMs: 250,
        aiInteraction: {
          provider: 'typesafe',
          model: 'jev-latest',
          request: {
            state: {
              cwd: '/workspace',
              git_state: 'clean',
              policy: {
                outside_read: 'allow',
                outside_write: 'restrict',
                no_access: [],
                read_only: [],
                allowed: []
              },
              latest_user_request: 'run tests',
              previous_user_requests: [],
              recent_tool_calls: [],
              pending_action: { tool: 'execute_command', target: 'npm test' }
            },
            questions: { decision: 'choice question' }
          },
          response: { answers: { decision: { choice: 'safe' } } },
          latencyMs: 250
        }
      }
    };

    logger.log(contextWithConv, resultWithAI);

    const decisionsFile = logger.getDecisionsLogFilePath();
    const outputsFile = logger.getOutputsLogFilePath();

    assert.equal(fs.existsSync(decisionsFile), true);
    assert.equal(fs.existsSync(outputsFile), true);

    const decisionRecord = JSON.parse(fs.readFileSync(decisionsFile, 'utf8').trim());
    const outputRecord = JSON.parse(fs.readFileSync(outputsFile, 'utf8').trim());

    // Correlate via agent and conversationId
    assert.equal(decisionRecord.agent, 'antigravity');
    assert.equal(decisionRecord.conversationId, 'conv-ai-test');
    assert.equal(decisionRecord.stepIdx, undefined);
    assert.equal(outputRecord.agent, 'antigravity');
    assert.equal(outputRecord.conversationId, 'conv-ai-test');
    assert.equal(outputRecord.stepIdx, undefined);

    // Verify AI prompt and raw output structure
    assert.equal(outputRecord.provider, 'typesafe');
    assert.equal(outputRecord.request.state.pending_action.target, 'npm test');
    assert.equal(outputRecord.request.questions.decision, 'choice question');
    assert.equal(outputRecord.response.answers.decision.choice, 'safe');
    assert.equal(outputRecord.latencyMs, 250);
  });

  test('embeds conversationId when provided in CanonicalContext and omits stepIdx', () => {
    const config: PolicyConfig = {
      rules: { restrict: [], allow: [] },
      tier2: {
        enabled: false,
        provider: 'mock',
        timeout_ms: 800
      },
      telemetry: {
        enabled: true,
        log_dir: logDir
      }
    };

    const logger = new TelemetryLogger(config, logDir);
    const contextWithConv: CanonicalContext = {
      ...sampleContext,
      conversationId: 'conv-abc-123',
      stepIdx: 4
    };

    logger.log(contextWithConv, sampleResult);

    const expectedFile = logger.getDecisionsLogFilePath();
    assert.equal(fs.existsSync(expectedFile), true);
    const content = fs.readFileSync(expectedFile, 'utf8').trim();
    const record = JSON.parse(content);

    assert.equal(record.conversationId, 'conv-abc-123');
    assert.equal(record.stepIdx, undefined);
  });

  test('maps Tier 1 rule dimension to breachedDimension in decisions log', () => {
    const config: PolicyConfig = {
      rules: { restrict: [], allow: [] },
      tier2: {
        enabled: false,
        provider: 'mock',
        timeout_ms: 800
      },
      telemetry: { enabled: true, log_dir: logDir }
    };

    const logger = new TelemetryLogger(config, logDir);
    const restrictResult: PolicyDecision = {
      decision: 'restrict',
      reason: 'Harmful command blocked',
      tierMatched: 'tier1',
      evidence: {
        tier1List: 'restrict',
        tier1Pattern: '^rm -rf /',
        tier1Dimension: 'harmful'
      }
    };

    logger.log(sampleContext, restrictResult);

    const expectedFile = logger.getDecisionsLogFilePath();
    const content = fs.readFileSync(expectedFile, 'utf8').trim();
    const record = JSON.parse(content);

    assert.equal(record.evaluation.tierMatched, 'tier1');
    assert.equal(record.evaluation.tier1List, 'restrict');
    assert.equal(record.evaluation.breachedDimension, 'harmful');
  });

  test('performs zero I/O when telemetry is disabled', () => {
    const config: PolicyConfig = {
      rules: { restrict: [], allow: [] },
      tier2: {
        enabled: false,
        provider: 'mock',
        timeout_ms: 800
      },
      telemetry: {
        enabled: false,
        log_dir: logDir
      }
    };

    const logger = new TelemetryLogger(config, logDir);
    logger.log(sampleContext, sampleResult);

    assert.equal(fs.existsSync(logDir), false);
  });

  test('swallows errors gracefully when file path is invalid', () => {
    const config: PolicyConfig = {
      rules: { restrict: [], allow: [] },
      tier2: {
        enabled: false,
        provider: 'mock',
        timeout_ms: 800
      },
      telemetry: {
        enabled: true,
        log_dir: '/dev/null/forbidden/dir'
      }
    };

    const logger = new TelemetryLogger(config, '/dev/null/forbidden/dir');
    // Should not throw
    assert.doesNotThrow(() => {
      logger.log(sampleContext, sampleResult);
    });
  });
});
