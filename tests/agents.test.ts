import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { AntigravityAdapter, AntigravityAgent, extractAntigravitySessionContext } from '../dist/agents/antigravity-adapter.js';
import { OpencodeAdapter, OpencodeAgent } from '../dist/agents/opencode-adapter.js';
import { PiAdapter, PiAgent, enrichPiContext } from '../dist/agents/pi-adapter.js';
import { budgetUserRequests, budgetRecentToolCalls, TRIMMED_HISTORY_NOTICE } from '../dist/agents/shared/history-format.js';


describe('Antigravity normalizer', () => {
  test('maps run_command to execute_command with payload', async () => {
    const ctx = await AntigravityAdapter.buildContext(
      JSON.stringify({ toolCall: { name: 'run_command', args: { CommandLine: 'ls -la', Cwd: '/tmp' } } })
    );
    assert.equal(ctx.agent, 'antigravity');
    assert.equal(ctx.toolName, 'execute_command');
    assert.equal(ctx.payload, 'ls -la');
    assert.equal(ctx.cwd, '/tmp');
  });

  test('extracts cwd from workspacePaths when args.Cwd is omitted', async () => {
    const ctx = await AntigravityAdapter.buildContext(
      JSON.stringify({
        toolCall: { name: 'run_command', args: { CommandLine: 'git status' } },
        workspacePaths: ['/Users/test/project']
      })
    );
    assert.equal(ctx.cwd, '/Users/test/project');
    assert.deepEqual(ctx.workspacePaths, ['/Users/test/project']);
  });

  test('maps view_file to read_file', async () => {
    const ctx = await AntigravityAdapter.buildContext(
      JSON.stringify({ toolCall: { name: 'view_file', args: { AbsolutePath: '/tmp/a.txt' } } })
    );
    assert.equal(ctx.toolName, 'read_file');
    assert.equal(ctx.payload, '/tmp/a.txt');
  });

  test('extracts Path argument for read_file, write_file, and maps edit_file', async () => {
    const readCtx = await AntigravityAdapter.buildContext(
      JSON.stringify({ toolCall: { name: 'read_file', args: { Path: '/tmp/read.txt' } } })
    );
    assert.equal(readCtx.toolName, 'read_file');
    assert.equal(readCtx.payload, '/tmp/read.txt');

    const writeCtx = await AntigravityAdapter.buildContext(
      JSON.stringify({ toolCall: { name: 'write_file', args: { Path: '/tmp/write.txt', Content: 'hello' } } })
    );
    assert.equal(writeCtx.toolName, 'write_file');
    assert.equal(writeCtx.payload, '/tmp/write.txt');

    const editCtx = await AntigravityAdapter.buildContext(
      JSON.stringify({ toolCall: { name: 'edit_file', args: { Path: '/tmp/edit.txt', Target: 'a', Replacement: 'b' } } })
    );
    assert.equal(editCtx.toolName, 'write_file');
    assert.equal(editCtx.payload, '/tmp/edit.txt');
  });

  test('passes canonical names through and keeps unknown tools', async () => {
    const canon = await AntigravityAdapter.buildContext(
      JSON.stringify({ toolCall: { name: 'execute_command', args: { CommandLine: 'pwd' } } })
    );
    assert.equal(canon.toolName, 'execute_command');
    const unknown = await AntigravityAdapter.buildContext(
      JSON.stringify({ toolCall: { name: 'weird_tool', args: {} } })
    );
    assert.equal(unknown.toolName, 'weird_tool');
  });

  test('extracts toolSummary into summary when provided', async () => {
    const ctx = await AntigravityAdapter.buildContext(
      JSON.stringify({
        toolCall: { name: 'run_command', args: { CommandLine: 'ls', toolSummary: 'List directory contents' } }
      })
    );
    assert.equal(ctx.summary, 'List directory contents');
  });
});

describe('Antigravity formatter', () => {
  test('emits decision envelope with permissionOverrides on allow', () => {
    const res = AntigravityAdapter.formatResponse(
      { decision: 'allow', reason: 'ok', tierMatched: 'tier1', evidence: {} },
      { toolName: 'execute_command', payload: 'ls' }
    );
    assert.equal(res.decision, 'allow');
    assert.deepEqual(res.permissionOverrides, ['command(ls)']);
  });

  test('resolves restrict to deny in auto mode and omits permissionOverrides', () => {
    const res = AntigravityAdapter.formatResponse(
      { decision: 'restrict', reason: 'agent msg', tierMatched: 'tier1', evidence: { mode: 'auto' } },
      { toolName: 'execute_command', payload: 'rm -rf /' },
      'auto'
    );
    assert.equal(res.decision, 'deny');
    assert.equal(res.reason, 'agent msg');
    assert.equal(res.permissionOverrides, undefined);
  });

  test('resolves restrict to ask in ask mode and renders the reason verbatim', () => {
    const res = AntigravityAdapter.formatResponse(
      { decision: 'restrict', reason: 'user msg', tierMatched: 'tier1', evidence: { mode: 'ask' } },
      { toolName: 'execute_command', payload: 'rm -rf /' },
      'ask'
    );
    assert.equal(res.decision, 'ask');
    assert.equal(res.reason, 'user msg');
    assert.equal(res.permissionOverrides, undefined);
  });
});

describe('Antigravity enricher', () => {
  test('reads JSONL transcript goals and history', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-'));
    const tp = path.join(dir, 't.jsonl');
    fs.writeFileSync(
      tp,
      [
        JSON.stringify({ type: 'USER_INPUT', content: 'build feature X' }),
        JSON.stringify({ tool_calls: [{ name: 'run_command' }] }),
        JSON.stringify({ type: 'USER_INPUT', content: 'now do Y' })
      ].join('\n')
    );
    const session = await extractAntigravitySessionContext(tp);
    assert.equal(session.latestUserRequest, 'now do Y');
    assert.deepEqual(session.previousUserRequests, ['build feature X']);
    assert.deepEqual(session.recentToolCalls, [{ tool: 'execute_command', payload: '' }]);
    const via = await AntigravityAdapter.buildContext(JSON.stringify({ transcriptPath: tp }));
    assert.equal(via.latestUserRequest, 'now do Y');
    assert.deepEqual(via.previousUserRequests, ['build feature X']);
    assert.deepEqual(via.recentToolCalls, [{ tool: 'execute_command', payload: '' }]);
  });

  test('returns empty when transcript missing', async () => {
    const session = await extractAntigravitySessionContext('/nonexistent/t.jsonl');
    assert.deepEqual(session, {});
  });
});

describe('OpenCode normalizer', () => {
  test('maps shell to execute_command with single resource', async () => {
    const ctx = await OpencodeAdapter.buildContext(
      { action: 'shell', resources: ['ls -la'], effect: 'allow' },
      undefined,
      { cwd: '/repo', workspacePaths: ['/repo'] }
    );
    assert.equal(ctx.agent, 'opencode');
    assert.equal(ctx.toolName, 'execute_command');
    assert.equal(ctx.payload, 'ls -la');
    assert.equal(ctx.cwd, '/repo');
    assert.equal((ctx as any).resources, undefined);
    assert.equal((ctx as any).commandLine, undefined);
  });

  test('buildContexts splits multi-resource events into individual contexts', async () => {
    const contexts = await OpencodeAdapter.buildContexts(
      { action: 'shell', resources: ['ls -la', 'pwd'], effect: 'allow' },
      undefined,
      { cwd: '/repo', workspacePaths: ['/repo'] }
    );
    assert.equal(contexts.length, 2);
    assert.equal(contexts[0].toolName, 'execute_command');
    assert.equal(contexts[0].payload, 'ls -la');
    assert.equal(contexts[1].toolName, 'execute_command');
    assert.equal(contexts[1].payload, 'pwd');
    assert.equal((contexts[0] as any).resources, undefined);
    assert.equal((contexts[0] as any).commandLine, undefined);
    assert.equal((contexts[1] as any).resources, undefined);
    assert.equal((contexts[1] as any).commandLine, undefined);
  });

  test('maps read/edit/glob and passes unknown actions through', async () => {
    const read = await OpencodeAdapter.buildContext({ action: 'read', resources: ['/a.txt'], effect: 'allow' });
    assert.equal(read.toolName, 'read_file');
    const edit = await OpencodeAdapter.buildContext({ action: 'edit', resources: ['/a.txt'], effect: 'allow' });
    assert.equal(edit.toolName, 'write_file');
    const other = await OpencodeAdapter.buildContext({ action: 'question', resources: ['q'], effect: 'allow' });
    assert.equal(other.toolName, 'question');
  });

  test('extracts cwd and workspacePaths dynamically from session host', async () => {
    const host = {
      session: {
        get: async ({ sessionID }: { sessionID: string }) => ({
          location: { directory: '/Users/test/workspace' },
          subpath: 'packages/backend'
        }),
        context: async () => []
      }
    };
    const ctx = await OpencodeAdapter.buildContext(
      { sessionID: 'sess-123', action: 'shell', resources: ['npm test'] },
      host
    );
    assert.equal(ctx.cwd, path.resolve('/Users/test/workspace', 'packages/backend'));
    assert.deepEqual(ctx.workspacePaths, ['/Users/test/workspace']);
  });
});

describe('OpenCode formatter', () => {
  test('maps restrict outcome to effect/message based on mode', () => {
    const resAsk = OpencodeAdapter.formatResponse(
      { decision: 'restrict', reason: 'user prompt', tierMatched: 'tier2', evidence: { mode: 'ask' } },
      undefined,
      'ask'
    );
    assert.equal(resAsk.effect, 'ask');
    assert.equal(resAsk.message, 'user prompt');

    const resAuto = OpencodeAdapter.formatResponse(
      { decision: 'restrict', reason: 'agent deny', tierMatched: 'tier2', evidence: { mode: 'auto' } },
      undefined,
      'auto'
    );
    assert.equal(resAuto.effect, 'deny');
    assert.equal(resAuto.message, 'agent deny');

    const resAllow = OpencodeAdapter.formatResponse(
      { decision: 'allow', reason: 'permitted', tierMatched: 'tier1', evidence: {} },
      undefined
    );
    assert.equal(resAllow.effect, 'allow');
    assert.equal(resAllow.message, 'permitted');
  });
});

describe('OpenCode enricher', () => {
  test('extracts goals from session host API', async () => {
    const host = {
      session: {
        context: async () => [
          { type: 'user', text: 'goal one' },
          { type: 'assistant', content: [{ type: 'tool', name: 'read' }] },
          { type: 'user', text: 'goal two' }
        ]
      }
    };
    const session = await OpencodeAdapter.enrichContext({ sessionID: 's1' }, host);
    assert.equal(session.latestUserRequest, 'goal two');
    assert.deepEqual(session.previousUserRequests, ['goal one']);
    assert.deepEqual(session.recentToolCalls, [{ tool: 'read_file', payload: '' }]);
  });

  test('returns conversationId when host unavailable', async () => {
    const session = await OpencodeAdapter.enrichContext({ sessionID: 's9' });
    assert.equal(session.conversationId, 's9');
  });
});

describe('Pi normalizer', () => {
  test('maps bash and powershell to execute_command with command payload', async () => {
    const bash = await PiAdapter.buildContext({
      type: 'tool_call',
      toolName: 'bash',
      input: { command: 'git status' }
    });
    assert.equal(bash.agent, 'pi');
    assert.equal(bash.toolName, 'execute_command');
    assert.equal(bash.payload, 'git status');

    const ps = await PiAdapter.buildContext({
      type: 'tool_call',
      toolName: 'powershell',
      input: { command: 'Get-ChildItem' }
    });
    assert.equal(ps.agent, 'pi');
    assert.equal(ps.toolName, 'execute_command');
    assert.equal(ps.payload, 'Get-ChildItem');
  });

  test('maps read, write, edit to canonical tools with path payload', async () => {
    const read = await PiAdapter.buildContext({ toolName: 'read', input: { path: '/tmp/test.ts' } });
    assert.equal(read.toolName, 'read_file');
    assert.equal(read.payload, '/tmp/test.ts');

    const write = await PiAdapter.buildContext({ toolName: 'write', input: { path: '/tmp/out.ts' } });
    assert.equal(write.toolName, 'write_file');
    assert.equal(write.payload, '/tmp/out.ts');

    const edit = await PiAdapter.buildContext({ toolName: 'edit', input: { path: '/tmp/edit.ts' } });
    assert.equal(edit.toolName, 'write_file');
    assert.equal(edit.payload, '/tmp/edit.ts');
  });

  test('maps ls to read_file and defaults to "." when path is omitted or whitespace', async () => {
    const lsExplicit = await PiAdapter.buildContext({ toolName: 'ls', input: { path: '/var/log' } });
    assert.equal(lsExplicit.toolName, 'read_file');
    assert.equal(lsExplicit.payload, '/var/log');

    const lsEmpty = await PiAdapter.buildContext({ toolName: 'ls', input: {} });
    assert.equal(lsEmpty.toolName, 'read_file');
    assert.equal(lsEmpty.payload, '.');

    const lsWhitespace = await PiAdapter.buildContext({ toolName: 'ls', input: { path: '   ' } });
    assert.equal(lsWhitespace.toolName, 'read_file');
    assert.equal(lsWhitespace.payload, '.');
  });

  test('maps find to read_file and yields contexts for path and pattern, defaulting to "."', async () => {
    const contexts = await PiAdapter.buildContexts({
      toolName: 'find',
      input: { path: '/project', pattern: '*.env' }
    });
    assert.equal(contexts.length, 2);
    assert.equal(contexts[0].toolName, 'read_file');
    assert.equal(contexts[0].payload, '/project');
    assert.equal(contexts[1].toolName, 'read_file');
    assert.equal(contexts[1].payload, '*.env');

    const fallback = await PiAdapter.buildContexts({ toolName: 'find', input: {} });
    assert.equal(fallback.length, 1);
    assert.equal(fallback[0].payload, '.');

    const patternOnly = await PiAdapter.buildContexts({ toolName: 'find', input: { pattern: 'id_rsa' } });
    assert.equal(patternOnly.length, 1);
    assert.equal(patternOnly[0].payload, 'id_rsa');
  });

  test('maps grep to read_file and yields contexts for path and glob, defaulting to "."', async () => {
    const contexts = await PiAdapter.buildContexts({
      toolName: 'grep',
      input: { path: '/project', glob: '*.ts' }
    });
    assert.equal(contexts.length, 2);
    assert.equal(contexts[0].toolName, 'read_file');
    assert.equal(contexts[0].payload, '/project');
    assert.equal(contexts[1].toolName, 'read_file');
    assert.equal(contexts[1].payload, '*.ts');

    const fallback = await PiAdapter.buildContexts({ toolName: 'grep', input: {} });
    assert.equal(fallback.length, 1);
    assert.equal(fallback[0].payload, '.');
  });

  test('passes unmapped tools through with payload or serialized input', async () => {
    const custom = await PiAdapter.buildContext({
      toolName: 'custom_mcp',
      input: { query: 'test-query' }
    });
    assert.equal(custom.toolName, 'custom_mcp');
    assert.equal(custom.payload, JSON.stringify({ query: 'test-query' }));
  });
});

describe('Pi formatter', () => {
  test('maps restrict outcome to effect based on mode', () => {
    const resAsk = PiAdapter.formatResponse(
      { decision: 'restrict', reason: 'user prompt', tierMatched: 'tier2', evidence: { mode: 'ask' } },
      undefined,
      'ask'
    );
    assert.equal(resAsk.effect, 'ask');
    assert.equal(resAsk.reason, 'user prompt');

    const resAuto = PiAdapter.formatResponse(
      { decision: 'restrict', reason: 'agent deny', tierMatched: 'tier2', evidence: { mode: 'auto' } },
      undefined,
      'auto'
    );
    assert.equal(resAuto.effect, 'deny');
    assert.equal(resAuto.reason, 'agent deny');
  });

  test('maps allow outcome to effect: allow', () => {
    const resAllow = PiAdapter.formatResponse(
      { decision: 'allow', reason: 'permitted', tierMatched: 'tier1', evidence: {} },
      undefined
    );
    assert.equal(resAllow.effect, 'allow');
    assert.equal(resAllow.reason, 'permitted');
  });
});

describe('Pi enricher', () => {
  test('extracts goals and recent assistant tool calls from active branch', async () => {
    const ctx = {
      sessionManager: {
        getSessionId: () => 'sess-pi-42',
        getBranch: () => [
          { role: 'user', content: 'fix bug in auth' },
          {
            role: 'assistant',
            parts: [{ type: 'tool_call', name: 'read', input: { path: '/auth.ts' } }]
          },
          { role: 'user', content: 'now check tests' }
        ]
      }
    };

    const session = await enrichPiContext(ctx);
    assert.equal(session.conversationId, 'sess-pi-42');
    assert.equal(session.latestUserRequest, 'now check tests');
    assert.deepEqual(session.previousUserRequests, ['fix bug in auth']);
    assert.deepEqual(session.recentToolCalls, [{ tool: 'read_file', payload: '/auth.ts' }]);
  });

  test('preserves raw user message text without local truncation', async () => {
    const longMsg = 'A'.repeat(1200);
    const ctx = {
      sessionManager: {
        getSessionId: () => 'sess-raw',
        getBranch: () => [{ role: 'user', content: longMsg }]
      }
    };
    const session = await enrichPiContext(ctx);
    assert.equal(session.latestUserRequest, longMsg);
  });

  test('handles missing or throwing sessionManager gracefully', async () => {
    const empty = await enrichPiContext(undefined);
    assert.deepEqual(empty, {});

    const throwing = await enrichPiContext({
      sessionManager: {
        getSessionId: () => 'sess-err',
        getBranch: () => {
          throw new Error('branch read failure');
        }
      }
    });
    assert.equal(throwing.conversationId, 'sess-err');
    assert.equal(throwing.latestUserRequest, undefined);
  });
});

describe('budgetUserRequests and budgetRecentToolCalls', () => {
  test('single user turn sets latestUserRequest and empty previousUserRequests', () => {
    const res = budgetUserRequests(['Only prompt']);
    assert.equal(res.latestUserRequest, 'Only prompt');
    assert.deepEqual(res.previousUserRequests, []);
  });

  test('multi-turn within 2000 chars keeps previous turns in chronological order', () => {
    const res = budgetUserRequests(['First turn', 'Second turn', 'Latest turn']);
    assert.equal(res.latestUserRequest, 'Latest turn');
    assert.deepEqual(res.previousUserRequests, ['First turn', 'Second turn']);
  });

  test('caps each previous request at 500 characters', () => {
    const longTurn = 'X'.repeat(600);
    const res = budgetUserRequests([longTurn, 'Latest']);
    assert.equal(res.latestUserRequest, 'Latest');
    assert.equal(res.previousUserRequests.length, 1);
    assert.equal(res.previousUserRequests[0].length, 500);
  });

  test('prepends trim notice when previous requests exceed 2000 chars total', () => {
    const turn = 'A'.repeat(450);
    const turns = [turn, turn, turn, turn, turn, 'Latest'];
    const res = budgetUserRequests(turns);
    assert.equal(res.latestUserRequest, 'Latest');
    assert.equal(res.previousUserRequests[0], TRIMMED_HISTORY_NOTICE);
    assert.ok(res.previousUserRequests.length < turns.length);
  });

  test('budgetRecentToolCalls caps payload at 300 chars and window at 1500 chars', () => {
    const longPayload = 'p'.repeat(400);
    const calls = [
      { name: 'read_file', input: longPayload },
      { name: 'run_command', input: { CommandLine: 'short cmd' } }
    ];
    const budgeted = budgetRecentToolCalls(calls);
    assert.equal(budgeted.length, 2);
    assert.equal(budgeted[0].tool, 'read_file');
    assert.equal(budgeted[0].payload.length, 300);
    assert.equal(budgeted[1].tool, 'run_command');
    assert.equal(budgeted[1].payload, 'short cmd');
  });
});

