import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { AstAnalyzer } from '../dist/core/engine/ast-analyzer.js';
import { pathPolicyReason } from '../dist/core/engine/reason-catalog.js';
import type { AllowRule, PathsConfig, ProtectedPathsConfig, RestrictRule } from '../src/types.js';

const restrictRules: RestrictRule[] = [
  { tool: 'execute_command', pattern: '^rm\\s+(-rf|-fr|--recursive\\s+--force)\\s+[/~]', dimension: 'harmful' },
  { tool: 'execute_command', pattern: 'curl\\s+.*\\|\\s*(ba)?sh', dimension: 'opaque' }
];

const protectedPaths: ProtectedPathsConfig = {
  noAccess: ['\\.env(\\b|$)'],
  readOnly: ['/etc/hosts'],
  allowed: ['/dev/null', '/tmp(?:/.*)?']
};

const pureReadAllowRules: AllowRule[] = [
  { tool: 'execute_command', pattern: '^git\\s+(status|diff|log)$' },
  { tool: 'execute_command', pattern: '^cat(\\s+.*)?$' },
  { tool: 'execute_command', pattern: '^grep(\\s+.*)?$' },
  { tool: 'execute_command', pattern: '^echo(\\s+.*)?$' },
  { tool: 'execute_command', pattern: '^ls(\\s+.*)?$' },
  { tool: 'execute_command', pattern: '^wc(\\s+.*)?$' }
];

const allowRules: AllowRule[] = [
  ...pureReadAllowRules,
  { tool: 'execute_command', pattern: '^npm\\s+test(\\s+.*)?$' },
  { tool: 'execute_command', pattern: '^mkdir\\s+(?:-p\\s+)?[\\w./@][\\w./@-]*$' }
];

const analyzer = new AstAnalyzer();
const evaluate = (
  payload: string,
  mode: 'auto' | 'ask' = 'auto',
  pathContext?: { cwd?: string; workspacePaths?: string[]; userPaths?: PathsConfig }
) =>
  analyzer.evaluate(payload, mode, restrictRules, allowRules, protectedPaths, pureReadAllowRules, pathContext);

describe('AstAnalyzer (POSIX AST Shell Parser)', () => {
  test('malformed syntax and unclosed quotes fail closed with restrict / opaque', () => {
    const res = evaluate('echo "unclosed quote');
    assert.equal(res?.decision, 'restrict');
    assert.equal(res?.evidence.tier1Dimension, 'opaque');
    assert.equal(res?.tierMatched, 'tier1');
  });

  test('output redirection to /dev/null is allowed, while file redirects fall through or restrict', () => {
    // Redirection to real files is not fast-allowed (falls through to Tier 2)
    const fileRedirect = evaluate('echo hello > file.txt');
    assert.equal(fileRedirect, null);

    const clobberRedirect = evaluate('echo hello >| out.txt');
    assert.equal(clobberRedirect, null);

    const combinedRedirect = evaluate('echo hello &> out.txt');
    assert.equal(combinedRedirect, null);

    // Redirection to protected system targets is restricted by Path Policy Gate
    const appendRedirect = evaluate('echo hello >> /etc/hosts');
    assert.equal(appendRedirect?.decision, 'restrict');
    assert.equal(appendRedirect?.evidence.tier1Dimension, undefined);
    assert.equal(appendRedirect?.evidence.pathPolicyViolation, 'read_only');

    const envRedirect = evaluate('echo secret > .env');
    assert.equal(envRedirect?.decision, 'restrict');
    assert.equal(envRedirect?.evidence.tier1Dimension, undefined);
    assert.equal(envRedirect?.evidence.pathPolicyViolation, 'no_access');

    // Redirection to /dev/null and NUL permitted for fast-allow
    const nullRedirect = evaluate('echo hello > /dev/null');
    assert.equal(nullRedirect?.decision, 'allow');

    const devNullUpper = evaluate('echo hello > /DEV/NULL');
    assert.equal(devNullUpper?.decision, 'allow');

    const nulRedirect = evaluate('echo hello > NUL');
    assert.equal(nulRedirect?.decision, 'allow');

    const fd2NullRedirect = evaluate('echo hello 2>/dev/null');
    assert.equal(fd2NullRedirect?.decision, 'allow');
  });

  test('dynamic commands and execution primitives fall through to Tier 2', () => {
    // Dynamic command names fall through to Tier 2 (not auto-allowed)
    assert.equal(evaluate('$CMD foo'), null);
    assert.equal(evaluate('"$CMD" foo'), null);

    // Execution primitives fall through to Tier 2
    assert.equal(evaluate('eval "npm test"'), null);
    assert.equal(evaluate('source ./script.sh'), null);
    assert.equal(evaluate('. ./script.sh'), null);
  });

  test('environment prefixes and custom variables fall through to Tier 2 instead of hard-restricting', () => {
    // Environment prefix runs fall through to Tier 2
    assert.equal(evaluate('PYTHONPATH=/tmp/lib npm test'), null);
    assert.equal(evaluate('PATH=/tmp:$PATH npm test'), null);
    assert.equal(evaluate('export HOME=/root'), null);

    // Custom unwhitelisted variables fall through to Tier 2
    assert.equal(evaluate('echo $DIR'), null);
    assert.equal(evaluate('echo "$TARGET"'), null);
  });

  test('system variable constants are permitted for Tier 1 fast-allow', () => {
    // Whitelisted system variables
    assert.equal(evaluate('echo $HOME')?.decision, 'allow');
    assert.equal(evaluate('echo "$HOME"')?.decision, 'allow');
    assert.equal(evaluate('echo "${HOME}"')?.decision, 'allow');
    assert.equal(evaluate('echo $PWD')?.decision, 'allow');
    assert.equal(evaluate('echo $TMPDIR')?.decision, 'allow');

    // Unseeded variables fall through to Tier 2
    assert.equal(evaluate('echo $USER'), null);
    assert.equal(evaluate('echo $CI'), null);
    assert.equal(evaluate('echo $?'), null);
    assert.equal(evaluate('echo $#'), null);
  });

  test('command chaining triggers restrict via short-circuit', () => {
    const chained = evaluate('npm test && rm -rf /');
    assert.equal(chained?.decision, 'restrict');
    assert.equal(chained?.evidence.tier1Dimension, 'harmful');

    const semiChained = evaluate('git status ; rm -rf ~');
    assert.equal(semiChained?.decision, 'restrict');
    assert.equal(semiChained?.evidence.tier1Dimension, 'harmful');
  });

  test('nested command substitution traverses into inner command and triggers restrict', () => {
    const envSubst = evaluate('echo "$(cat .env)"');
    assert.equal(envSubst?.decision, 'restrict');
    assert.equal(envSubst?.evidence.tier1Dimension, undefined);
    assert.equal(envSubst?.evidence.pathPolicyViolation, 'no_access');

    const backtickHarmful = evaluate('echo "`rm -rf /`"');
    assert.equal(backtickHarmful?.decision, 'restrict');
    assert.equal(backtickHarmful?.evidence.tier1Dimension, 'harmful');
  });

  test('pipelines require universal conjunction of all commands to allow', () => {
    const bothAllowed = evaluate('cat file | grep text');
    assert.equal(bothAllowed?.decision, 'allow');

    const oneUnmapped = evaluate('cat file | unmapped_command');
    assert.equal(oneUnmapped, null);
  });

  test('quote and escape evasion normalizes correctly', () => {
    const quoteEvasionAllow = evaluate("'g'it status");
    assert.equal(quoteEvasionAllow?.decision, 'allow');

    const escapeEvasionRestrict = evaluate('\\r\\m -rf /');
    assert.equal(escapeEvasionRestrict?.decision, 'restrict');
    assert.equal(escapeEvasionRestrict?.evidence.tier1Dimension, 'harmful');
  });

  test('Gate 2 Protected Paths: noAccess blocks reads and writes, readOnly permits proven pure reads', () => {
    // noAccess blocks even pure reads
    const catEnv = evaluate('cat .env');
    assert.equal(catEnv?.decision, 'restrict');
    assert.equal(catEnv?.evidence.tier1Dimension, undefined);
    assert.equal(catEnv?.evidence.pathPolicyViolation, 'no_access');
    assert.equal(catEnv?.evidence.tier1Pattern, '\\.env(\\b|$)');
    assert.equal(catEnv?.reason, pathPolicyReason('no_access', 'auto'));

    // readOnly allows pure reads
    const catHosts = evaluate('cat /etc/hosts');
    assert.equal(catHosts?.decision, 'allow');

    // readOnly blocks redirect writes
    const redirectHosts = evaluate('echo hello >> /etc/hosts');
    assert.equal(redirectHosts?.decision, 'restrict');
    assert.equal(redirectHosts?.evidence.tier1Dimension, undefined);
    assert.equal(redirectHosts?.evidence.pathPolicyViolation, 'read_only');
    assert.equal(redirectHosts?.reason, pathPolicyReason('read_only', 'auto'));

    // readOnly blocks dynamic variable expansion in compound pipelines
    const varHosts = evaluate('cat /etc/hosts && echo $CUSTOM_VAR');
    assert.equal(varHosts?.decision, 'restrict');
    assert.equal(varHosts?.evidence.tier1Dimension, undefined);
    assert.equal(varHosts?.evidence.pathPolicyViolation, 'read_only');

    // readOnly blocks unmapped/non-pure-read commands
    const unmappedHosts = evaluate('python3 /etc/hosts');
    assert.equal(unmappedHosts?.decision, 'restrict');
    assert.equal(unmappedHosts?.evidence.tier1Dimension, undefined);
    assert.equal(unmappedHosts?.evidence.pathPolicyViolation, 'read_only');

    // Bare redirects without command name
    const bareEnv = evaluate('> .env');
    assert.equal(bareEnv?.decision, 'restrict');
    assert.equal(bareEnv?.evidence.tier1Dimension, undefined);
    assert.equal(bareEnv?.evidence.pathPolicyViolation, 'no_access');

    const bareHosts = evaluate('> /etc/hosts');
    assert.equal(bareHosts?.decision, 'restrict');
    assert.equal(bareHosts?.evidence.tier1Dimension, undefined);
    assert.equal(bareHosts?.evidence.pathPolicyViolation, 'read_only');

    const bareSafe = evaluate('> safe.txt');
    assert.equal(bareSafe, null);
  });

  test('Gate 2 Workspace Boundary: enforces outside_write and outside_read when cwd is provided', () => {
    const ctx = { cwd: '/workspace/app' };

    // Inside workspace mutation -> passes Gate 2 and matches allow rule
    const insideMkdir = evaluate('mkdir -p /workspace/app/dist', 'auto', ctx);
    assert.equal(insideMkdir?.decision, 'allow');

    // Relative inside workspace mutation -> allowed
    const relMkdir = evaluate('mkdir -p src/components', 'auto', ctx);
    assert.equal(relMkdir?.decision, 'allow');

    // Outside workspace mutation -> restricted with outside_write
    const outsideMkdir = evaluate('mkdir -p /workspace/other/dir', 'auto', ctx);
    assert.equal(outsideMkdir?.decision, 'restrict');
    assert.equal(outsideMkdir?.evidence.tier1Dimension, undefined);
    assert.equal(outsideMkdir?.evidence.pathPolicyViolation, 'outside_write');
    assert.equal(outsideMkdir?.reason, pathPolicyReason('outside_write', 'auto'));

    // Traversal outside workspace via .. -> restricted with outside_write
    const traversalRedirect = evaluate('echo hi > ../outside.txt', 'auto', ctx);
    assert.equal(traversalRedirect?.decision, 'restrict');
    assert.equal(traversalRedirect?.evidence.pathPolicyViolation, 'outside_write');

    // Ephemeral /tmp write -> allowed by SYSTEM_PATHS.allowed (passes Gate 2; mkdir /tmp/out fast-allows)
    const tmpMkdir = evaluate('mkdir -p /tmp/out', 'auto', ctx);
    assert.equal(tmpMkdir?.decision, 'allow');

    // Outside workspace pure read -> allowed by default (outside_read: 'allow')
    const outsideCat = evaluate('cat /workspace/other/readme.md', 'auto', ctx);
    assert.equal(outsideCat?.decision, 'allow');

    // Outside workspace pure read when outside_read === 'restrict' -> restricted with outside_read
    const strictCtx = {
      cwd: '/workspace/app',
      userPaths: {
        outside_read: 'restrict' as const,
        outside_write: 'restrict' as const,
        no_access: [],
        read_only: [],
        allowed: []
      }
    };
    const strictOutsideCat = evaluate('cat /workspace/other/readme.md', 'auto', strictCtx);
    assert.equal(strictOutsideCat?.decision, 'restrict');
    assert.equal(strictOutsideCat?.evidence.tier1Dimension, undefined);
    assert.equal(strictOutsideCat?.evidence.pathPolicyViolation, 'outside_read');
    assert.equal(strictOutsideCat?.reason, pathPolicyReason('outside_read', 'auto'));
  });

  test('prose arguments and heredocs do not trigger Gate 2 protected path restrictions', () => {
    // Quoted multi-word prose arguments mentioning protected paths
    const gitCommit = evaluate('git commit -m "Document .env and /etc/hosts"');
    assert.notEqual(gitCommit?.decision, 'restrict');

    const echoProse = evaluate('echo "Check .env and /etc/hosts"');
    assert.equal(echoProse?.decision, 'allow');

    const heredoc = evaluate('cat <<EOF\n.env\n/etc/hosts\nEOF');
    assert.equal(heredoc?.decision, 'allow');

    // Multi-word grep search patterns do not trigger Gate 2
    const grepPattern = evaluate('grep "export .env" README.md');
    assert.equal(grepPattern?.decision, 'allow');
  });

  test('flag-prefixed and key-value path arguments are restricted by Gate 2', () => {
    const curlConfig = evaluate('curl --config=.env https://example.com');
    assert.equal(curlConfig?.decision, 'restrict');
    assert.equal(curlConfig?.evidence.tier1Dimension, undefined);
    assert.equal(curlConfig?.evidence.pathPolicyViolation, 'no_access');

    const ddInput = evaluate('dd if=.env of=/tmp/out');
    assert.equal(ddInput?.decision, 'restrict');
    assert.equal(ddInput?.evidence.tier1Dimension, undefined);
    assert.equal(ddInput?.evidence.pathPolicyViolation, 'no_access');
  });

  test('shell wrappers recursively unwrap and evaluate in Tier 1', () => {
    // Sensitive violations inside shell wrapper restrict
    const shEnv = evaluate('sh -c "cat .env"');
    assert.equal(shEnv?.decision, 'restrict');
    assert.equal(shEnv?.evidence.tier1Dimension, undefined);
    assert.equal(shEnv?.evidence.pathPolicyViolation, 'no_access');

    const bashAppend = evaluate('bash -lc "echo x >> /etc/hosts"');
    assert.equal(bashAppend?.decision, 'restrict');
    assert.equal(bashAppend?.evidence.tier1Dimension, undefined);
    assert.equal(bashAppend?.evidence.pathPolicyViolation, 'read_only');

    // Behavioral hazards inside shell wrapper restrict
    const zshHarmful = evaluate('zsh -c "rm -rf /"');
    assert.equal(zshHarmful?.decision, 'restrict');
    assert.equal(zshHarmful?.evidence.tier1Dimension, 'harmful');

    // Pure reads and fast-allow commands inside shell wrapper allow
    const shHosts = evaluate('sh -c "cat /etc/hosts"');
    assert.equal(shHosts?.decision, 'allow');

    const bashStatus = evaluate('bash -c "git status"');
    assert.equal(bashStatus?.decision, 'allow');

    // Unmapped commands inside shell wrapper fall through to Tier 2
    const shPython = evaluate('sh -c "python3 app.py"');
    assert.equal(shPython, null);

    // Shell wrapper with syntax error in inner script fails closed
    const badInner = evaluate('sh -c "echo \\"unclosed quote"');
    assert.equal(badInner?.decision, 'restrict');
    assert.equal(badInner?.evidence.tier1Dimension, 'opaque');
  });

  test('non-shell interpreter inline code falls through to Tier 2 while script files restrict', () => {
    // Inline code falls through to Tier 2
    const pythonInline = evaluate('python3 -c "open(\'/etc/hosts\')"');
    assert.equal(pythonInline, null);

    const nodeInline = evaluate('node -e "fs.readFileSync(\'.env\')"');
    assert.equal(nodeInline, null);

    // Direct script files targeting protected paths restrict in Tier 1
    const pythonHosts = evaluate('python3 /etc/hosts');
    assert.equal(pythonHosts?.decision, 'restrict');
    assert.equal(pythonHosts?.evidence.tier1Dimension, undefined);
    assert.equal(pythonHosts?.evidence.pathPolicyViolation, 'read_only');

    const pythonEnv = evaluate('python3 .env');
    assert.equal(pythonEnv?.decision, 'restrict');
    assert.equal(pythonEnv?.evidence.tier1Dimension, undefined);
    assert.equal(pythonEnv?.evidence.pathPolicyViolation, 'no_access');
  });

  test('Gate 1 & Gate 2 variable assignment resolution', () => {
    // Path resolution via variable: no_access
    const targetEnv = evaluate('F=.env; cat $F');
    assert.equal(targetEnv?.decision, 'restrict');
    assert.equal(targetEnv?.evidence.pathPolicyViolation, 'no_access');

    // Path resolution via variable on redirect: read_only mutation
    const appendHosts = evaluate('F=/etc/hosts; echo x >> $F');
    assert.equal(appendHosts?.decision, 'restrict');
    assert.equal(appendHosts?.evidence.pathPolicyViolation, 'read_only');

    // Command indirection: Gate 1 harmful pattern match
    const rmIndirect = evaluate('CMD=rm; $CMD -rf /');
    assert.equal(rmIndirect?.decision, 'restrict');
    assert.equal(rmIndirect?.evidence.tier1Dimension, 'harmful');

    // Variable resolution inside shell wrapper script
    const shEnv = evaluate('F=.env; sh -c "cat $F"');
    assert.equal(shEnv?.decision, 'restrict');
    assert.equal(shEnv?.evidence.pathPolicyViolation, 'no_access');
  });

  test('Gate 2 for loop wordlist expansion', () => {
    // Sensitive file targeted inside loop
    const loopEnv = evaluate('for f in a.txt .env; do cat "$f"; done');
    assert.equal(loopEnv?.decision, 'restrict');
    assert.equal(loopEnv?.evidence.pathPolicyViolation, 'no_access');

    // Read-only file mutated inside loop
    const loopHosts = evaluate('for f in a.txt /etc/hosts; do echo x >> "$f"; done');
    assert.equal(loopHosts?.decision, 'restrict');
    assert.equal(loopHosts?.evidence.pathPolicyViolation, 'read_only');
  });

  test('Tier 1 0ms Fast-Allow with resolved static variables and loops', () => {
    // Safe static variable reference allows in 0ms
    const staticDir = evaluate('DIR=src; ls "$DIR"');
    assert.equal(staticDir?.decision, 'allow');

    // Safe static for loop allows in 0ms
    const loopAllow = evaluate('for f in a.ts b.ts; do wc -l "$f"; done');
    assert.equal(loopAllow?.decision, 'allow');

    // Proven pure read on read_only path via variable allows in 0ms
    const readHosts = evaluate('F=/etc/hosts; cat "$F"');
    assert.equal(readHosts?.decision, 'allow');
  });

  test('dynamic reassignments and tainting via variables.delete', () => {
    // Dynamic subshell assignment taints variable and falls through to Tier 2
    const dynamicSubst = evaluate('DIR=src; DIR=$(pwd); ls "$DIR"');
    assert.equal(dynamicSubst, null);

    // Unresolved reference taints variable and falls through
    const unknownVar = evaluate('F=.env; F=$UNKNOWN; echo "$F"');
    assert.equal(unknownVar, null);

    // Command substitution targeting sensitive path restricts closed
    const envSubst = evaluate('F=$(cat .env)');
    assert.equal(envSubst?.decision, 'restrict');
    assert.equal(envSubst?.evidence.pathPolicyViolation, 'no_access');

    // Complex parameter expansions fall through to Tier 2
    const complexModifier = evaluate('echo ${DIR:-src}');
    assert.equal(complexModifier, null);
  });

  test('system environment variable reassignment protection', () => {
    // Reassigning PATH disqualifies fast-allow and falls through to Tier 2
    const pathReassign = evaluate('PATH=/tmp; ls');
    assert.equal(pathReassign, null);

    // Reassigning HOME disqualifies fast-allow
    const homeReassign = evaluate('HOME=/tmp; ls $HOME');
    assert.equal(homeReassign, null);

    // Reassigning TMPDIR still updates variables so subsequent target is caught by Gate 2
    const tmpdirEnv = evaluate('TMPDIR=.env; cat $TMPDIR');
    assert.equal(tmpdirEnv?.decision, 'restrict');
    assert.equal(tmpdirEnv?.evidence.pathPolicyViolation, 'no_access');
  });

  test('combination cap enforcement', () => {
    // For loop with > 50 items falls through to Tier 2
    const items = Array.from({ length: 51 }, (_, i) => `item${i}`).join(' ');
    const largeLoop = evaluate(`for f in ${items}; do ls "$f"; done`);
    assert.equal(largeLoop, null);

    // Cartesian product > 50 combinations falls through to Tier 2
    const items8 = '1 2 3 4 5 6 7 8';
    const largeProduct = evaluate(`for f in ${items8}; do for g in ${items8}; do ls "$f" "$g"; done; done`);
    assert.equal(largeProduct, null);
  });
});
