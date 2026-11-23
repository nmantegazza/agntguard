import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { GitState } from '../types.js';

const execFileAsync = promisify(execFile);

export interface GitContext {
  git_state: GitState;
}

export async function inspectGitContext(cwd?: string): Promise<GitContext> {
  const dir = cwd || process.cwd();

  try {
    const { stdout: insideWorkTree } = await execFileAsync(
      'git',
      ['rev-parse', '--is-inside-work-tree'],
      { cwd: dir, timeout: 300, encoding: 'utf8' }
    );

    if (insideWorkTree.trim() !== 'true') {
      return { git_state: 'not_tracked' };
    }

    const { stdout: statusOutput } = await execFileAsync(
      'git',
      ['status', '--porcelain'],
      { cwd: dir, timeout: 300, encoding: 'utf8' }
    );

    return { git_state: statusOutput.trim().length > 0 ? 'dirty' : 'clean' };
  } catch {
    return { git_state: 'not_tracked' };
  }
}
