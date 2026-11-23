import pc from 'picocolors';

export function isColorEnabled(): boolean {
  if (process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== '') {
    return false;
  }
  if (process.env.FORCE_COLOR === '0') {
    return false;
  }
  if (process.env.FORCE_COLOR === '1' || process.env.FORCE_COLOR === 'true') {
    return true;
  }
  return Boolean(process.stdout?.isTTY || pc.isColorSupported);
}

export function getColors() {
  return pc.createColors(isColorEnabled());
}

export const symbols = {
  bullet: '●',
  circle: '○',
  warning: '⚠',
  square: '■',
  diamond: '◇',
  railTop: '┌',
  railMid: '│',
  railBottom: '└'
};

export function badgeHealth(status: 'enabled' | 'disabled' | 'broken' | 'missing key'): string {
  const c = getColors();
  switch (status) {
    case 'enabled':
      return c.green('● enabled');
    case 'disabled':
      return c.dim('○ disabled');
    case 'broken':
      return c.yellow('⚠ broken');
    case 'missing key':
      return c.yellow('⚠ missing key');
  }
}

export function badgeVerdict(verdict: 'allow' | 'restrict'): string {
  const c = getColors();
  if (verdict === 'allow') {
    return c.green('● allow');
  }
  return c.red('■ restrict');
}

export function badgeScope(scope: 'user' | 'system' | 'User' | 'System'): string {
  const c = getColors();
  const normalized = scope.toLowerCase();
  if (normalized === 'user') {
    return c.bold(c.cyan('[User]'));
  }
  return c.dim('[System]');
}

export function renderRail(title: string, lines: string[]): string {
  const c = getColors();
  const top = `${c.cyan('┌')}  ${c.bold(title)}`;
  const body = lines.map((line) => `${c.cyan('│')}  ${line}`).join('\n');
  const bottom = `${c.cyan('└')}`;
  return body.length > 0 ? `${top}\n${body}\n${bottom}` : `${top}\n${bottom}`;
}
