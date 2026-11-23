import { loadConfig, getDefaultConfigPath } from '../../config.js';
import { loadApiKey } from '../../credentials.js';
import { SYSTEM_RESTRICT_RULES, SYSTEM_ALLOW_RULES, SYSTEM_PATHS } from '../../core/defaults/system-rules.js';
import { inspectHealth } from '../agents/registry.js';
import { badgeHealth, badgeVerdict, getColors, renderRail } from '../theme.js';

export async function handleStatusCommand(): Promise<void> {
  const config = loadConfig();
  const configPath = getDefaultConfigPath();
  const apiKey = loadApiKey();
  const health = inspectHealth();
  const c = getColors();

  const userPathCount =
    (config.paths?.no_access?.length || 0) +
    (config.paths?.read_only?.length || 0) +
    (config.paths?.allowed?.length || 0);

  const sysPathCount =
    SYSTEM_PATHS.noAccess.length +
    SYSTEM_PATHS.readOnly.length +
    SYSTEM_PATHS.allowed.length;

  const userRuleCount =
    (config.rules?.restrict?.length || 0) +
    (config.rules?.allow?.length || 0);

  const sysRuleCount =
    SYSTEM_RESTRICT_RULES.length +
    SYSTEM_ALLOW_RULES.length;

  const lines: string[] = [
    `${c.bold('HOST AGENT INTEGRATIONS')}`,
    ...Object.values(health).map((agent) => {
      const detectStr = agent.detected ? c.dim('(installed)') : c.dim('(not detected)');
      const badge = badgeHealth(agent.status);
      const namePadded = agent.name.padEnd(14);
      return `  ${c.cyan(namePadded)} ${badge.padEnd(20)} ${detectStr}`;
    }),
    '',
    `${c.bold('POLICY POSTURE')}`,
    `  Active Config:        ${configPath}`,
    `  Operating Mode:       ${c.bold(config.mode || 'auto')}`,
    `  Fallback Verdict:     ${badgeVerdict(config.fallback_verdict || 'allow')}`,
    `  Outside Read:         ${badgeVerdict(config.paths?.outside_read || 'allow')}`,
    `  Outside Write:        ${badgeVerdict(config.paths?.outside_write || 'restrict')}`,
    '',
    `${c.bold('RULE INVENTORY')}`,
    `  Gate 2 Path Rules:    ${c.cyan(String(userPathCount))} user rules active | ${c.dim(String(sysPathCount) + ' system guardrails')}`,
    `  Gate 3 Regex Rules:   ${c.cyan(String(userRuleCount))} user rules active | ${c.dim(String(sysRuleCount) + ' system guardrails')}`,
    '',
    `${c.bold('TIER 2 AI CLASSIFICATION')}`,
    `  Status:               ${config.tier2.enabled ? c.green('enabled') : c.dim('disabled')}`,
    `  Provider:             ${config.tier2.provider || 'typesafe'}`,
    `  Model:                ${config.tier2.model || 'jev-latest'}`,
    `  API Key:              ${apiKey ? c.green('configured') : c.yellow('missing key')}`,
    '',
    `${c.bold('TELEMETRY')}`,
    `  Logging:              ${config.telemetry.enabled ? c.green('enabled') : c.dim('disabled')}`,
    `  Log Directory:        ${config.telemetry.log_dir}`
  ];

  console.log(renderRail('AgntGuard Operational Dashboard', lines));
}
