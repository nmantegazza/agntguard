import * as p from '@clack/prompts';
import { loadConfig, saveConfig } from '../../config.js';
import { loadApiKey, saveApiKey } from '../../credentials.js';
import { OperatingMode } from '../../types.js';
import {
  AgentName,
  SUPPORTED_AGENTS,
  detectAgents,
  enableAgent,
  disableAgent,
  inspectHealth
} from '../agents/registry.js';
import { getColors } from '../theme.js';

export interface InitFlowOptions {
  agents: AgentName[];
  mode: OperatingMode;
  apiKey?: string;
}

export function executeInitFlow(options: InitFlowOptions): void {
  const config = loadConfig();
  const existingApiKey = loadApiKey();

  // 1. Update mode
  config.mode = options.mode;

  // 2. Handle API Key & Tier 2 status
  const keyToSave = options.apiKey?.trim();
  if (keyToSave) {
    saveApiKey(keyToSave);
    config.tier2.enabled = true;
  } else if (existingApiKey) {
    config.tier2.enabled = true;
  } else {
    config.tier2.enabled = false;
  }

  saveConfig(config);

  // 3. Synchronize agent integrations
  const currentHealth = inspectHealth();
  for (const agent of SUPPORTED_AGENTS) {
    if (options.agents.includes(agent)) {
      enableAgent(agent);
    } else if (currentHealth[agent].status === 'enabled') {
      disableAgent(agent);
    }
  }
}

export async function handleInitCommand(): Promise<void> {
  const c = getColors();

  if (!process.stdout.isTTY) {
    console.error(
      'Error: agntguard init requires an interactive terminal. Use agntguard enable <agent> to configure non-interactively.'
    );
    process.exit(1);
  }

  p.intro(c.cyan('Welcome to AgntGuard — Centralized Coding Agent Permission Engine'));

  const detected = detectAgents();
  const existingConfig = loadConfig();
  const existingApiKey = loadApiKey();

  // Step 1: Agent selection
  const selectedAgents = await p.multiselect({
    message: 'Step 1 of 3: Select coding agents to protect with AgntGuard:',
    options: SUPPORTED_AGENTS.map((agent) => ({
      value: agent,
      label: agent,
      hint: detected.includes(agent) ? 'detected on system' : undefined
    })),
    initialValues: detected
  });

  if (p.isCancel(selectedAgents)) {
    p.cancel('Setup cancelled.');
    process.exit(0);
  }

  // Step 2: Mode selection
  const selectedMode = await p.select({
    message: 'Step 2 of 3: Choose default restriction enforcement mode:',
    options: [
      {
        value: 'auto',
        label: 'auto',
        hint: 'Block restricted actions automatically (recommended for unattended agents)'
      },
      {
        value: 'ask',
        label: 'ask',
        hint: 'Prompt for user confirmation before blocking'
      }
    ],
    initialValue: existingConfig.mode || 'auto'
  });

  if (p.isCancel(selectedMode)) {
    p.cancel('Setup cancelled.');
    process.exit(0);
  }

  // Step 3: Tier 2 API Key
  const keyPrompt = existingApiKey
    ? 'Step 3 of 3: TypeSafe AI API key (Tier 2) [Press Enter to keep existing]:'
    : 'Step 3 of 3: Enter TypeSafe AI API key (Tier 2 risk scoring) [Press Enter to skip]:';

  const enteredKey = await p.password({
    message: keyPrompt
  });

  if (p.isCancel(enteredKey)) {
    p.cancel('Setup cancelled.');
    process.exit(0);
  }

  const apiKeyVal = enteredKey ? String(enteredKey).trim() : undefined;

  executeInitFlow({
    agents: selectedAgents as AgentName[],
    mode: selectedMode as OperatingMode,
    apiKey: apiKeyVal
  });

  const enabledList = (selectedAgents as AgentName[]).join(', ') || 'none';
  p.note(
    `Operating Mode:   ${selectedMode}\n` +
      `Protected Agents: ${enabledList}\n` +
      `Tier 2 AI Guard:  ${apiKeyVal || existingApiKey ? 'Enabled (TypeSafe jev-latest)' : 'Disabled'}`,
    'AgntGuard Posture Summary'
  );

  p.outro(c.green('AgntGuard setup successfully completed! Run "agntguard status" to inspect your dashboard.'));
}
