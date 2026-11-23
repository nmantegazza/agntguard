import * as p from '@clack/prompts';
import {
  AgentName,
  SUPPORTED_AGENTS,
  detectAgents,
  enableAgent,
  disableAgent,
  inspectHealth
} from '../agents/registry.js';

export async function handleEnableCommand(
  positional: string[],
  flags: Record<string, string | boolean>
): Promise<void> {
  let targets: AgentName[] = [];

  if (flags.all === true) {
    const detected = detectAgents();
    targets = detected.length > 0 ? detected : [...SUPPORTED_AGENTS];
  } else if (positional.length > 0) {
    for (const name of positional) {
      if (!SUPPORTED_AGENTS.includes(name as AgentName)) {
        console.error(`Error: Unsupported agent "${name}". Supported agents: ${SUPPORTED_AGENTS.join(', ')}`);
        process.exit(1);
      }
      targets.push(name as AgentName);
    }
  } else {
    if (!process.stdout.isTTY) {
      console.error(
        `Error: Specify agent name(s) or --all in non-interactive environments. Usage: agntguard enable [agent...] [--all]`
      );
      process.exit(1);
    }

    const detected = detectAgents();
    const selected = await p.multiselect({
      message: 'Select coding agents to protect with AgntGuard:',
      options: SUPPORTED_AGENTS.map((agent) => ({
        value: agent,
        label: agent,
        hint: detected.includes(agent) ? 'detected on system' : undefined
      })),
      initialValues: detected
    });

    if (p.isCancel(selected)) {
      p.cancel('Operation cancelled.');
      process.exit(0);
    }

    targets = selected as AgentName[];
  }

  if (targets.length === 0) {
    console.log('No agents selected to enable.');
    return;
  }

  for (const agent of targets) {
    try {
      enableAgent(agent);
      console.log(`Enabled AgntGuard hook for ${agent}.`);
    } catch (err: any) {
      console.error(`Failed to enable ${agent}: ${err.message}`);
      process.exit(1);
    }
  }
}

export async function handleDisableCommand(
  positional: string[],
  flags: Record<string, string | boolean>
): Promise<void> {
  let targets: AgentName[] = [];

  if (flags.all === true) {
    targets = [...SUPPORTED_AGENTS];
  } else if (positional.length > 0) {
    for (const name of positional) {
      if (!SUPPORTED_AGENTS.includes(name as AgentName)) {
        console.error(`Error: Unsupported agent "${name}". Supported agents: ${SUPPORTED_AGENTS.join(', ')}`);
        process.exit(1);
      }
      targets.push(name as AgentName);
    }
  } else {
    if (!process.stdout.isTTY) {
      console.error(
        `Error: Specify agent name(s) or --all in non-interactive environments. Usage: agntguard disable [agent...] [--all]`
      );
      process.exit(1);
    }

    const health = inspectHealth();
    const enabledAgents = (Object.keys(health) as AgentName[]).filter(
      (name) => health[name].status === 'enabled' || health[name].status === 'broken'
    );

    if (enabledAgents.length === 0) {
      console.log('No agents currently enabled to disable.');
      return;
    }

    const selected = await p.multiselect({
      message: 'Select coding agents to detach from AgntGuard:',
      options: enabledAgents.map((agent) => ({
        value: agent,
        label: agent
      }))
    });

    if (p.isCancel(selected)) {
      p.cancel('Operation cancelled.');
      process.exit(0);
    }

    targets = selected as AgentName[];
  }

  if (targets.length === 0) {
    console.log('No agents selected to disable.');
    return;
  }

  for (const agent of targets) {
    try {
      disableAgent(agent);
      console.log(`Disabled AgntGuard hook for ${agent}.`);
    } catch (err: any) {
      console.error(`Failed to disable ${agent}: ${err.message}`);
      process.exit(1);
    }
  }
}
