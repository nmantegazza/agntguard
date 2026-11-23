import * as p from '@clack/prompts';
import { loadConfig, saveConfig, getDefaultConfigPath } from '../../config.js';
import { SYSTEM_RESTRICT_RULES, SYSTEM_ALLOW_RULES, SYSTEM_PATHS } from '../../core/defaults/system-rules.js';
import { RestrictRule, RiskDimension } from '../../types.js';
import { badgeScope, getColors } from '../theme.js';

export async function handleRuleCommand(
  subcommand: string | undefined,
  positional: string[],
  flags: Record<string, string | boolean>
): Promise<void> {
  const action = subcommand || 'list';

  switch (action) {
    case 'list': {
      const config = loadConfig();
      const configPath = getDefaultConfigPath();
      const toolFilter = (flags.tool as string) || undefined;
      const showSystem = flags.system === true;

      const formatRestrict = (r: RestrictRule) => {
        return r.dimension ? `${r.pattern} [Dimension: ${r.dimension}]` : r.pattern;
      };

      console.log(`Active Config: ${configPath}`);
      console.log(`Operating Mode: ${config.mode || 'auto'}\n`);
      console.log('=== Rules ===\n');

      const tools = new Set<string>();
      if (toolFilter) {
        tools.add(toolFilter);
      } else {
        for (const r of SYSTEM_RESTRICT_RULES) if (r.tool) tools.add(r.tool);
        for (const r of SYSTEM_ALLOW_RULES) if (r.tool) tools.add(r.tool);
        for (const r of config.rules?.restrict || []) if (r.tool) tools.add(r.tool);
        for (const r of config.rules?.allow || []) if (r.tool) tools.add(r.tool);
      }

      for (const tool of tools) {
        console.log(`Tool: ${tool}`);
        console.log('  RESTRICT Patterns:');
        const sysRestricts = SYSTEM_RESTRICT_RULES.filter((r) => r.tool === tool);
        const usrRestricts = (config.rules?.restrict || []).filter((r) => r.tool === tool);

        if (showSystem) {
          let idx = 1;
          for (const r of sysRestricts) {
            console.log(`    ${idx++}. ${badgeScope('system')} ${formatRestrict(r)}`);
          }
        } else if (sysRestricts.length > 0) {
          console.log(`    ${badgeScope('system')} ${sysRestricts.length} built-in patterns active (--system to expand)`);
        }

        let uIdx = 1;
        for (const r of usrRestricts) {
          console.log(`    ${uIdx++}. ${badgeScope('user')} ${formatRestrict(r)}`);
        }

        console.log('  ALLOW Patterns:');
        const sysAllows = SYSTEM_ALLOW_RULES.filter((r) => r.tool === tool);
        const usrAllows = (config.rules?.allow || []).filter((r) => r.tool === tool);

        if (showSystem) {
          let idx = 1;
          for (const r of sysAllows) {
            console.log(`    ${idx++}. ${badgeScope('system')} ${r.pattern}`);
          }
        } else if (sysAllows.length > 0) {
          console.log(`    ${badgeScope('system')} ${sysAllows.length} built-in patterns active (--system to expand)`);
        }

        let aIdx = 1;
        for (const r of usrAllows) {
          console.log(`    ${aIdx++}. ${badgeScope('user')} ${r.pattern}`);
        }
        console.log('');
      }
      break;
    }

    case 'add': {
      let listName = (flags.list as 'allow' | 'restrict') || (positional[0] as 'allow' | 'restrict');
      let pattern = (flags.pattern as string) || positional[1];
      let tool = (flags.tool as string) || 'execute_command';
      let dimension = flags.dimension as RiskDimension | undefined;

      if (!listName || !pattern) {
        if (!process.stdout.isTTY) {
          if (!listName || !['allow', 'restrict'].includes(listName)) {
            console.error('Error: Valid --list <allow|restrict> is required');
          } else {
            console.error('Error: --pattern <regex> is required');
          }
          process.exit(1);
        }

        if (!listName) {
          const selectedList = await p.select({
            message: 'Select rule list:',
            options: [
              { value: 'restrict', label: 'restrict' },
              { value: 'allow', label: 'allow' }
            ]
          });
          if (p.isCancel(selectedList)) {
            p.cancel('Operation cancelled.');
            process.exit(0);
          }
          listName = selectedList as 'allow' | 'restrict';
        }

        const selectedTool = await p.text({
          message: 'Target tool:',
          defaultValue: 'execute_command',
          placeholder: 'execute_command'
        });
        if (p.isCancel(selectedTool)) {
          p.cancel('Operation cancelled.');
          process.exit(0);
        }
        tool = String(selectedTool).trim() || 'execute_command';

        const enteredPattern = await p.text({
          message: 'Regex pattern:'
        });
        if (p.isCancel(enteredPattern)) {
          p.cancel('Operation cancelled.');
          process.exit(0);
        }
        pattern = String(enteredPattern).trim();

        if (listName === 'restrict') {
          const selectedDim = await p.select({
            message: 'Risk dimension (optional):',
            options: [
              { value: '', label: 'none' },
              { value: 'harmful', label: 'harmful' },
              { value: 'sensitive', label: 'sensitive' },
              { value: 'opaque', label: 'opaque' },
              { value: 'external', label: 'external' }
            ]
          });
          if (p.isCancel(selectedDim)) {
            p.cancel('Operation cancelled.');
            process.exit(0);
          }
          dimension = selectedDim ? (String(selectedDim) as RiskDimension) : undefined;
        }
      }

      if (!listName || !['allow', 'restrict'].includes(listName)) {
        console.error('Error: Valid --list <allow|restrict> is required');
        process.exit(1);
      }
      if (!pattern) {
        console.error('Error: --pattern <regex> is required');
        process.exit(1);
      }

      try {
        new RegExp(pattern);
      } catch (e: any) {
        console.error(`Error: Invalid regex pattern "${pattern}": ${e.message}`);
        process.exit(1);
      }

      if (dimension && !['harmful', 'sensitive', 'opaque', 'external'].includes(dimension)) {
        console.error(`Error: Invalid risk dimension "${dimension}". Valid options: harmful, sensitive, opaque, external`);
        process.exit(1);
      }

      const config = loadConfig();
      if (!config.rules) {
        config.rules = { restrict: [], allow: [] };
      }
      if (!Array.isArray(config.rules[listName])) {
        config.rules[listName] = [];
      }

      const exists = config.rules[listName].some((r: any) => r.tool === tool && r.pattern === pattern);
      if (!exists) {
        if (listName === 'restrict') {
          const newEntry: RestrictRule = { tool, pattern, ...(dimension ? { dimension } : {}) };
          config.rules.restrict.push(newEntry);
        } else {
          config.rules.allow.push({ tool, pattern });
        }
        saveConfig(config);
        console.log(`Added pattern to [${listName}] (${tool}): ${pattern}`);
      } else {
        console.log(`Pattern already exists in [${listName}] (${tool}): ${pattern}`);
      }
      break;
    }

    case 'remove': {
      let listName = (flags.list as 'allow' | 'restrict') || (positional[0] as 'allow' | 'restrict');
      let pattern = (flags.pattern as string) || positional[1];
      let tool = (flags.tool as string) || 'execute_command';

      const config = loadConfig();
      if (!config.rules || !Array.isArray(config.rules[listName])) {
        if (config.rules) config.rules[listName] = [];
        else config.rules = { restrict: [], allow: [] };
      }

      if (!listName || !pattern) {
        if (!process.stdout.isTTY) {
          if (!listName || !['allow', 'restrict'].includes(listName)) {
            console.error('Error: Valid --list <allow|restrict> is required');
          } else {
            console.error('Error: --pattern <regex> is required');
          }
          process.exit(1);
        }

        const userRules = [
          ...(config.rules.restrict || []).map((r) => ({ list: 'restrict', ...r })),
          ...(config.rules.allow || []).map((r) => ({ list: 'allow', ...r }))
        ];

        if (userRules.length === 0) {
          console.log('No user rules found to remove.');
          return;
        }

        const selected = await p.select({
          message: 'Select user rule to remove:',
          options: userRules.map((r) => ({
            value: JSON.stringify({ list: r.list, tool: r.tool, pattern: r.pattern }),
            label: `[${r.list}] (${r.tool}): ${r.pattern}`
          }))
        });

        if (p.isCancel(selected)) {
          p.cancel('Operation cancelled.');
          process.exit(0);
        }

        const parsed = JSON.parse(String(selected));
        listName = parsed.list;
        tool = parsed.tool;
        pattern = parsed.pattern;
      }

      if (!listName || !['allow', 'restrict'].includes(listName)) {
        console.error('Error: Valid --list <allow|restrict> is required');
        process.exit(1);
      }
      if (!pattern) {
        console.error('Error: --pattern <regex> is required');
        process.exit(1);
      }

      const initialLength = config.rules[listName].length;
      config.rules[listName] = (config.rules[listName] as any[]).filter(
        (r) => !(r.tool === tool && r.pattern === pattern)
      );

      if (config.rules[listName].length < initialLength) {
        saveConfig(config);
        console.log(`Removed pattern from [${listName}] (${tool}): ${pattern}`);
        break;
      }

      // Check system rules
      const systemList = listName === 'restrict' ? SYSTEM_RESTRICT_RULES : SYSTEM_ALLOW_RULES;
      const isSystemRule = systemList.some((r) => r.tool === tool && r.pattern === pattern);
      const isSystemPath =
        SYSTEM_PATHS.noAccess.includes(pattern) ||
        SYSTEM_PATHS.readOnly.includes(pattern) ||
        SYSTEM_PATHS.allowed.includes(pattern);
      if (isSystemRule || isSystemPath) {
        console.error(`Cannot remove system rule "${pattern}". System rules are built-in security guardrails and cannot be deleted.`);
        process.exit(1);
      }

      console.log(`Pattern not found in [${listName}] (${tool}): ${pattern}`);
      break;
    }

    default:
      console.error(`Error: Unknown rule subcommand "${action}". Use list, add, or remove.`);
      process.exit(1);
  }
}
