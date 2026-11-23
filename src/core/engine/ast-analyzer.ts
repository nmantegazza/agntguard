import os from 'node:os';
import { parse } from 'unbash';
import type { ParsedScript, Word } from 'unbash';
import type {
  AllowRule,
  OperatingMode,
  PathsConfig,
  PolicyDecision,
  RestrictRule,
  RiskDimension,
  SystemPathsConfig
} from '../../types.js';
import { reasonFor } from './reason-catalog.js';
import { evaluatePathPolicy } from './path-policy.js';

export interface AstPathContext {
  cwd?: string;
  userPaths?: PathsConfig;
}

const MAX_EXPANSIONS = 50;

const PROTECTED_ENV_VARS: ReadonlySet<string> = new Set([
  'PATH',
  'HOME',
  'PWD',
  'TMPDIR',
  'IFS',
  'BASH_ENV',
  'ENV',
  'CDPATH'
]);

/**
 * AstAnalyzer: Evaluates `execute_command` using deterministic POSIX AST shell parsing.
 *
 * Algorithm:
 *   Step 0: Parse AST synchronously & Sanity Checks
 *           - Malformed syntax / parse errors fail closed (restrict / opaque)
 *           - Nested command substitution parse errors fail closed (restrict / opaque)
 *   Step 1: Check Restrict Rules (Short-Circuit)
 *           - If any atomic command, redirect target, or composite line matches a restrict rule,
 *             return restrict immediately.
 *   Step 1b: Gate 2: System Protected Path Guard
 *           - Check noAccess paths (restrict sensitive on any candidate match)
 *           - Check readOnly paths (allow pass-through only if Proven Pure Read, otherwise restrict sensitive)
 *   Step 2a: Check Static AST Eligibility for Tier 1 Fast-Allow
 *           - If the AST contains output redirection to files (> file, >> file),
 *             environment prefix assignments (PYTHONPATH=...), unexpanded custom variables ($var),
 *             command substitutions ($(cmd)), arithmetic expansions, dynamic executable names ($CMD),
 *             or execution primitives (eval, source, .), it is ineligible for 0ms fast-allow
 *             -> return null (fall through to Tier 2).
 *   Step 2b: Check Allow Rules (Universal Conjunction)
 *           - If all atomic commands match allow rules, return allow.
 *   Step 3: Unmapped Fallthrough
 *           - If not all atomic commands are covered by allow rules, return null.
 */
export class AstAnalyzer {
  public evaluate(
    payload: string,
    mode: OperatingMode,
    restrictRules: RestrictRule[],
    allowRules: AllowRule[],
    systemPaths: SystemPathsConfig,
    pureReadAllowRules: AllowRule[],
    pathContext?: AstPathContext,
    depth = 0
  ): PolicyDecision | null {
    if (depth > 5) {
      return this.restrictDecision('opaque', mode);
    }
    if (!payload || !payload.trim()) return null;

    // Step 0: Parse AST synchronously
    let ast: ParsedScript;
    try {
      ast = parse(payload);
    } catch {
      return this.restrictDecision('opaque', mode);
    }

    if (ast.errors && ast.errors.length > 0) {
      return this.restrictDecision('opaque', mode);
    }

    // Fail closed on nested script parse errors (e.g. within command substitutions)
    if (this.hasNestedParseErrors(ast)) {
      return this.restrictDecision('opaque', mode);
    }

    const runtimeTmp = os.tmpdir() || '/tmp';
    const tmpCandidates = Array.from(new Set(['/tmp', runtimeTmp]));

    const variables = new Map<string, string[]>([
      ['HOME', [os.homedir()]],
      ['PWD', [pathContext?.cwd || '.']],
      ['TMPDIR', tmpCandidates]
    ]);
    let fastAllowEligible = true;

    // Atomic Command, Redirect & Path Target Extraction
    const atomicCommands: string[] = [];
    const extraCandidates: string[] = [];
    const pathTargets: string[] = [];
    let shellWrapperIneligibleForFastAllow = false;
    let shellWrapperRestrictDecision: PolicyDecision | null = null;

    this.walkAst(ast, (node: any) => {
      // For node
      if (node.type === 'For') {
        const loopVar = (node.name?.value ?? node.name?.text ?? '').trim();
        if (!loopVar || this.isProtectedEnvVar(loopVar) || this.hasDynamicExpansion(node.name)) {
          fastAllowEligible = false;
        }
        if (!node.wordlist) {
          if (loopVar) variables.delete(loopVar);
          fastAllowEligible = false;
        } else {
          const flattenedItems: string[] = [];
          let listResolved = true;
          for (const w of node.wordlist) {
            const res = this.resolveWord(w, variables);
            if (!res.fullyResolved) {
              listResolved = false;
              break;
            }
            flattenedItems.push(...res.values);
            if (flattenedItems.length > MAX_EXPANSIONS) {
              listResolved = false;
              break;
            }
          }
          if (!listResolved || flattenedItems.length > MAX_EXPANSIONS) {
            if (loopVar) variables.delete(loopVar);
            fastAllowEligible = false;
          } else {
            variables.set(loopVar, flattenedItems);
          }
        }
      }

      // Command node
      if (node.type === 'Command') {
        const prefixAssignments: any[] = [];
        const prefixRedirections: any[] = [];
        for (const p of node.prefix ?? []) {
          if (p.type === 'Assignment') {
            prefixAssignments.push(p);
          } else {
            prefixRedirections.push(p);
          }
        }

        if (!node.name) {
          for (const assign of prefixAssignments) {
            this.processAssignment(assign, variables, () => {
              fastAllowEligible = false;
            });
          }
        } else {
          if (prefixAssignments.length > 0) {
            fastAllowEligible = false;
          }
          const prefixStrings = prefixAssignments
            .map((p: any) => p.text ?? `${p.name ?? ''}=${p.value?.text ?? p.value ?? ''}`)
            .filter(Boolean);

          const nameRes = this.resolveWord(node.name, variables);
          if (!nameRes.fullyResolved) {
            fastAllowEligible = false;
          }

          const argValueSlots: string[][] = [];
          const isAssignmentArg: boolean[] = [];
          const argFullyResolved: boolean[] = [];
          const rawCmdName = (node.name?.value ?? node.name?.text ?? '').trim();

          const args = node.args ?? [];
          for (let i = 0; i < args.length; i++) {
            const arg = args[i];
            if (arg.type === 'Assignment') {
              fastAllowEligible = false;
              if (rawCmdName !== 'alias') {
                this.processAssignment(arg, variables, () => {
                  fastAllowEligible = false;
                });
              }
              argValueSlots.push([arg.text ?? '']);
              isAssignmentArg.push(true);
              argFullyResolved.push(false);
            } else {
              const argRes = this.resolveWord(arg, variables);
              if (!argRes.fullyResolved) {
                fastAllowEligible = false;
              }
              argValueSlots.push(argRes.values);
              isAssignmentArg.push(false);
              argFullyResolved.push(argRes.fullyResolved);
            }
          }

          let combos = this.cartesianProduct([nameRes.values, ...argValueSlots], MAX_EXPANSIONS);
          if (!combos) {
            fastAllowEligible = false;
            const rawArgs = args.map((arg: any) => {
              if (arg.type === 'Assignment') return arg.text ?? '';
              return arg.value ?? arg.text ?? '';
            });
            combos = [[rawCmdName, ...rawArgs]];
          }

          for (const combo of combos) {
            const expandedName = combo[0]?.trim() ?? '';
            if (!expandedName) continue;
            const expandedArgs = combo.slice(1);

            if (expandedName === 'eval' || expandedName === 'source' || expandedName === '.') {
              fastAllowEligible = false;
            }

            const canonical = [expandedName, ...expandedArgs].join(' ').trim();
            if (prefixStrings.length > 0) {
              extraCandidates.push([...prefixStrings, canonical].join(' '));
            }

            const shellWrapper = this.extractShellWrapperFromArgs(expandedName, expandedArgs);
            if (shellWrapper) {
              extraCandidates.push(canonical);
              const scriptText = shellWrapper.scriptText.trim();
              const innerDecision = this.evaluate(
                scriptText,
                mode,
                restrictRules,
                allowRules,
                systemPaths,
                pureReadAllowRules,
                pathContext,
                depth + 1
              );
              if (innerDecision?.decision === 'restrict') {
                shellWrapperRestrictDecision = innerDecision;
              }

              const scriptSlotResolved =
                shellWrapper.scriptArgIndex >= 0 &&
                shellWrapper.scriptArgIndex < argFullyResolved.length &&
                argFullyResolved[shellWrapper.scriptArgIndex];

              if (!scriptSlotResolved || innerDecision?.decision !== 'allow') {
                shellWrapperIneligibleForFastAllow = true;
                fastAllowEligible = false;
                atomicCommands.push(canonical);
              } else {
                atomicCommands.push(scriptText);
              }
            } else {
              atomicCommands.push(canonical);
              for (let i = 0; i < expandedArgs.length; i++) {
                if (isAssignmentArg[i]) continue;
                const raw = expandedArgs[i].trim();
                if (!raw || /^--?[a-zA-Z0-9_-]+$/.test(raw)) continue;
                const unflagged = raw
                  .replace(/^(?:--?[a-zA-Z0-9_-]+|[a-zA-Z_][a-zA-Z0-9_]*)=/, '')
                  .replace(/^["']|["']$/g, '')
                  .trim();
                if (unflagged) {
                  pathTargets.push(unflagged);
                }
              }
            }
          }
        }
      }

      // Redirect node
      if (node.type === 'Redirect') {
        if (node.descriptor?.type === 'FileDescriptorVariable') {
          fastAllowEligible = false;
        }
        if (node.target) {
          const targetRes = this.resolveWord(node.target, variables);
          if (!targetRes.fullyResolved || targetRes.values.length > MAX_EXPANSIONS) {
            fastAllowEligible = false;
          }
          const targets = targetRes.values.length <= MAX_EXPANSIONS
            ? targetRes.values
            : [(node.target.value ?? node.target.text ?? '').trim()];

          for (const rawTarget of targets) {
            const target = rawTarget.trim();
            if (!target) continue;

            extraCandidates.push(target);
            if (node.operator) {
              extraCandidates.push(`${node.operator} ${target}`);
            }

            const cleanTarget = target.replace(/^["']|["']$/g, '').trim();
            const isDevNull = cleanTarget.toLowerCase() === '/dev/null' || cleanTarget.toLowerCase() === 'nul';
            const op = node.operator ?? '';

            if (!isDevNull && !(op === '>&' && /^\d+$/.test(target))) {
              pathTargets.push(cleanTarget);
            }

            if ((op === '>' || op === '>>' || op === '>|' || op === '&>' || op === '&>>') && !isDevNull) {
              fastAllowEligible = false;
            }
            if (op === '>&' && !/^\d+$/.test(target) && !isDevNull) {
              fastAllowEligible = false;
            }
          }
        }
      }

      // Dynamic & expansion nodes anywhere in AST
      if (
        node.type === 'CommandExpansion' ||
        node.type === 'ArithmeticExpansion' ||
        node.type === 'ProcessSubstitution' ||
        node.type === 'ArithmeticCommand' ||
        node.type === 'ArithmeticFor'
      ) {
        fastAllowEligible = false;
      }

      if (node.type === 'SimpleExpansion') {
        const text = node.text ?? '';
        const varName = text.startsWith('$') ? text.slice(1) : text;
        if (!variables.has(varName)) {
          fastAllowEligible = false;
        }
      }

      if (node.type === 'ParameterExpansion') {
        if (node.prefix || node.index || node.operation || !node.parameter || !variables.has(node.parameter)) {
          fastAllowEligible = false;
        }
      }
    });

    if (shellWrapperRestrictDecision) {
      return shellWrapperRestrictDecision;
    }

    // Step 1: Check Restrict Rules (Short-Circuit)
    // Test normalized atomic commands, raw payload, lines, and redirect targets.
    const candidates = [...atomicCommands, ...extraCandidates];
    if (!candidates.includes(payload)) {
      candidates.push(payload);
    }
    if (payload.includes('\n')) {
      for (const line of payload.split('\n')) {
        const trimmed = line.trim();
        if (trimmed && !candidates.includes(trimmed)) {
          candidates.push(trimmed);
        }
      }
    }

    for (const cmd of candidates) {
      for (const rule of restrictRules) {
        if (this.matches(rule.pattern, cmd)) {
          return {
            decision: 'restrict',
            reason: reasonFor(rule.dimension, mode),
            tierMatched: 'tier1',
            evidence: {
              tier1List: 'restrict',
              tier1Dimension: rule.dimension,
              tier1Pattern: rule.pattern,
              mode
            }
          };
        }
      }
    }

    // Step 1b: Gate 2: Unified Path Policy & Workspace Boundary
    const isPureRead =
      !shellWrapperIneligibleForFastAllow &&
      this.isProvenPureRead(atomicCommands, pureReadAllowRules, fastAllowEligible);

    const pathDecision = evaluatePathPolicy({
      targets: pathTargets,
      isShellToken: true,
      isProvenPureRead: isPureRead,
      mode,
      systemPaths,
      userPaths: pathContext?.userPaths,
      cwd: pathContext?.cwd
    });
    if (pathDecision) {
      return pathDecision;
    }

    if (atomicCommands.length === 0) {
      return null;
    }

    // Step 2a: Check Static AST Eligibility for Tier 1 Fast-Allow
    if (shellWrapperIneligibleForFastAllow || !fastAllowEligible) {
      return null;
    }

    // Step 2b: Check Allow Rules (Universal Conjunction)
    const matchedPatterns: string[] = [];
    for (const cmd of atomicCommands) {
      let matchedRule: AllowRule | undefined;
      for (const rule of allowRules) {
        if (this.matches(rule.pattern, cmd)) {
          matchedRule = rule;
          break;
        }
      }
      if (!matchedRule) {
        // Step 3: At least one command is not covered by allow rules -> fall through
        return null;
      }
      matchedPatterns.push(matchedRule.pattern);
    }

    const patternEvidence = matchedPatterns.length === 1
      ? matchedPatterns[0]
      : matchedPatterns.join('; ');

    return {
      decision: 'allow',
      reason: `Permitted by Tier 1 allow pattern: ${matchedPatterns[0]}`,
      tierMatched: 'tier1',
      evidence: {
        tier1List: 'allow',
        tier1Pattern: patternEvidence,
        mode
      }
    };
  }

  private isProtectedEnvVar(name: string): boolean {
    return PROTECTED_ENV_VARS.has(name) || name.startsWith('LD_') || name.startsWith('DYLD_');
  }

  private resolveParts(
    parts: any[],
    variables: ReadonlyMap<string, string[]>,
    originalWord?: Word
  ): { values: string[]; fullyResolved: boolean } {
    let combinations: string[] = [''];
    let fullyResolved = true;

    for (const part of parts) {
      let partValues: string[];
      let partResolved = true;

      if (part.type === 'Literal' || part.type === 'SingleQuoted' || part.type === 'AnsiCQuoted') {
        partValues = [part.value ?? part.text ?? ''];
      } else if (part.type === 'DoubleQuoted' || part.type === 'LocaleString') {
        if (part.parts && Array.isArray(part.parts) && part.parts.length > 0) {
          const inner = this.resolveParts(part.parts, variables, originalWord);
          partValues = inner.values;
          if (!inner.fullyResolved) {
            partResolved = false;
          }
        } else {
          partValues = [part.value ?? ''];
        }
      } else if (part.type === 'SimpleExpansion') {
        const text = part.text ?? '';
        const varName = text.startsWith('$') ? text.slice(1) : text;
        const val = variables.get(varName);
        if (val !== undefined && val.length > 0) {
          partValues = val;
        } else {
          partResolved = false;
          partValues = [text];
        }
      } else if (part.type === 'ParameterExpansion') {
        const isBare = !part.prefix && !part.index && !part.operation && Boolean(part.parameter);
        const val = isBare ? variables.get(part.parameter) : undefined;
        if (isBare && val !== undefined && val.length > 0) {
          partValues = val;
        } else {
          partResolved = false;
          partValues = [part.text ?? ''];
        }
      } else if (
        part.type === 'CommandExpansion' ||
        part.type === 'ArithmeticExpansion' ||
        part.type === 'ProcessSubstitution'
      ) {
        partResolved = false;
        partValues = [part.text ?? ''];
      } else if (part.type === 'ExtendedGlob' || part.type === 'BraceExpansion') {
        let hasExp = false;
        if (part.parts) {
          this.walkAst(part.parts, (n: any) => {
            if (
              n.type === 'SimpleExpansion' ||
              n.type === 'ParameterExpansion' ||
              n.type === 'CommandExpansion' ||
              n.type === 'ArithmeticExpansion' ||
              n.type === 'ProcessSubstitution'
            ) {
              hasExp = true;
            }
          });
        }
        if (hasExp) {
          partResolved = false;
        }
        partValues = [part.text ?? ''];
      } else {
        partValues = [part.value ?? part.text ?? ''];
      }

      if (!partResolved) {
        fullyResolved = false;
      }

      if (combinations.length * partValues.length > MAX_EXPANSIONS) {
        return {
          values: [originalWord?.value ?? originalWord?.text ?? ''],
          fullyResolved: false
        };
      }

      const nextCombinations: string[] = [];
      for (const prefix of combinations) {
        for (const val of partValues) {
          nextCombinations.push(prefix + val);
        }
      }
      combinations = nextCombinations;
    }

    return { values: combinations, fullyResolved };
  }

  private resolveWord(
    word: Word | undefined,
    variables: ReadonlyMap<string, string[]>
  ): { values: string[]; fullyResolved: boolean } {
    if (!word) {
      return { values: [''], fullyResolved: true };
    }
    const parts = (word as any).parts;
    if (!parts || !Array.isArray(parts) || parts.length === 0) {
      return { values: [word.value ?? word.text ?? ''], fullyResolved: true };
    }
    return this.resolveParts(parts, variables, word);
  }

  private processAssignment(
    assignment: any,
    variables: Map<string, string[]>,
    markIneligible: () => void
  ): void {
    const name = assignment.name ?? '';
    if (!name) {
      markIneligible();
      return;
    }

    if (this.isProtectedEnvVar(name)) {
      markIneligible();
    }

    if (
      assignment.append ||
      assignment.index ||
      !assignment.value ||
      assignment.value.type === 'ArrayValue'
    ) {
      variables.delete(name);
      markIneligible();
      return;
    }

    const resolved = this.resolveWord(assignment.value, variables);
    if (!resolved.fullyResolved || resolved.values.length > MAX_EXPANSIONS) {
      variables.delete(name);
      markIneligible();
    } else {
      variables.set(name, resolved.values);
    }
  }

  private cartesianProduct(arrays: string[][], maxLimit: number): string[][] | null {
    let result: string[][] = [[]];
    for (const arr of arrays) {
      if (arr.length === 0) continue;
      if (result.length * arr.length > maxLimit) {
        return null;
      }
      const next: string[][] = [];
      for (const prefix of result) {
        for (const item of arr) {
          next.push([...prefix, item]);
        }
      }
      result = next;
    }
    return result;
  }

  private extractShellWrapperFromArgs(
    expandedName: string,
    expandedArgs: string[]
  ): { scriptText: string; scriptArgIndex: number } | null {
    const baseName = expandedName.replace(/\\/g, '').replace(/^.*[/\\]/, '');
    if (baseName !== 'sh' && baseName !== 'bash' && baseName !== 'zsh' && baseName !== 'dash' && baseName !== 'ksh') {
      return null;
    }
    for (let i = 0; i < expandedArgs.length; i++) {
      const text = expandedArgs[i].trim();
      if (text === '--') break;
      if (!text.startsWith('-') || text === '-') break;
      if (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(text)) {
        if (i + 1 < expandedArgs.length) {
          return { scriptText: expandedArgs[i + 1], scriptArgIndex: i + 1 };
        }
        return null;
      }
    }
    return null;
  }

  private restrictDecision(dimension: RiskDimension, mode: OperatingMode): PolicyDecision {
    return {
      decision: 'restrict',
      reason: reasonFor(dimension, mode),
      tierMatched: 'tier1',
      evidence: {
        tier1List: 'restrict',
        tier1Dimension: dimension,
        mode
      }
    };
  }

  private hasNestedParseErrors(ast: ParsedScript): boolean {
    let hasError = false;
    this.walkAst(ast, (node: any) => {
      if (hasError) return;
      if (node.script?.errors && node.script.errors.length > 0) {
        hasError = true;
      }
    });
    return hasError;
  }

  private isProvenPureRead(
    atomicCommands: string[],
    pureReadAllowRules: AllowRule[],
    fastAllowEligible: boolean
  ): boolean {
    if (!fastAllowEligible || atomicCommands.length === 0) {
      return false;
    }
    for (const cmd of atomicCommands) {
      let matched = false;
      for (const rule of pureReadAllowRules) {
        if (this.matches(rule.pattern, cmd)) {
          matched = true;
          break;
        }
      }
      if (!matched) {
        return false;
      }
    }
    return true;
  }

  private hasDynamicExpansion(word?: Word): boolean {
    if (!word) return false;
    const text = word.text ?? '';
    const val = word.value ?? '';
    if (text.startsWith('$') || val.startsWith('$')) return true;

    let dynamic = false;
    this.walkAst(word, (n: any) => {
      if (
        n.type === 'SimpleExpansion' ||
        n.type === 'ParameterExpansion' ||
        n.type === 'CommandExpansion' ||
        n.type === 'ArithmeticExpansion' ||
        n.type === 'ProcessSubstitution'
      ) {
        dynamic = true;
      }
    });
    return dynamic;
  }

  private walkAst(node: unknown, visitor: (node: any) => void): void {
    if (!node) return;
    if (Array.isArray(node)) {
      for (const item of node) this.walkAst(item, visitor);
      return;
    }
    if (typeof node !== 'object') return;

    visitor(node);

    const obj = node as Record<string, any>;

    if ('parts' in obj && Array.isArray(obj.parts)) {
      for (const part of obj.parts) {
        this.walkAst(part, visitor);
      }
    }

    if ('script' in obj && obj.script) {
      this.walkAst(obj.script, visitor);
    }

    if (obj.type === 'Assignment') {
      if (obj.index) this.walkAst(obj.index, visitor);
      if (obj.value) this.walkAst(obj.value, visitor);
    } else if (obj.type === 'ArrayValue') {
      if (obj.elements) this.walkAst(obj.elements, visitor);
    } else if (obj.type === 'ArithmeticCommand') {
      if (obj.expression) this.walkAst(obj.expression, visitor);
    } else if (obj.type === 'ArithmeticFor') {
      if (obj.initialize) this.walkAst(obj.initialize, visitor);
      if (obj.test) this.walkAst(obj.test, visitor);
      if (obj.update) this.walkAst(obj.update, visitor);
    }

    for (const key of Object.keys(obj)) {
      if (key === 'parts' || key === 'script' || key === 'parent') continue;
      this.walkAst(obj[key], visitor);
    }
  }

  private matches(pattern: string, target: string): boolean {
    try {
      return new RegExp(pattern).test(target);
    } catch {
      return false;
    }
  }
}
