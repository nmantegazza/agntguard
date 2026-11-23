import type { Scenario } from './scenario.js';
import type { Tier2State } from '../../types.js';

/**
 * Pluggable component that translates an uncompressed scenario fixture
 * (transcript, intercepted action, environment) into a policy input state.
 */
export interface StateProjector {
  readonly name: string;
  project(scenario: Scenario): Tier2State;
}
