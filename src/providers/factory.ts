import type { DecisionProvider, Tier2Config } from '../types.js';
import { TypeSafeProvider } from './typesafe-provider.js';
import { MockProvider } from './mock-provider.js';

export function createProvider(config?: Tier2Config): DecisionProvider | undefined {
  if (!config) {
    return undefined;
  }

  switch (config.provider) {
    case 'mock':
      return new MockProvider();
    case 'typesafe':
    default:
      return new TypeSafeProvider({ model: config.model });
  }
}