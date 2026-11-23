import type { CanonicalContext, DecisionProvider, Tier2Category } from '../types.js';

export class MockProvider implements DecisionProvider {
  public readonly name = 'mock';
  private category: Tier2Category;
  private delayMs: number;
  private shouldFail: boolean;

  constructor(category: Tier2Category = 'safe', delayMs: number = 0, shouldFail: boolean = false) {
    this.category = category;
    this.delayMs = delayMs;
    this.shouldFail = shouldFail;
  }

  public setCategory(category: Tier2Category): void {
    this.category = category;
  }

  public async evaluate(_context: CanonicalContext, _signal?: AbortSignal): Promise<Tier2Category> {
    if (this.delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    }
    if (this.shouldFail) {
      throw new Error('MockProvider forced failure');
    }
    return this.category;
  }
}
