import { describe, expect, test } from 'vitest';
import { formatNotaryBoundary } from './notaryLifecycle';

describe('formatNotaryBoundary', () => {
  test('renders a zero lower bound semantically', () => {
    expect(formatNotaryBoundary(0, { kind: 'lower' })).toBe('No lower bound configured');
  });

  test('keeps absent cutoffs distinct from lower bounds', () => {
    expect(formatNotaryBoundary(null)).toBe('No cutoff configured');
    expect(formatNotaryBoundary(null, { kind: 'lower', missingLabel: 'Not defined locally' })).toBe(
      'Not defined locally',
    );
  });

  test('formats real timestamps in the requested timezone', () => {
    expect(
      formatNotaryBoundary(Date.UTC(2026, 0, 1, 12), {
        kind: 'lower',
        locales: 'en-US',
        timeZone: 'America/Los_Angeles',
      }),
    ).toBe('Jan 1, 2026, 4:00 AM');
  });
});
