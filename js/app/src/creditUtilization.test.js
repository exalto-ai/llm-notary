import { describe, expect, test } from 'vitest';
import { aggregateDailyDebits, loadRecentDebits } from './creditUtilization';

const NOW = Date.UTC(2026, 7, 9, 18, 30);
const TODAY = Date.UTC(2026, 7, 9);
const DAY_MS = 86_400_000;

function entry({ daysAgo = 0, bytes, kind = 'debit', milliseconds = false }) {
  const timestamp = TODAY - daysAgo * DAY_MS + 43_200_000;
  return {
    id: `${kind}-${daysAgo}-${bytes}`,
    kind,
    amount_bytes: bytes,
    created_at: milliseconds ? timestamp : timestamp / 1000,
    display_label: 'Test entry',
  };
}

describe('daily credit utilization', () => {
  test('returns seven consecutive UTC days including zero-usage days', () => {
    const result = aggregateDailyDebits([], NOW);

    expect(result).toHaveLength(7);
    expect(result[0].timestamp).toBe(TODAY - 6 * DAY_MS);
    expect(result[6].timestamp).toBe(TODAY);
    expect(result.every((day) => day.mb === 0)).toBe(true);
  });

  test('aggregates same-day debits in decimal megabytes', () => {
    const result = aggregateDailyDebits([
      entry({ daysAgo: 2, bytes: 250_000 }),
      entry({ daysAgo: 2, bytes: 750_000 }),
    ], NOW);

    expect(result.find((day) => day.timestamp === TODAY - 2 * DAY_MS)?.mb).toBe(1);
  });

  test('uses UTC calendar boundaries', () => {
    const justBeforeUtcMidnight = Date.UTC(2026, 7, 8, 23, 59, 59) / 1000;
    const justAfterUtcMidnight = Date.UTC(2026, 7, 9, 0, 0, 1) / 1000;
    const result = aggregateDailyDebits([
      { ...entry({ bytes: 400_000 }), created_at: justBeforeUtcMidnight },
      { ...entry({ bytes: 600_000 }), created_at: justAfterUtcMidnight },
    ], NOW);

    expect(result.find((day) => day.timestamp === TODAY - DAY_MS)?.mb).toBe(0.4);
    expect(result.find((day) => day.timestamp === TODAY)?.mb).toBe(0.6);
  });

  test('accepts API seconds and browser millisecond timestamps', () => {
    const result = aggregateDailyDebits([
      entry({ daysAgo: 1, bytes: 500_000 }),
      entry({ daysAgo: 4, bytes: 250_000, milliseconds: true }),
    ], NOW);

    expect(result.find((day) => day.timestamp === TODAY - DAY_MS)?.mb).toBe(0.5);
    expect(result.find((day) => day.timestamp === TODAY - 4 * DAY_MS)?.mb).toBe(0.25);
  });

  test('ignores grants, invalid values, and entries outside the window', () => {
    const result = aggregateDailyDebits([
      entry({ bytes: 9_000_000, kind: 'grant' }),
      entry({ daysAgo: 7, bytes: 1_000_000 }),
      { ...entry({ bytes: 1_000_000 }), amount_bytes: Number.NaN },
    ], NOW);

    expect(result.every((day) => day.mb === 0)).toBe(true);
  });

  test('treats a signed debit amount as utilization', () => {
    const result = aggregateDailyDebits([entry({ bytes: -125_000 })], NOW);
    expect(result[6].mb).toBe(0.125);
  });

  test('loads paginated history until it crosses the seven-day boundary', async () => {
    const requests = [];
    const pages = [
      { items: [entry({ bytes: 500_000 }), entry({ kind: 'grant', bytes: 2_000_000 })], next_cursor: 'page-2' },
      { items: [entry({ daysAgo: 3, bytes: 250_000 }), entry({ daysAgo: 7, bytes: 1_000_000 })], next_cursor: 'page-3' },
    ];
    const result = await loadRecentDebits(async (options) => {
      requests.push(options);
      return pages[requests.length - 1];
    }, NOW);

    expect(requests).toEqual([{ limit: 100 }, { limit: 100, cursor: 'page-2' }]);
    expect(result.map(({ amount_bytes }) => amount_bytes)).toEqual([500_000, 250_000]);
  });
});
