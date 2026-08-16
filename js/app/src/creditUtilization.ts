const BYTES_PER_MB = 1_000_000;
const DAY_MS = 86_400_000;
const UTILIZATION_DAYS = 30;

export interface CreditHistoryEntry {
  amount_bytes: number;
  created_at: number;
  credit_kind: string;
  kind: string;
}

interface CreditHistoryPage {
  items: CreditHistoryEntry[];
  next_cursor?: string | null;
}

interface CreditHistoryPageOptions {
  cursor?: string;
  limit: number;
}

export interface DailyDebit {
  bytes: number;
  key: string;
  mb: number;
  timestamp: number;
}

function utcDayStart(timestamp: number): number {
  const date = new Date(timestamp);
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
}

function entryTimestampMs(entry: CreditHistoryEntry): number | null {
  if (!Number.isFinite(entry.created_at)) return null;
  return entry.created_at >= 1e12 ? entry.created_at : entry.created_at * 1000;
}

export async function loadRecentDebits(
  loadPage: (options: CreditHistoryPageOptions) => Promise<CreditHistoryPage>,
  now = Date.now(),
  cancelled = () => false,
): Promise<CreditHistoryEntry[] | null> {
  const cutoff = utcDayStart(now) - (UTILIZATION_DAYS - 1) * DAY_MS;
  const entries: CreditHistoryEntry[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;

  while (!cancelled()) {
    const page = await loadPage({ limit: 100, ...(cursor ? { cursor } : {}) });
    if (cancelled()) return null;
    for (const entry of page.items) {
      const createdAt = entryTimestampMs(entry);
      if (
        entry.kind === 'debit' &&
        entry.credit_kind === 'notarization' &&
        createdAt !== null &&
        createdAt >= cutoff
      )
        entries.push(entry);
    }

    const oldest = page.items.length ? entryTimestampMs(page.items[page.items.length - 1]) : null;
    if (!page.next_cursor || page.items.length === 0 || (oldest !== null && oldest < cutoff)) break;
    if (seenCursors.has(page.next_cursor))
      throw new Error('Credit history pagination repeated a cursor.');
    seenCursors.add(page.next_cursor);
    cursor = page.next_cursor;
  }

  return entries;
}

export function aggregateDailyDebits(
  debitEntries: CreditHistoryEntry[] | null,
  now = Date.now(),
): DailyDebit[] {
  const today = utcDayStart(now);
  const days = Array.from({ length: UTILIZATION_DAYS }, (_, index) => {
    const timestamp = today - (UTILIZATION_DAYS - 1 - index) * DAY_MS;
    return {
      key: new Date(timestamp).toISOString().slice(0, 10),
      timestamp,
      bytes: 0,
      mb: 0,
    };
  });
  const byTimestamp = new Map(days.map((day) => [day.timestamp, day]));

  for (const entry of debitEntries || []) {
    if (entry.kind !== 'debit' || !Number.isFinite(entry.amount_bytes)) continue;
    const createdAt = entryTimestampMs(entry);
    if (createdAt === null) continue;
    const day = byTimestamp.get(utcDayStart(createdAt));
    if (day) day.bytes += Math.abs(entry.amount_bytes);
  }

  return days.map((day) => ({ ...day, mb: day.bytes / BYTES_PER_MB }));
}
