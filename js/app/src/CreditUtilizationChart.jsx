import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { aggregateDailyDebits } from './creditUtilization';

const chartNumber = new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 });

function axisDayLabel(timestamp) {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  }).format(new Date(timestamp));
}

function fullDayLabel(timestamp) {
  return new Intl.DateTimeFormat(undefined, {
    weekday: 'short',
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  }).format(new Date(timestamp));
}

function formatMb(value) {
  if (value > 0 && value < 0.01) return '<0.01 MB';
  return `${chartNumber.format(value)} MB`;
}

export default function CreditUtilizationChart({ credits, formatBytes, historyDebits = null, historyError = false }) {
  const loading = historyDebits === null;
  const data = aggregateDailyDebits(historyDebits).map((day) => ({
    ...day,
    axisLabel: axisDayLabel(day.timestamp),
    fullLabel: fullDayLabel(day.timestamp),
  }));
  const maxMb = Math.max(...data.map((day) => day.mb));
  const totalMb = data.reduce((total, day) => total + day.mb, 0);
  const usedDays = data.filter((day) => day.mb > 0);
  const axisTicks = data.filter((_, index) => index % 5 === 0 || index === data.length - 1).map((day) => day.key);
  const axisLabels = new Map(data.map((day) => [day.key, day.axisLabel]));
  const summary = `Daily utilization in MB for the last 30 UTC days. Total ${formatMb(totalMb)}. ${usedDays.map((day) => `${day.fullLabel}, ${formatMb(day.mb)}`).join('; ')}.`;

  return <section className="dashboard-utilization" aria-labelledby="dashboard-utilization-title">
    <header><div><span className="eyebrow">Daily utilization</span><h2 id="dashboard-utilization-title">Last 30 days</h2></div><span>MB · UTC</span></header>
    {historyError ? <div className="dashboard-utilization-plot dashboard-utilization-plot--message" role="alert"><strong>Daily utilization unavailable</strong><span>Refresh the page to try again.</span></div> : loading ? <div className="dashboard-utilization-plot dashboard-utilization-plot--loading" role="status" aria-label="Loading daily utilization"><i /></div> : maxMb === 0 ? <div className="dashboard-utilization-plot dashboard-utilization-plot--message" role="status"><strong>No utilization in the last 30 days</strong><span>Hosted finalization use will appear here in MB.</span></div> :
      <div className="dashboard-utilization-plot" role="img" aria-label={summary}>
        <ResponsiveContainer width="100%" height={190}>
          <BarChart data={data} margin={{ top: 14, right: 8, bottom: 0, left: 0 }} barCategoryGap="24%" accessibilityLayer>
            <XAxis type="category" dataKey="key" ticks={axisTicks} tickFormatter={(key) => axisLabels.get(key) || key} axisLine={false} tickLine={false} interval={0} fontSize={10} fill="var(--muted)" fontFamily="'IBM Plex Mono', monospace" />
            <YAxis type="number" domain={[0, maxMb > 0 ? 'auto' : 1]} axisLine={false} tickLine={false} width={64} tickFormatter={(value) => formatMb(Number(value))} fontSize={9} fill="var(--muted)" fontFamily="'IBM Plex Mono', monospace" />
            <Tooltip cursor={{ fill: 'var(--line-soft)' }} labelFormatter={(_, payload) => payload?.[0]?.payload?.fullLabel || ''} formatter={(value) => [formatMb(Number(value)), 'Utilization']} contentStyle={{ border: '1px solid var(--line)', borderRadius: 0, background: 'var(--white)', boxShadow: 'none', fontSize: 11, fontFamily: "'IBM Plex Mono', monospace" }} />
            <Bar dataKey="mb" fill="var(--action)" isAnimationActive={false} maxBarSize={28} />
          </BarChart>
        </ResponsiveContainer>
      </div>}
    <dl><div><dt><i className="dashboard-utilization-period" />30-day use</dt><dd>{loading || historyError ? '—' : formatMb(totalMb)}</dd></div><div><dt>Available</dt><dd>{formatBytes(credits.total_remaining_bytes)}</dd></div><div><dt>Overall budget</dt><dd>{formatBytes(credits.total_granted_bytes)}</dd></div></dl>
  </section>;
}
