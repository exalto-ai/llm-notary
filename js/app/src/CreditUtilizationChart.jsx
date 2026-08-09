import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { aggregateDailyDebits } from './creditUtilization';

const chartNumber = new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 });

function shortDayLabel(timestamp) {
  return new Intl.DateTimeFormat(undefined, {
    weekday: 'short',
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

export default function CreditUtilizationChart({ historyDebits = null, historyError = false }) {
  const loading = historyDebits === null;
  const data = aggregateDailyDebits(historyDebits).map((day) => ({
    ...day,
    label: shortDayLabel(day.timestamp),
    fullLabel: fullDayLabel(day.timestamp),
  }));
  const maxMb = Math.max(...data.map((day) => day.mb));
  const summary = maxMb === 0
    ? 'No utilization recorded for the last seven UTC days. Daily values are shown in MB.'
    : `Daily utilization in MB for the last seven UTC days: ${data.map((day) => `${day.fullLabel}, ${formatMb(day.mb)}`).join('; ')}.`;

  return <section className="dashboard-utilization" aria-labelledby="dashboard-utilization-title">
    <header><div><span className="eyebrow">Daily utilization</span><h2 id="dashboard-utilization-title">Last 7 days</h2></div><span>MB · UTC</span></header>
    {historyError ? <div className="dashboard-utilization-plot dashboard-utilization-plot--message" role="alert">Daily utilization unavailable.</div> : loading ? <div className="dashboard-utilization-plot dashboard-utilization-plot--loading" role="status" aria-label="Loading daily utilization"><i /></div> :
      <div className="dashboard-utilization-plot" role="img" aria-label={summary}>
        <ResponsiveContainer width="100%" height={190}>
          <BarChart data={data} margin={{ top: 14, right: 8, bottom: 0, left: 0 }} accessibilityLayer>
            <XAxis type="category" dataKey="label" axisLine={false} tickLine={false} interval={0} fontSize={10} fill="var(--muted)" fontFamily="'DM Mono', monospace" />
            <YAxis type="number" domain={[0, maxMb > 0 ? 'auto' : 1]} axisLine={false} tickLine={false} width={64} tickFormatter={(value) => formatMb(Number(value))} fontSize={9} fill="var(--muted)" fontFamily="'DM Mono', monospace" />
            <Tooltip cursor={{ fill: 'var(--line-soft)' }} labelFormatter={(_, payload) => payload?.[0]?.payload?.fullLabel || ''} formatter={(value) => [formatMb(Number(value)), 'Utilization']} contentStyle={{ border: '1px solid var(--line)', borderRadius: 0, background: 'var(--white)', boxShadow: 'none', fontSize: 11, fontFamily: "'DM Mono', monospace" }} />
            <Bar dataKey="mb" fill="var(--ink)" isAnimationActive={false} maxBarSize={48} />
          </BarChart>
        </ResponsiveContainer>
      </div>}
  </section>;
}
