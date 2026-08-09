import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

export default function CreditUtilizationChart({ credits, formatBytes }) {
  const data = [{ name: 'Active credits', used: credits.total_used_bytes, available: credits.total_remaining_bytes }];
  return <section className="dashboard-utilization" aria-labelledby="dashboard-utilization-title">
    <header><div><span className="eyebrow">Current balance</span><h2 id="dashboard-utilization-title">Credit usage</h2></div><span>{formatBytes(credits.total_granted_bytes)} total</span></header>
    <div className="dashboard-utilization-plot" aria-label={`${formatBytes(credits.total_used_bytes)} used and ${formatBytes(credits.total_remaining_bytes)} available`}>
      <ResponsiveContainer width="100%" height={92}>
        <BarChart data={data} layout="vertical" margin={{ top: 20, right: 0, bottom: 20, left: 0 }} accessibilityLayer>
          <XAxis type="number" domain={[0, Math.max(1, credits.total_granted_bytes)]} hide />
          <YAxis type="category" dataKey="name" hide />
          <Tooltip cursor={false} formatter={(value, name) => [formatBytes(Number(value)), name === 'used' ? 'Used' : 'Available']} contentStyle={{ border: '1px solid var(--line)', borderRadius: 0, background: 'var(--white)', boxShadow: 'none', fontSize: 11 }} />
          <Bar dataKey="used" stackId="credits" fill="var(--ink)" isAnimationActive={false} />
          <Bar dataKey="available" stackId="credits" fill="var(--action)" isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </div>
    <dl><div><dt><i className="dashboard-utilization-used" />Used</dt><dd>{formatBytes(credits.total_used_bytes)}</dd></div><div><dt><i className="dashboard-utilization-available" />Available</dt><dd>{formatBytes(credits.total_remaining_bytes)}</dd></div></dl>
  </section>;
}
