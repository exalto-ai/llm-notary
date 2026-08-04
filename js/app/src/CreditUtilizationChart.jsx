import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

function fileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function CreditUtilizationChart({ credits }) {
  const data = [{ name: 'Active credits', used: credits.total_used_bytes, available: credits.total_remaining_bytes }];
  return <section className="dashboard-utilization" aria-labelledby="dashboard-utilization-title">
    <header><div><span className="eyebrow">Current allocation</span><h2 id="dashboard-utilization-title">Utilization</h2></div><span>{fileSize(credits.total_granted_bytes)} granted</span></header>
    <div className="dashboard-utilization-plot" aria-label={`${fileSize(credits.total_used_bytes)} used and ${fileSize(credits.total_remaining_bytes)} available`}>
      <ResponsiveContainer width="100%" height={92}>
        <BarChart data={data} layout="vertical" margin={{ top: 20, right: 0, bottom: 20, left: 0 }} accessibilityLayer>
          <XAxis type="number" domain={[0, Math.max(1, credits.total_granted_bytes)]} hide />
          <YAxis type="category" dataKey="name" hide />
          <Tooltip cursor={false} formatter={(value, name) => [fileSize(Number(value)), name === 'used' ? 'Used' : 'Available']} contentStyle={{ border: '1px solid var(--line)', borderRadius: 0, background: 'var(--white)', boxShadow: 'none', fontSize: 11 }} />
          <Bar dataKey="used" stackId="credits" fill="var(--ink)" isAnimationActive={false} />
          <Bar dataKey="available" stackId="credits" fill="var(--action)" isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </div>
    <dl><div><dt><i className="dashboard-utilization-used" />Used</dt><dd>{fileSize(credits.total_used_bytes)}</dd></div><div><dt><i className="dashboard-utilization-available" />Available</dt><dd>{fileSize(credits.total_remaining_bytes)}</dd></div></dl>
  </section>;
}
