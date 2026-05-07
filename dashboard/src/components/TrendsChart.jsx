import { useMemo, useState } from 'react';
import {
  ResponsiveContainer, LineChart, Line, XAxis, YAxis,
  CartesianGrid, Tooltip, Legend,
} from 'recharts';

const RANGES = {
  '24h': { hours: 24, bucketMs: 60 * 60 * 1000, label: '24h', tickFmt: (d) => `${d.getHours()}:00` },
  '7d':  { hours: 24 * 7, bucketMs: 24 * 60 * 60 * 1000, label: '7d', tickFmt: (d) => d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) },
};

function bucketize(events, range) {
  const { hours, bucketMs, tickFmt } = RANGES[range];
  const now = Date.now();
  const start = now - hours * 3600 * 1000;

  const buckets = new Map();
  const firstBucket = Math.floor(start / bucketMs) * bucketMs;
  const lastBucket = Math.floor(now / bucketMs) * bucketMs;
  for (let t = firstBucket; t <= lastBucket; t += bucketMs) {
    buckets.set(t, { t, label: tickFmt(new Date(t)), blocked: 0, allowed: 0, warning: 0, findings: 0 });
  }

  for (const e of events) {
    const ts = new Date(e.timestamp).getTime();
    if (ts < start) continue;
    const key = Math.floor(ts / bucketMs) * bucketMs;
    const b = buckets.get(key);
    if (!b) continue;
    if (e.action === 'blocked') b.blocked++;
    else if (e.action === 'allowed') b.allowed++;
    else if (e.action === 'warning') b.warning++;
    else if (e.action === 'findings') b.findings++;
  }

  return Array.from(buckets.values()).sort((a, b) => a.t - b.t);
}

function TrendsChart({ events }) {
  const [range, setRange] = useState('24h');
  const data = useMemo(() => bucketize(events || [], range), [events, range]);

  return (
    <>
      <div className="trends-header">
        <h3 style={{ marginBottom: 0 }}>Activity Trends</h3>
        <div className="trends-range">
          {Object.keys(RANGES).map(r => (
            <button
              key={r}
              className={`trends-range-btn ${range === r ? 'active' : ''}`}
              onClick={() => setRange(r)}
            >
              {RANGES[r].label}
            </button>
          ))}
        </div>
      </div>
      <div className="trends-chart">
        <ResponsiveContainer width="100%" height={240}>
          <LineChart data={data} margin={{ top: 8, right: 16, left: -8, bottom: 0 }}>
            <CartesianGrid stroke="#2a2d3e" strokeDasharray="3 3" />
            <XAxis dataKey="label" stroke="#8b8fa3" fontSize={12} />
            <YAxis stroke="#8b8fa3" fontSize={12} allowDecimals={false} />
            <Tooltip
              contentStyle={{ background: '#1e2130', border: '1px solid #2a2d3e', borderRadius: 8 }}
              labelStyle={{ color: '#e4e6f0' }}
            />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Line type="monotone" dataKey="blocked" stroke="#ef4444" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="warning" stroke="#eab308" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="findings" stroke="#f97316" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="allowed" stroke="#22c55e" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </>
  );
}

export default TrendsChart;
