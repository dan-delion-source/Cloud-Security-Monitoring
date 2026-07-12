import React, { useMemo, useEffect, useState } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts';
import { BarChart3 } from 'lucide-react';
import { useSecurityStore } from '../../../store/securityStore';

interface HourlyData {
  hour: string;
  Critical: number;
  High: number;
  Medium: number;
}

export const HourlyChart: React.FC = () => {
  const { logs, unauthorizedEvents, buckets, iamAnomalies } = useSecurityStore();

  // Tick counter to force re-render every 60s so the time axis shifts
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const timer = setInterval(() => setTick(t => t + 1), 60_000);
    return () => clearInterval(timer);
  }, []);

  const chartData = useMemo(() => {
    const now = new Date();
    const currentHourUTC = now.getUTCHours();

    // Build 12 hourly buckets keyed by UTC hour
    const bucketMap = new Map<number, { Critical: number; High: number; Medium: number }>();
    for (let i = 11; i >= 0; i--) {
      const h = (currentHourUTC - i + 24) % 24;
      bucketMap.set(h, { Critical: 0, High: 0, Medium: 0 });
    }

    // 12 hours ago as cutoff
    const cutoff = new Date(now.getTime() - 12 * 60 * 60 * 1000);

    // Helper: place a timestamped event with a severity into the correct bucket
    const place = (timestamp: string, severity: string) => {
      const d = new Date(timestamp);
      if (d < cutoff || d > now) return;
      const h = d.getUTCHours();
      const bucket = bucketMap.get(h);
      if (!bucket) return;
      const sev = severity?.toUpperCase();
      if (sev === 'CRITICAL') bucket.Critical++;
      else if (sev === 'HIGH') bucket.High++;
      else if (sev === 'MEDIUM') bucket.Medium++;
      // LOW events are intentionally excluded from the chart
    };

    // Feed all event sources into buckets
    logs.forEach(l => place(l.timestamp, l.severity));
    unauthorizedEvents.forEach(e => place(e.timestamp, e.severity));
    iamAnomalies.forEach(a => place(a.timestamp, a.severity));
    buckets
      .filter(b => !b.remediated)
      .forEach(b => {
        // S3 buckets use creationDate (Date object), fallback to current time
        const ts = b.creationDate ? b.creationDate.toISOString() : now.toISOString();
        place(ts, b.severity);
      });

    // Convert map to ordered array
    const data: HourlyData[] = [];
    for (let i = 11; i >= 0; i--) {
      const h = (currentHourUTC - i + 24) % 24;
      const entry = bucketMap.get(h)!;
      data.push({
        hour: `${String(h).padStart(2, '0')}:00`,
        Critical: entry.Critical,
        High: entry.High,
        Medium: entry.Medium
      });
    }

    return data;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [logs, unauthorizedEvents, buckets, iamAnomalies, tick]);

  return (
    <div className="glass-card p-4 flex flex-col h-[320px] select-none">
      
      {/* Title Header */}
      <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800/60 shrink-0">
        <h3 className="text-xs font-black uppercase tracking-widest text-gray-900 dark:text-white flex items-center gap-1.5">
          <BarChart3 className="w-4 h-4 text-[#378ADD]" />
          Hourly Event Distribution (12h)
        </h3>
        <span className="text-[10px] text-gray-400 font-mono">
          Last 12 hours UTC · Live
        </span>
      </div>

      {/* Chart Canvas */}
      <div className="flex-1 min-h-0 pt-4 text-[10px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={chartData}
            margin={{ top: 10, right: 10, left: -25, bottom: 0 }}
          >
            <XAxis 
              dataKey="hour" 
              stroke="#888888" 
              fontSize={9}
              tickLine={false}
              axisLine={false}
              dy={6}
            />
            <YAxis 
              stroke="#888888" 
              fontSize={9}
              tickLine={false}
              axisLine={false}
              allowDecimals={false}
              dx={-6}
            />
            <Tooltip
              cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }}
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="bg-white dark:bg-[#121B2F] border border-gray-200 dark:border-gray-800 p-2.5 rounded-lg shadow-xl text-xs space-y-1">
                      <span className="font-semibold text-gray-900 dark:text-gray-100 block border-b border-gray-200 dark:border-gray-800 pb-1">
                        Time: {payload[0].payload.hour}
                      </span>
                      {payload.map((p, idx) => (
                        <div key={idx} className="flex items-center justify-between gap-4">
                          <span className="flex items-center gap-1.5 text-gray-500">
                            <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: p.color }} />
                            {p.name}:
                          </span>
                          <span className="font-bold text-gray-900 dark:text-gray-100">
                            {p.value}
                          </span>
                        </div>
                      ))}
                    </div>
                  );
                }
                return null;
              }}
            />
            <Legend 
              verticalAlign="top" 
              height={30} 
              iconSize={8}
              iconType="circle"
              wrapperStyle={{ fontSize: '9px', paddingBottom: '10px' }}
            />
            
            {/* Stacked Bars */}
            <Bar dataKey="Critical" stackId="a" fill="#E24B4A" name="Critical" />
            <Bar dataKey="High" stackId="a" fill="#EF9F27" name="High" />
            <Bar dataKey="Medium" stackId="a" fill="#378ADD" name="Medium" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

    </div>
  );
};

export default HourlyChart;
