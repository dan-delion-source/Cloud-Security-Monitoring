import React from 'react';
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

interface HourlyData {
  hour: string;
  Critical: number;
  High: number;
  Medium: number;
}

export const HourlyChart: React.FC = () => {
  // Generate a trailing 12-hour list from current UTC hour
  const generateHourlyData = (): HourlyData[] => {
    const data: HourlyData[] = [];
    const currentHour = new Date().getUTCHours();
    
    // Fixed pre-simulated logs spread over trailing 12 hours for beautiful rendering
    const patterns = [
      { c: 0, h: 1, m: 2 },
      { c: 0, h: 0, m: 1 },
      { c: 1, h: 0, m: 0 },
      { c: 0, h: 2, m: 3 },
      { c: 0, h: 1, m: 1 },
      { c: 0, h: 0, m: 2 },
      { c: 1, h: 1, m: 0 },
      { c: 0, h: 0, m: 1 },
      { c: 2, h: 1, m: 4 },
      { c: 0, h: 2, m: 2 },
      { c: 1, h: 0, m: 1 },
      { c: 0, h: 1, m: 3 },
    ];

    for (let i = 11; i >= 0; i--) {
      const h = (currentHour - i + 24) % 24;
      const formattedHour = `${String(h).padStart(2, '0')}:00`;
      const pattern = patterns[11 - i];
      
      data.push({
        hour: formattedHour,
        Critical: pattern.c,
        High: pattern.h,
        Medium: pattern.m
      });
    }

    return data;
  };

  const chartData = generateHourlyData();

  return (
    <div className="glass-card p-4 flex flex-col h-[320px] select-none">
      
      {/* Title Header */}
      <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800/60 shrink-0">
        <h3 className="text-xs font-black uppercase tracking-widest text-gray-900 dark:text-white flex items-center gap-1.5">
          <BarChart3 className="w-4 h-4 text-[#378ADD]" />
          Hourly Event Distribution (12h)
        </h3>
        <span className="text-[10px] text-gray-400 font-mono">
          Last 12 hours UTC
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
