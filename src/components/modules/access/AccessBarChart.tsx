import React from 'react';
import { useSecurityStore } from '../../../store/securityStore';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell
} from 'recharts';
import { BarChart3 } from 'lucide-react';

interface AccessChartItem {
  name: string;
  value: number;
  color: string;
}

export const AccessBarChart: React.FC = () => {
  const { unauthorizedEvents } = useSecurityStore();

  // Route breakdown colors:
  // Public IP (red) / No VPC endpoint (amber) / CF bypass (amber) / Unauth invoke (blue)
  const categoryConfig: Record<string, { label: string; color: string }> = {
    'Public IP': { label: 'Public IP', color: '#E24B4A' },
    'No VPC endpoint': { label: 'No VPC endpoint', color: '#EF9F27' },
    'CF bypass': { label: 'CF bypass', color: '#EF9F27' },
    'Unauth invoke': { label: 'Unauth invoke', color: '#378ADD' }
  };

  // Compute live event count breakdown
  const computeBreakdown = (): AccessChartItem[] => {
    const counts: Record<string, number> = {
      'Public IP': 0,
      'No VPC endpoint': 0,
      'CF bypass': 0,
      'Unauth invoke': 0
    };

    unauthorizedEvents.forEach((e) => {
      if (counts[e.routeType] !== undefined) {
        counts[e.routeType]++;
      }
    });

    return Object.keys(counts).map((key) => ({
      name: key,
      value: counts[key],
      color: categoryConfig[key].color
    }));
  };

  const data = computeBreakdown();

  return (
    <div className="glass-card p-4 flex flex-col h-[250px] select-none">
      
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800/60 shrink-0">
        <h3 className="text-xs font-black uppercase tracking-widest text-gray-900 dark:text-white flex items-center gap-1.5">
          <BarChart3 className="w-4 h-4 text-[#EF9F27]" />
          Access Vectors (12h)
        </h3>
        <span className="text-[10px] text-gray-400 font-mono">
          Route Category breakdown
        </span>
      </div>

      {/* Horizontal Bar Chart */}
      <div className="flex-1 min-h-0 pt-4 text-[10px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 0, right: 20, left: 10, bottom: 5 }}
          >
            <XAxis 
              type="number"
              stroke="#888888" 
              fontSize={9}
              tickLine={false}
              axisLine={false}
              allowDecimals={false}
            />
            <YAxis 
              dataKey="name" 
              type="category"
              stroke="#888888" 
              fontSize={9}
              tickLine={false}
              axisLine={false}
              width={85}
            />
            <Tooltip
              cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }}
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const item = payload[0].payload as AccessChartItem;
                  return (
                    <div className="bg-white dark:bg-[#121B2F] border border-gray-200 dark:border-gray-800 p-2 rounded shadow-lg text-xs">
                      <span className="font-semibold text-gray-950 dark:text-gray-100 block">
                        {item.name}
                      </span>
                      <span className="font-bold" style={{ color: item.color }}>
                        {item.value} {item.value === 1 ? 'event' : 'events'}
                      </span>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Bar 
              dataKey="value" 
              radius={[0, 4, 4, 0]}
              barSize={12}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

    </div>
  );
};

export default AccessBarChart;
