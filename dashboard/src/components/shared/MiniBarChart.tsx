import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell
} from 'recharts';

interface ChartDataItem {
  name: string;
  value: number;
  color?: string;
  [key: string]: any;
}

interface MiniBarChartProps {
  data: ChartDataItem[];
  height?: number;
  colorMap?: Record<string, string>;
  dataKey?: string;
}

export const MiniBarChart: React.FC<MiniBarChartProps> = ({
  data,
  height = 180,
  colorMap,
  dataKey = 'value'
}) => {
  return (
    <div style={{ width: '100%', height }} className="select-none text-[11px]">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 10, right: 10, left: -25, bottom: 0 }}
        >
          <XAxis
            dataKey="name"
            stroke="#888888"
            fontSize={10}
            tickLine={false}
            axisLine={false}
            dy={8}
          />
          <YAxis
            stroke="#888888"
            fontSize={10}
            tickLine={false}
            axisLine={false}
            allowDecimals={false}
            dx={-8}
          />
          <Tooltip
            cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }}
            content={({ active, payload }) => {
              if (active && payload && payload.length) {
                const item = payload[0].payload as ChartDataItem;
                return (
                  <div className="bg-white dark:bg-[#121B2F] border border-gray-200 dark:border-gray-800 p-2.5 rounded-lg shadow-xl text-xs">
                    <span className="font-semibold text-gray-900 dark:text-gray-100 block">
                      {item.name}
                    </span>
                    <span className="text-[#378ADD] font-bold">
                      {item.value} {item.value === 1 ? 'event' : 'events'}
                    </span>
                  </div>
                );
              }
              return null;
            }}
          />
          <Bar
            dataKey={dataKey}
            radius={[4, 4, 0, 0]}
            maxBarSize={45}
          >
            {data.map((entry, index) => {
              // Priority: entry.color -> colorMap[entry.name] -> default brand blue
              const fill = entry.color || (colorMap && colorMap[entry.name]) || '#185FA5';
              return <Cell key={`cell-${index}`} fill={fill} />;
            })}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default MiniBarChart;
