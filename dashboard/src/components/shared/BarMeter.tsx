import React from 'react';
import { roundNumber, formatPercentage } from '../../utils/formatters';

interface BarMeterProps {
  label: string;
  count: number;
  total: number;
  color: string; // Hex color or Tailwind color class
  className?: string;
}

export const BarMeter: React.FC<BarMeterProps> = ({
  label,
  count,
  total,
  color,
  className = ''
}) => {
  const percentage = total > 0 ? (count / total) * 100 : 0;
  const displayPercentage = formatPercentage(count, total);

  return (
    <div className={`space-y-1.5 ${className}`}>
      
      {/* Top Labels */}
      <div className="flex items-center justify-between text-xs">
        <span className="font-semibold text-gray-700 dark:text-gray-300">
          {label}
        </span>
        <span className="font-mono text-gray-500 dark:text-gray-400">
          {roundNumber(count)} hits ({displayPercentage})
        </span>
      </div>

      {/* Meter Track */}
      <div className="w-full h-2.5 bg-gray-100 dark:bg-gray-800/80 rounded-full overflow-hidden border border-gray-200/20 dark:border-gray-700/20">
        <div
          className="h-full rounded-full transition-all duration-500 ease-out"
          style={{
            width: `${percentage}%`,
            backgroundColor: color
          }}
        />
      </div>
      
    </div>
  );
};

export default BarMeter;
