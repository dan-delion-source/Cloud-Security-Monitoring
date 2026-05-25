import React from 'react';
import type { LucideIcon } from 'lucide-react';

interface KpiCardProps {
  label: string;
  value: number | string;
  icon: LucideIcon;
  trend: string;
  trendDirection?: 'up' | 'down' | 'neutral';
  colorClass: string; // text color or background outline mapping
  iconBgClass: string;
}

export const KpiCard: React.FC<KpiCardProps> = ({
  label,
  value,
  icon: Icon,
  trend,
  trendDirection = 'neutral',
  colorClass,
  iconBgClass
}) => {
  return (
    <div className="glass-card p-4 flex items-center justify-between hover:shadow-md hover:border-gray-300 dark:hover:border-gray-700/80 transition duration-300">
      
      {/* Metrics Column */}
      <div className="space-y-1">
        <span className="text-[10px] uppercase font-bold tracking-widest text-gray-500 dark:text-gray-400">
          {label}
        </span>
        <div className={`text-2xl font-extrabold font-mono tracking-tight ${colorClass}`}>
          {value}
        </div>
        <p className="text-[10px] text-gray-400 dark:text-gray-500 flex items-center gap-1">
          <span className={
            trendDirection === 'up' ? 'text-red-500 font-bold' :
            trendDirection === 'down' ? 'text-emerald-500 font-bold' : 'text-gray-400'
          }>
            {trend.split(' ')[0]}
          </span>
          <span>{trend.substring(trend.indexOf(' ') + 1)}</span>
        </p>
      </div>

      {/* Graphic Icon */}
      <div className={`p-3 rounded-xl border border-transparent ${iconBgClass} shrink-0`}>
        <Icon className={`w-5 h-5 ${colorClass}`} />
      </div>

    </div>
  );
};

export default KpiCard;
