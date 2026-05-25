import React from 'react';
import { type Severity, SEVERITY_BG_COLORS } from '../../constants/severity';

interface StatusBadgeProps {
  severity: Severity;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ severity, className = '' }) => {
  const badgeStyle = SEVERITY_BG_COLORS[severity] || 'bg-gray-100 text-gray-800 border-gray-200';
  
  return (
    <span 
      className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border tracking-wider shrink-0 select-none ${badgeStyle} ${className}`}
    >
      {severity}
    </span>
  );
};

export default StatusBadge;
