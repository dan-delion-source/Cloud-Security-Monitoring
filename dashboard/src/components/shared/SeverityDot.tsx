import React from 'react';
import type { Severity } from '../../constants/severity';

interface SeverityDotProps {
  severity: Severity;
  className?: string;
}

export const SeverityDot: React.FC<SeverityDotProps> = ({ severity, className = '' }) => {
  // Map severity to appropriate color classes
  const colorMap: Record<Severity, string> = {
    CRITICAL: 'bg-[#E24B4A]',
    HIGH: 'bg-[#EF9F27]',
    MEDIUM: 'bg-[#378ADD]',
    LOW: 'bg-[#639922]',
  };

  const colorClass = colorMap[severity] || 'bg-gray-400';

  return (
    <span
      className={`inline-block w-[7px] h-[7px] rounded-full shrink-0 ${colorClass} ${className}`}
      role="img"
      aria-label={`Severity: ${severity.toLowerCase()}`}
    />
  );
};

export default SeverityDot;
