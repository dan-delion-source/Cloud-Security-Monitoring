import React from 'react';
import type { ParsedLog } from '../../types/cloudtrail';
import { SeverityDot } from './SeverityDot';
import { formatDateUTC } from '../../utils/formatters';

interface LogRowProps {
  log: ParsedLog;
  onClick: () => void;
  style?: React.CSSProperties;
}

export const LogRow: React.FC<LogRowProps> = ({ log, onClick, style }) => {
  return (
    <div
      style={style}
      onClick={onClick}
      className={`absolute left-0 right-0 flex items-center border-b border-gray-100 dark:border-gray-800/40 px-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-[#15213b]/30 transition-all select-none ${
        log.isNew ? 'bg-indigo-500/10 dark:bg-indigo-500/5 animate-highlight-new' : ''
      }`}
    >
      {/* Severity Column (w-12) */}
      <div className="w-12 flex items-center justify-center shrink-0">
        <SeverityDot severity={log.severity} />
      </div>

      {/* Event Name (20%) */}
      <div className="w-[22%] truncate font-semibold text-gray-900 dark:text-gray-100 pr-3">
        {log.eventName}
      </div>

      {/* Principal ARN (38%) */}
      <div className="w-[38%] truncate font-mono text-[11px] text-gray-500 dark:text-gray-400 pr-3">
        {log.principalArn}
      </div>

      {/* Source IP (18%) */}
      <div className="w-[18%] truncate font-mono text-gray-600 dark:text-gray-300">
        {log.sourceIP}
      </div>

      {/* Timestamp (22%) */}
      <div className="w-[22%] text-right text-gray-500 dark:text-gray-400 font-mono text-[11px] shrink-0">
        {formatDateUTC(log.timestamp).replace(' UTC', '')}
      </div>
    </div>
  );
};

export default LogRow;
