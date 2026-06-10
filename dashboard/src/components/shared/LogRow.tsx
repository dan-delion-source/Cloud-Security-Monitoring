import React from 'react';
import type { ParsedLog } from '../../types/cloudtrail';
import { SeverityDot } from './SeverityDot';
import { formatDateUTC } from '../../utils/formatters';

interface LogRowProps {
  log: ParsedLog;
  onClick: () => void;
  style?: React.CSSProperties;
}

export const LogRow: React.FC<LogRowProps> = React.memo(({ log, onClick, style }) => {
  return (
    <div
      style={style}
      onClick={onClick}
      className={`absolute left-0 right-0 flex items-center border-b border-gray-100 dark:border-gray-800/40 px-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-[#15213b]/30 transition-all select-none ${
        log.isBlocked || log.isMuted
          ? 'opacity-40 bg-gray-50/50 dark:bg-gray-950/20'
          : log.isNew
          ? 'bg-indigo-500/10 dark:bg-indigo-500/5 animate-highlight-new'
          : ''
      }`}
    >
      {/* Severity Column (w-24) */}
      <div className="w-24 flex items-center justify-center shrink-0">
        <SeverityDot severity={log.severity} />
      </div>

      {/* Event Name (24%) */}
      <div className="w-[24%] pr-4 flex items-center gap-1.5 shrink-0 min-w-0">
        <span className={`truncate flex-1 font-semibold text-[13px] text-gray-900 dark:text-gray-100 ${
          log.isMuted ? 'line-through text-gray-400 dark:text-gray-500' : ''
        }`}>
          {log.eventName}
        </span>
        {log.isMuted && (
          <span className="px-1 py-0.5 text-[8px] font-bold uppercase bg-gray-150 dark:bg-gray-800 text-gray-500 rounded border border-gray-250 dark:border-gray-700 leading-none shrink-0">
            Muted
          </span>
        )}
      </div>

      {/* Principal ARN (34%) */}
      <div className="w-[34%] truncate font-mono text-[11px] text-gray-500 dark:text-gray-400 pr-4 shrink-0">
        {log.principalArn}
      </div>

      {/* Source IP (18%) */}
      <div className="w-[18%] pr-4 flex items-center gap-1 shrink-0 min-w-0">
        <span className={`truncate flex-1 font-mono text-[12px] text-gray-600 dark:text-gray-300 ${
          log.isBlocked ? 'line-through text-gray-400 dark:text-gray-500' : ''
        }`}>
          {log.sourceIP}
        </span>
        {log.isBlocked && (
          <span className="px-1 py-0.5 text-[8px] font-bold uppercase bg-red-100 dark:bg-red-950/40 text-red-500 rounded border border-red-200 dark:border-red-900/40 leading-none shrink-0">
            Blocked
          </span>
        )}
      </div>

      {/* Timestamp (remaining) */}
      <div className="flex-1 text-right text-gray-500 dark:text-gray-400 font-mono text-[11px] shrink-0">
        {formatDateUTC(log.timestamp).replace(' UTC', '')}
      </div>
    </div>
  );
});

LogRow.displayName = 'LogRow';

export default LogRow;
