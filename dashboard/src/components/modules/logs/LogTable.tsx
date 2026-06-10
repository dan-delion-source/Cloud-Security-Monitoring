import React, { useRef, useState, useMemo } from 'react';
import { useSecurityStore } from '../../../store/securityStore';
import { useVirtualizer } from '@tanstack/react-virtual';
import LogRow from '../../shared/LogRow';
import { RefreshCw, SearchX, FileSpreadsheet } from 'lucide-react';

export const LogTable: React.FC = () => {
  const { logs, logFilter, logSearchQuery, setSelectedEvent, isLoading, blockedIps, mutedEvents } = useSecurityStore();
  const parentRef = useRef<HTMLDivElement>(null);
  const [hideBlocked, setHideBlocked] = useState(false);

  // Memoize filtered logs to avoid recalculating on every render
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      const isBlocked = log.isBlocked || blockedIps.includes(log.sourceIP);
      const isMuted = log.isMuted || mutedEvents.includes(log.eventName);

      if (hideBlocked && (isBlocked || isMuted)) {
        return false;
      }

      const matchesFilter = logFilter === 'ALL' || log.severity === logFilter;
      const matchesSearch =
        !logSearchQuery ||
        log.eventName.toLowerCase().includes(logSearchQuery.toLowerCase()) ||
        log.principalArn.toLowerCase().includes(logSearchQuery.toLowerCase()) ||
        log.sourceIP.toLowerCase().includes(logSearchQuery.toLowerCase()) ||
        log.awsRegion.toLowerCase().includes(logSearchQuery.toLowerCase());

      return matchesFilter && matchesSearch;
    });
  }, [logs, logFilter, logSearchQuery, hideBlocked, blockedIps, mutedEvents]);

  // Setup virtualization (Count of rows, parent container scroll viewport, row size)
  const rowVirtualizer = useVirtualizer({
    count: filteredLogs.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 44, // 44px matches padding and fonts in LogRow
    overscan: 10,
  });

  return (
    <div className="flex flex-col bg-white dark:bg-[#121B2E]/60 border border-gray-200/50 dark:border-gray-800/50 rounded-xl overflow-hidden shadow-sm backdrop-blur-md h-[550px]">

      {/* Table Header Section */}
      <div className="flex items-center bg-gray-50 dark:bg-[#152035]/60 border-b border-gray-200 dark:border-gray-800 text-xs font-extrabold uppercase tracking-wider text-gray-500 dark:text-gray-400 py-3.5 px-4 shrink-0 select-none">
        <div className="w-24 text-center shrink-0">Severity</div>
        <div className="w-[24%] pr-4 shrink-0">Event Name</div>
        <div className="w-[34%] pr-4 shrink-0">Principal ARN</div>
        <div className="w-[18%] shrink-0">Source IP</div>
        <div className="flex-1 text-right shrink-0">Timestamp</div>
      </div>

      {/* Loading Overlay */}
      {isLoading && logs.length === 0 && (
        <div className="flex-1 flex flex-col items-center justify-center space-y-3">
          <RefreshCw className="w-8 h-8 text-[#185FA5] animate-spin" />
          <span className="text-xs text-gray-500">Querying active CloudTrail event stream...</span>
        </div>
      )}

      {/* Empty States */}
      {!isLoading && filteredLogs.length === 0 && (
        <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-xs text-gray-400 space-y-3 select-none">
          <div className="p-4 bg-gray-50 dark:bg-gray-800/30 rounded-full border border-gray-100 dark:border-gray-800/40">
            {logSearchQuery ? <SearchX className="w-8 h-8" /> : <FileSpreadsheet className="w-8 h-8" />}
          </div>
          <div className="max-w-[280px]">
            <p className="font-semibold text-gray-700 dark:text-gray-300">
              {logSearchQuery ? 'No search matches' : 'Log repository clean'}
            </p>
            <p className="text-[10px] text-gray-500 mt-1">
              {logSearchQuery
                ? 'Try broadening your query terms, checking spelling, or resetting the filter pill.'
                : 'No CloudTrail actions match the current monitoring scope.'
              }
            </p>
          </div>
        </div>
      )}

      {/* Scrollable Virtualized Content Panel */}
      {filteredLogs.length > 0 && (
        <div
          ref={parentRef}
          className="flex-1 overflow-y-auto min-h-0 relative w-full"
        >
          {/* Sizer Element - defines total scroll height */}
          <div
            style={{
              height: `${rowVirtualizer.getTotalSize()}px`,
              width: '100%',
              position: 'relative',
            }}
          >
            {/* Render visible items absolutely positioned */}
            {rowVirtualizer.getVirtualItems().map((virtualItem) => {
              const log = filteredLogs[virtualItem.index];
              if (!log) return null;

              const isBlocked = log.isBlocked || blockedIps.includes(log.sourceIP);
              const isMuted = log.isMuted || mutedEvents.includes(log.eventName);
              const decoratedLog = { ...log, isBlocked, isMuted };

              return (
                <LogRow
                  key={log.id}
                  log={decoratedLog}
                  onClick={() => setSelectedEvent({ type: 'log', data: decoratedLog as unknown as Record<string, unknown> })}
                  style={{
                    height: `${virtualItem.size}px`,
                    transform: `translateY(${virtualItem.start}px)`,
                  }}
                />
              );
            })}
          </div>
        </div>
      )}

      {/* Footer Metrics */}
      <div className="px-4 py-2 border-t border-gray-200 dark:border-gray-800/60 bg-gray-50 dark:bg-[#121B2F]/40 flex items-center justify-between text-[10px] text-gray-400 shrink-0 font-mono">
        <div className="flex items-center gap-4">
          <span>Displaying {filteredLogs.length} of {logs.length} logs</span>
          <label className="flex items-center gap-1.5 cursor-pointer text-gray-500 dark:text-gray-450 select-none font-sans font-bold hover:text-gray-700 dark:hover:text-gray-200">
            <input
              type="checkbox"
              checked={hideBlocked}
              onChange={(e) => setHideBlocked(e.target.checked)}
              className="rounded border-gray-300 dark:border-gray-700 text-[#185FA5] focus:ring-[#185FA5] w-3 h-3 cursor-pointer"
            />
            <span>Hide Blocked/Muted Logs</span>
          </label>
        </div>
        {isLoading && <span className="animate-pulse text-[#378ADD]">Polling live...</span>}
      </div>

    </div>
  );
};

export default LogTable;
