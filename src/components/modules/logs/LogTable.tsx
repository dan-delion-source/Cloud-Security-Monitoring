import React, { useRef } from 'react';
import { useSecurityStore } from '../../../store/securityStore';
import { useVirtualizer } from '@tanstack/react-virtual';
import LogRow from '../../shared/LogRow';
import { RefreshCw, SearchX, FileSpreadsheet } from 'lucide-react';

export const LogTable: React.FC = () => {
  const { logs, logFilter, logSearchQuery, setSelectedEvent, isLoading } = useSecurityStore();
  const parentRef = useRef<HTMLDivElement>(null);

  // Apply log filter and search text
  const filteredLogs = logs.filter((log) => {
    const matchesFilter = logFilter === 'ALL' || log.severity === logFilter;
    const matchesSearch =
      !logSearchQuery ||
      log.eventName.toLowerCase().includes(logSearchQuery.toLowerCase()) ||
      log.principalArn.toLowerCase().includes(logSearchQuery.toLowerCase()) ||
      log.sourceIP.toLowerCase().includes(logSearchQuery.toLowerCase()) ||
      log.awsRegion.toLowerCase().includes(logSearchQuery.toLowerCase());
      
    return matchesFilter && matchesSearch;
  });

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
      <div className="flex items-center bg-gray-50 dark:bg-[#152035]/60 border-b border-gray-200 dark:border-gray-800 text-[11px] font-extrabold uppercase tracking-wider text-gray-500 dark:text-gray-400 py-3.5 px-4 shrink-0 select-none">
        <div className="w-12 text-center shrink-0">Severity</div>
        <div className="w-[22%] pr-3">Event Name</div>
        <div className="w-[38%] pr-3">Principal ARN</div>
        <div className="w-[18%]">Source IP</div>
        <div className="w-[22%] text-right">Timestamp</div>
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
              
              return (
                <LogRow
                  key={log.id}
                  log={log}
                  onClick={() => setSelectedEvent({ type: 'log', data: log })}
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
        <span>Displaying {filteredLogs.length} of {logs.length} logs</span>
        {isLoading && <span className="animate-pulse text-[#378ADD]">Polling live...</span>}
      </div>

    </div>
  );
};

export default LogTable;
