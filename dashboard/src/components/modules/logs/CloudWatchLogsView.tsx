import React, { useState, useEffect, useRef } from 'react';
import { useCloudWatch } from '../../../hooks/useCloudWatch';
import { Terminal, RefreshCw, Layers } from 'lucide-react';

export const CloudWatchLogsView: React.FC = () => {
  const { logGroups, logEvents, isLoading, refreshEvents } = useCloudWatch();
  const [selectedGroup, setSelectedGroup] = useState<string>('');
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Set default group once loaded
  useEffect(() => {
    if (logGroups.length > 0 && !selectedGroup) {
      setSelectedGroup(logGroups[0].logGroupName);
    }
  }, [logGroups, selectedGroup]);

  // Fetch events when selected group changes
  useEffect(() => {
    if (selectedGroup) {
      refreshEvents(selectedGroup);
    }
  }, [selectedGroup, refreshEvents]);

  // Scroll terminal to bottom when new logs arrive
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logEvents]);

  const handleGroupChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setSelectedGroup(e.target.value);
  };

  const handleRefresh = () => {
    if (selectedGroup) {
      refreshEvents(selectedGroup);
    }
  };

  // Helper to colorize and format log lines
  const renderLogMessage = (message: string) => {
    let type: 'info' | 'warn' | 'error' | 'plain' = 'plain';
    let content = message;

    if (message.includes('INFO')) {
      type = 'info';
    } else if (message.includes('WARN')) {
      type = 'warn';
    } else if (message.includes('ERROR') || message.includes('AccessDenied') || message.includes('Access Denied')) {
      type = 'error';
    }

    // Split timestamp and text if formatted like Lambda standard output
    const parts = message.split('\t');
    if (parts.length >= 3) {
      const timestamp = parts[0];
      const level = parts[1];
      const text = parts.slice(2).join('\t');

      return (
        <div className="flex items-start gap-2.5 py-1 px-2 hover:bg-slate-800/40 rounded transition font-mono text-[11px] leading-relaxed">
          <span className="text-slate-500 shrink-0 select-none font-medium">{timestamp}</span>
          <span className={`px-1.5 py-0.2 rounded font-extrabold uppercase text-[9px] shrink-0 select-none ${
            level === 'INFO' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
            level === 'WARN' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20 animate-pulse' :
            'bg-rose-500/10 text-rose-400 border border-rose-500/20'
          }`}>{level}</span>
          <span className={`flex-1 break-words font-medium ${
            type === 'info' ? 'text-slate-350' :
            type === 'warn' ? 'text-amber-200' :
            type === 'error' ? 'text-rose-250 font-bold' :
            'text-slate-300'
          }`}>{text}</span>
        </div>
      );
    }

    return (
      <div className="flex items-start gap-2 py-0.5 px-2 hover:bg-slate-800/40 rounded transition font-mono text-[11px] leading-relaxed">
        <span className={`flex-1 break-words font-medium ${
          type === 'info' ? 'text-slate-350' :
          type === 'warn' ? 'text-amber-200' :
          type === 'error' ? 'text-rose-300 font-bold' :
          'text-slate-300'
        }`}>{content}</span>
      </div>
    );
  };

  return (
    <div className="space-y-4">
      {/* Control Panel */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white dark:bg-[#121B2E]/60 border border-gray-200/50 dark:border-gray-800/50 rounded-xl p-4 shadow-sm backdrop-blur-md select-none">
        
        {/* Selector */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 w-full sm:w-auto">
          <label className="text-[10px] font-extrabold text-gray-500 dark:text-gray-400 uppercase tracking-widest flex items-center gap-1.5 shrink-0">
            <Layers className="w-3.5 h-3.5 text-[#378ADD]" />
            Ingested Log Group
          </label>
          <select
            value={selectedGroup}
            onChange={handleGroupChange}
            className="block px-3 py-1.5 text-xs bg-gray-50 dark:bg-[#0E1524]/60 border border-gray-250 dark:border-gray-850 rounded-lg text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-1 focus:ring-[#185FA5] transition font-mono w-full sm:w-72"
          >
            {logGroups.map((g) => (
              <option key={g.logGroupName} value={g.logGroupName}>
                {g.logGroupName}
              </option>
            ))}
          </select>
        </div>

        {/* Refresh button */}
        <button
          onClick={handleRefresh}
          disabled={isLoading || !selectedGroup}
          className="flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-bold text-white bg-[#185FA5] hover:bg-[#134D87] disabled:bg-[#185FA5]/50 shadow-sm rounded-lg transition shrink-0"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Sync Log Streams</span>
        </button>

      </div>

      {/* Terminal Display */}
      <div className="flex flex-col bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl h-[500px]">
        {/* Terminal Header */}
        <div className="flex items-center justify-between bg-slate-900 border-b border-slate-800/60 px-4 py-2.5 select-none shrink-0">
          <div className="flex items-center gap-2">
            {/* Window Controls */}
            <div className="flex gap-1.5">
              <span className="w-3 h-3 rounded-full bg-red-500/80 border border-red-600/30" />
              <span className="w-3 h-3 rounded-full bg-yellow-500/80 border border-yellow-600/30" />
              <span className="w-3 h-3 rounded-full bg-green-500/80 border border-green-600/30" />
            </div>
            <span className="w-px h-3.5 bg-slate-850 mx-1.5" />
            <h4 className="text-[10px] font-bold text-slate-400 font-mono flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-[#378ADD]" />
              logs@{selectedGroup || 'cloudwatch'}
            </h4>
          </div>
          <div className="flex items-center gap-1.5 font-mono text-[9px] text-slate-500">
            <span className="animate-pulse w-1.5 h-1.5 rounded-full bg-emerald-500" />
            <span>LOCALSTACK INGESTION ACTIVE</span>
          </div>
        </div>

        {/* Scrollable logs */}
        <div className="flex-1 overflow-y-auto p-4 space-y-1.5 font-mono min-h-0 bg-slate-950/80 selection:bg-slate-700 selection:text-white scrollbar-thin scrollbar-thumb-slate-800 scrollbar-track-transparent">
          {isLoading && logEvents.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center space-y-2 text-slate-500 text-xs">
              <RefreshCw className="w-6 h-6 animate-spin text-slate-600" />
              <p>Streaming log frames from LocalStack container...</p>
            </div>
          ) : logEvents.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center space-y-1 text-slate-650 text-xs py-8">
              <Terminal className="w-8 h-8 text-slate-700 mb-1" />
              <p className="font-bold text-slate-500">No log streams created</p>
              <p className="text-[10px] text-slate-600 max-w-[340px] text-center mt-1">
                LocalStack has not captured execution outputs for this log group. Click "Run Scan" to invoke Lambda functions and stream logs.
              </p>
            </div>
          ) : (
            <>
              <div className="text-slate-600 text-[10px] font-mono select-none border-b border-slate-900 pb-2 mb-2">
                --- Log stream opened at {new Date(logEvents[0].timestamp).toLocaleString()} ---
              </div>
              
              {logEvents.map((event) => (
                <div key={event.eventId}>
                  {renderLogMessage(event.message)}
                </div>
              ))}
              
              <div className="text-slate-750 text-[10px] font-mono select-none pt-2 border-t border-slate-950 flex items-center gap-1.5 justify-between">
                <span>--- Log stream end [EOF] ---</span>
                <span className="flex items-center gap-1 font-bold text-emerald-500/80 uppercase">
                  Live Listening
                  <span className="w-1 h-1 rounded-full bg-emerald-500 animate-ping" />
                </span>
              </div>
              
              <div ref={terminalEndRef} />
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default CloudWatchLogsView;
