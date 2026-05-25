import React from 'react';
import { useSecurityStore } from '../../../store/securityStore';
import SeverityDot from '../../shared/SeverityDot';
import { formatDateUTC } from '../../../utils/formatters';
import { ArrowRight, Lock } from 'lucide-react';

export const AccessFeed: React.FC = () => {
  const { unauthorizedEvents, setSelectedEvent } = useSecurityStore();

  // Sort by timestamp desc
  const sortedEvents = [...unauthorizedEvents].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  return (
    <div className="glass-card p-4 flex flex-col h-[520px] select-none">
      
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800/60 shrink-0">
        <h3 className="text-xs font-black uppercase tracking-widest text-gray-900 dark:text-white flex items-center gap-1.5">
          <Lock className="w-4 h-4 text-[#EF9F27]" />
          Boundary Threat Feed
        </h3>
        <span className="text-[10px] text-gray-400 font-mono">
          {sortedEvents.length} events detected
        </span>
      </div>

      {/* Detections List */}
      <div className="flex-1 overflow-y-auto pt-3 space-y-2.5 pr-0.5">
        {sortedEvents.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center text-xs text-gray-400">
            <p className="font-semibold">Network boundary secure</p>
            <p className="text-[10px] text-gray-500">No unauthorized requests or VPC blocks</p>
          </div>
        ) : (
          sortedEvents.map((evt) => (
            <div
              key={evt.id}
              onClick={() => setSelectedEvent({ type: 'unauth', data: evt })}
              className="group flex flex-col md:flex-row md:items-center justify-between gap-3 p-3 bg-gray-50 dark:bg-[#121B2F]/30 hover:bg-gray-100 dark:hover:bg-[#15213b]/45 rounded-lg border border-gray-150 dark:border-gray-850 cursor-pointer transition duration-200"
            >
              {/* Left Info Column */}
              <div className="flex items-start gap-2.5 min-w-0 flex-1">
                <div className="pt-1.5 shrink-0">
                  <SeverityDot severity={evt.severity} />
                </div>
                <div className="space-y-1 min-w-0">
                  <p className="text-xs font-bold text-gray-900 dark:text-gray-100 leading-tight">
                    {evt.description}
                  </p>
                  
                  {/* Source -> Destination */}
                  <div className="flex items-center gap-1.5 text-[10px] text-gray-500 dark:text-gray-400 font-mono">
                    <span className="truncate bg-gray-100 dark:bg-gray-800/80 px-1.5 py-0.5 rounded text-gray-700 dark:text-gray-300">
                      {evt.source}
                    </span>
                    <ArrowRight className="w-3 h-3 text-[#185FA5] shrink-0" />
                    <span className="truncate bg-gray-100 dark:bg-gray-800/80 px-1.5 py-0.5 rounded text-gray-700 dark:text-gray-300">
                      {evt.destination}
                    </span>
                  </div>
                </div>
              </div>

              {/* Right Metadata Column */}
              <div className="md:text-right shrink-0 flex md:flex-col items-center md:items-end justify-between md:justify-center gap-2">
                <span className="text-[9px] font-bold uppercase px-2 py-0.5 rounded bg-gray-200/50 dark:bg-slate-800 text-gray-600 dark:text-slate-400 border border-gray-200/20 dark:border-slate-700/20">
                  {evt.routeType}
                </span>
                <span className="text-[10px] text-gray-400 dark:text-gray-500 font-mono">
                  {formatDateUTC(evt.timestamp).replace(' UTC', '')}
                </span>
              </div>
              
            </div>
          ))
        )}
      </div>
      
    </div>
  );
};

export default AccessFeed;
