import React from 'react';
import { useSecurityStore } from '../../../store/securityStore';
import { X, AlertOctagon, Terminal } from 'lucide-react';
import { formatDateRelative } from '../../../utils/formatters';

export const AlertFeed: React.FC = () => {
  const { activeAlerts, dismissAlert } = useSecurityStore();

  // Show only non-dismissed alerts, limit to 4
  const visibleAlerts = activeAlerts.filter(a => !a.dismissed).slice(0, 4);

  return (
    <div className="glass-card p-4 flex flex-col h-[320px] select-none">
      
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800/60 shrink-0">
        <h3 className="text-xs font-black uppercase tracking-widest text-gray-900 dark:text-white flex items-center gap-1.5">
          <AlertOctagon className="w-4 h-4 text-[#E24B4A]" />
          Active Incident Feed
        </h3>
        <span className="text-[10px] text-gray-400 font-mono">
          {visibleAlerts.length} active alerts
        </span>
      </div>

      {/* Feed Contents */}
      <div className="flex-1 overflow-y-auto pt-3 space-y-3 pr-0.5">
        {visibleAlerts.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center text-xs text-gray-400 space-y-2">
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 rounded-full">
              <AlertOctagon className="w-5 h-5" />
            </div>
            <div>
              <p className="font-semibold text-gray-700 dark:text-gray-300">All boundaries clean</p>
              <p className="text-[10px] text-gray-500">No active high or critical incidents reported</p>
            </div>
          </div>
        ) : (
          visibleAlerts.map((alert) => {
            const borderColors = {
              CRITICAL: 'border-l-4 border-l-[#E24B4A]',
              HIGH: 'border-l-4 border-l-[#EF9F27]',
              MEDIUM: 'border-l-4 border-l-[#378ADD]',
              LOW: 'border-l-4 border-l-[#639922]'
            };

            const leftBorder = borderColors[alert.severity] || 'border-l-4 border-l-gray-400';

            return (
              <div
                key={alert.id}
                className={`relative pl-3 pr-9 py-2.5 bg-gray-50 dark:bg-[#121B2F]/30 hover:bg-gray-100 dark:hover:bg-[#15213b]/45 rounded-r-lg border border-y-gray-200/40 dark:border-y-gray-850/40 border-r-gray-200/40 dark:border-r-gray-850/40 transition duration-200 ${leftBorder}`}
              >
                {/* Dismiss Action */}
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    dismissAlert(alert.id);
                  }}
                  className="absolute top-2 right-2 p-0.5 rounded text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-250 dark:hover:bg-gray-800"
                  aria-label="Dismiss alert"
                >
                  <X className="w-3.5 h-3.5" />
                </button>

                {/* Info */}
                <div className="space-y-1">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] uppercase font-extrabold text-gray-900 dark:text-white truncate max-w-[190px]">
                      {alert.title}
                    </span>
                    <span className="text-[9px] font-bold text-gray-400 font-mono">
                      · {formatDateRelative(alert.timestamp)}
                    </span>
                  </div>
                  <p className="text-[10px] text-gray-500 dark:text-gray-400 leading-normal line-clamp-2">
                    {alert.message}
                  </p>
                  
                  {/* Origin */}
                  <div className="flex items-center gap-1 text-[9px] text-gray-400 font-mono mt-1">
                    <Terminal className="w-3 h-3 text-[#185FA5]" />
                    <span>Source: {alert.source}</span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
      
    </div>
  );
};

export default AlertFeed;
