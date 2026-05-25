import React from 'react';
import { useSecurityStore } from '../../../store/securityStore';
import { Globe, ShieldAlert } from 'lucide-react';

interface IpRank {
  ip: string;
  count: number;
}

export const TopSourceIps: React.FC = () => {
  const { unauthorizedEvents } = useSecurityStore();

  // Aggregate IP frequencies
  const getRankedIps = (): IpRank[] => {
    const counts: Record<string, number> = {};
    
    unauthorizedEvents.forEach((e) => {
      if (e.sourceIP) {
        counts[e.sourceIP] = (counts[e.sourceIP] || 0) + 1;
      }
    });

    return Object.keys(counts)
      .map((ip) => ({ ip, count: counts[ip] }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5); // top 5
  };

  const rankedIps = getRankedIps();

  return (
    <div className="glass-card p-4 flex flex-col h-[255px] select-none">
      
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800/60 shrink-0">
        <h3 className="text-xs font-black uppercase tracking-widest text-gray-900 dark:text-white flex items-center gap-1.5">
          <Globe className="w-4 h-4 text-[#378ADD]" />
          Top Offending Source IPs
        </h3>
        <span className="text-[10px] text-gray-400 font-mono">
          Ranked by hit frequency
        </span>
      </div>

      {/* Rank List */}
      <div className="flex-1 overflow-y-auto pt-3 space-y-2 pr-0.5">
        {rankedIps.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-xs text-gray-400">
            <p className="font-semibold">No boundary hits reported</p>
          </div>
        ) : (
          rankedIps.map((item, idx) => (
            <div
              key={item.ip}
              className="flex items-center justify-between p-2 bg-gray-50/50 dark:bg-[#121B2F]/20 hover:bg-gray-150 dark:hover:bg-[#15213b]/30 rounded-lg border border-gray-100/50 dark:border-gray-850/50 text-xs transition duration-200"
            >
              <div className="flex items-center gap-3">
                {/* Index badge */}
                <span className="w-5 h-5 flex items-center justify-center font-bold text-[10px] rounded-md bg-gray-200/60 dark:bg-slate-800 text-gray-600 dark:text-slate-400">
                  {idx + 1}
                </span>
                
                {/* Monospace IP */}
                <span className="font-mono font-semibold text-gray-850 dark:text-gray-200">
                  {item.ip}
                </span>
              </div>

              {/* Hit Counter Badge */}
              <span className="inline-flex items-center gap-1 font-mono font-bold text-[10px] px-2 py-0.5 rounded bg-red-500/10 dark:bg-red-500/5 border border-red-500/15 text-[#E24B4A]">
                <ShieldAlert className="w-3 h-3 text-[#E24B4A] shrink-0" />
                {item.count} {item.count === 1 ? 'hit' : 'hits'}
              </span>
            </div>
          ))
        )}
      </div>

    </div>
  );
};

export default TopSourceIps;
