import React from 'react';
import { useSecurityStore } from '../../store/securityStore';
import type { Severity } from '../../constants/severity';
import { Search, X } from 'lucide-react';

export const FilterBar: React.FC = () => {
  const { logFilter, setLogFilter, logSearchQuery, setLogSearchQuery } = useSecurityStore();

  const severityPills: Array<{ label: string; value: 'ALL' | Severity; color: string }> = [
    { label: 'All Logs', value: 'ALL', color: 'hover:border-gray-400 dark:hover:border-gray-500' },
    { label: 'Critical', value: 'CRITICAL', color: 'border-[#E24B4A]/30 text-[#E24B4A] hover:bg-[#E24B4A]/5' },
    { label: 'High', value: 'HIGH', color: 'border-[#EF9F27]/30 text-[#EF9F27] hover:bg-[#EF9F27]/5' },
    { label: 'Medium', value: 'MEDIUM', color: 'border-[#378ADD]/30 text-[#378ADD] hover:bg-[#378ADD]/5' },
    { label: 'Low', value: 'LOW', color: 'border-[#639922]/30 text-[#639922] hover:bg-[#639922]/5' },
  ];

  return (
    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-white dark:bg-[#121B2E]/60 border border-gray-200/50 dark:border-gray-800/50 rounded-xl p-4 shadow-sm backdrop-blur-md">
      
      {/* Pills Container */}
      <div className="flex flex-wrap items-center gap-2">
        {severityPills.map((pill) => {
          const isActive = logFilter === pill.value;
          
          let activeStyles = 'border-gray-200 dark:border-gray-800 text-gray-600 dark:text-gray-400 bg-transparent';
          if (isActive) {
            if (pill.value === 'ALL') {
              activeStyles = 'border-gray-900 dark:border-gray-200 text-gray-900 dark:text-white bg-gray-100 dark:bg-gray-800';
            } else if (pill.value === 'CRITICAL') {
              activeStyles = 'bg-[#E24B4A] text-white border-[#E24B4A] shadow-sm shadow-[#E24B4A]/25';
            } else if (pill.value === 'HIGH') {
              activeStyles = 'bg-[#EF9F27] text-white border-[#EF9F27] shadow-sm shadow-[#EF9F27]/25';
            } else if (pill.value === 'MEDIUM') {
              activeStyles = 'bg-[#378ADD] text-white border-[#378ADD] shadow-sm shadow-[#378ADD]/25';
            } else if (pill.value === 'LOW') {
              activeStyles = 'bg-[#639922] text-white border-[#639922] shadow-sm shadow-[#639922]/25';
            }
          }

          return (
            <button
              key={pill.value}
              onClick={() => setLogFilter(pill.value)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-200 ${activeStyles} ${!isActive ? pill.color : ''}`}
            >
              {pill.label}
            </button>
          );
        })}
      </div>

      {/* Free Text Search */}
      <div className="relative w-full md:w-80 shrink-0">
        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <Search className="h-4 w-4 text-gray-400" />
        </div>
        <input
          type="text"
          value={logSearchQuery}
          onChange={(e) => setLogSearchQuery(e.target.value)}
          placeholder="Search by event, IP, source or ARN..."
          className="block w-full pl-10 pr-9 py-1.5 text-xs bg-gray-50 dark:bg-[#0E1524]/60 border border-gray-200 dark:border-gray-800 rounded-lg text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-[#185FA5] focus:border-[#185FA5] transition"
        />
        {logSearchQuery && (
          <button
            onClick={() => setLogSearchQuery('')}
            className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
            aria-label="Clear search"
          >
            <X className="h-3 w-3" />
          </button>
        )}
      </div>
      
    </div>
  );
};

export default FilterBar;
