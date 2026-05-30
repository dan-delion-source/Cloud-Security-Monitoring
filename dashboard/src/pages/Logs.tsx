import React, { useState } from 'react';
import { useCloudTrail } from '../hooks/useCloudTrail';
import FilterBar from '../components/shared/FilterBar';
import LogTable from '../components/modules/logs/LogTable';
import CloudWatchLogsView from '../components/modules/logs/CloudWatchLogsView';
import { FileSpreadsheet, Terminal } from 'lucide-react';

export const Logs: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'cloudtrail' | 'cloudwatch'>('cloudtrail');
  
  // Call CloudTrail polling hook
  useCloudTrail();

  return (
    <div className="space-y-4">
      {/* Tab Navigation */}
      <div className="flex bg-slate-100 dark:bg-[#121B2F]/60 border border-gray-200/50 dark:border-gray-800/40 p-1.5 rounded-xl max-w-md shadow-sm backdrop-blur-md select-none">
        
        {/* CloudTrail S3 Tab */}
        <button
          onClick={() => setActiveTab('cloudtrail')}
          className={`flex items-center justify-center gap-2 flex-1 py-2 text-xs font-bold rounded-lg transition-all ${
            activeTab === 'cloudtrail'
              ? 'bg-[#185FA5] text-white shadow-sm'
              : 'text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200'
          }`}
        >
          <FileSpreadsheet className="w-4 h-4" />
          <span>CloudTrail Logs (S3)</span>
        </button>

        {/* CloudWatch Lambda Tab */}
        <button
          onClick={() => setActiveTab('cloudwatch')}
          className={`flex items-center justify-center gap-2 flex-1 py-2 text-xs font-bold rounded-lg transition-all ${
            activeTab === 'cloudwatch'
              ? 'bg-[#185FA5] text-white shadow-sm'
              : 'text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200'
          }`}
        >
          <Terminal className="w-4 h-4" />
          <span>CloudWatch Ingestion</span>
        </button>

      </div>

      {/* Tab Contents */}
      {activeTab === 'cloudtrail' ? (
        <div className="space-y-4">
          {/* Search and Severity Filter Bar */}
          <FilterBar />
          
          {/* High-Performance Virtual Log Table */}
          <LogTable />
        </div>
      ) : (
        <CloudWatchLogsView />
      )}
      
    </div>
  );
};

export default Logs;
