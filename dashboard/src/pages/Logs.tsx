import React from 'react';
import { useCloudTrail } from '../hooks/useCloudTrail';
import FilterBar from '../components/shared/FilterBar';
import LogTable from '../components/modules/logs/LogTable';

export const Logs: React.FC = () => {
  // Call Hook to handle mounts, full scan triggers and log polling
  useCloudTrail();

  return (
    <div className="space-y-4">
      
      {/* Search and Severity Filter Bar */}
      <FilterBar />
      
      {/* High-Performance Virtual Log Table */}
      <LogTable />
      
    </div>
  );
};

export default Logs;
