import React from 'react';
import { useVpcFlowLogs } from '../hooks/useVpcFlowLogs';
import AccessFeed from '../components/modules/access/AccessFeed';
import AccessBarChart from '../components/modules/access/AccessBarChart';
import TopSourceIps from '../components/modules/access/TopSourceIps';

export const UnauthorizedAccess: React.FC = () => {
  // Activate VPC flow logs scan + mock generator
  useVpcFlowLogs();

  return (
    <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
      
      {/* Left Column: Boundary Threat Feed (Spans 3/5 cols) */}
      <div className="lg:col-span-3">
        <AccessFeed />
      </div>

      {/* Right Column: Analytics & Ranked IPs (Spans 2/5 cols) */}
      <div className="lg:col-span-2 flex flex-col gap-4">
        <AccessBarChart />
        <TopSourceIps />
      </div>

    </div>
  );
};

export default UnauthorizedAccess;
