import React from 'react';
import { useIamReport } from '../hooks/useIamReport';
import { useSecurityStore } from '../store/securityStore';
import IamFindingCard from '../components/modules/iam/IamFindingCard';
import IamSummary from '../components/modules/iam/IamSummary';
import { ShieldAlert } from 'lucide-react';

export const IamMisuse: React.FC = () => {
  // Activate IAM anomaly check hook
  useIamReport();

  const { iamAnomalies } = useSecurityStore();

  return (
    <div className="space-y-4">
      
      {/* Dynamic Finding Cards List */}
      <div className="space-y-3">
        {iamAnomalies.length === 0 ? (
          <div className="glass-card p-8 flex flex-col items-center justify-center text-center text-xs text-gray-400 space-y-2 select-none h-[220px]">
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 rounded-full">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <p className="font-semibold text-gray-700 dark:text-gray-300">Identity boundary secure</p>
              <p className="text-[10px] text-gray-500">No compromised credentials or IAM misconfigurations found.</p>
            </div>
          </div>
        ) : (
          iamAnomalies.map((finding) => (
            <IamFindingCard key={finding.id} finding={finding} />
          ))
        )}
      </div>

      {/* IAM Compliance Posture & CDK Stack Generator */}
      <IamSummary />

    </div>
  );
};

export default IamMisuse;
