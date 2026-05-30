import React from 'react';
import { useIamReport } from '../hooks/useIamReport';
import { useSecurityStore } from '../store/securityStore';
import IamFindingCard from '../components/modules/iam/IamFindingCard';
import IamSummary from '../components/modules/iam/IamSummary';
import { ShieldAlert, Users, CheckCircle2, AlertTriangle } from 'lucide-react';

export const IamMisuse: React.FC = () => {
  // Activate IAM anomaly check hook, extracting liveUsers from LocalStack
  const { liveUsers } = useIamReport();

  const { iamAnomalies } = useSecurityStore();

  return (
    <div className="space-y-4">
      {/* Live Directory Section */}
      <div className="glass-card p-5 space-y-4 select-none">
        <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800/60">
          <div className="flex items-center gap-2">
            <Users className="w-5 h-5 text-[#185FA5]" />
            <div>
              <h3 className="text-xs font-black uppercase tracking-widest text-gray-900 dark:text-white leading-none">
                Live IAM Identity Inventory
              </h3>
              <span className="text-[9px] text-gray-400 font-mono mt-0.5 block">
                Real-time security auditing of active LocalStack IAM users
              </span>
            </div>
          </div>
          <span className="text-[9px] bg-blue-500/10 text-blue-500 px-2 py-0.5 rounded font-mono font-bold animate-pulse">
            LocalStack IAM Active
          </span>
        </div>

        {/* Directory Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {liveUsers.map((user) => (
            <div 
              key={user.userName}
              className={`p-4 border rounded-xl bg-gray-50/30 dark:bg-[#121B2F]/20 flex flex-col justify-between space-y-3.5 transition-all hover:shadow-md ${
                user.complianceStatus === 'NON_COMPLIANT'
                  ? 'border-red-500/20 hover:border-red-500/30'
                  : 'border-emerald-500/20 hover:border-emerald-500/30'
              }`}
            >
              {/* Header Info */}
              <div className="flex items-start justify-between gap-2">
                <div className="space-y-0.5 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-black text-gray-900 dark:text-white font-mono truncate">
                      {user.userName}
                    </span>
                    {user.complianceStatus === 'NON_COMPLIANT' ? (
                      <span className="flex items-center gap-0.5 text-[8px] font-black uppercase px-1.5 py-0.2 bg-red-500/10 text-red-500 border border-red-500/10 rounded animate-pulse shrink-0">
                        <AlertTriangle className="w-2.5 h-2.5" />
                        Breach
                      </span>
                    ) : (
                      <span className="flex items-center gap-0.5 text-[8px] font-black uppercase px-1.5 py-0.2 bg-emerald-500/10 text-emerald-500 border border-emerald-500/10 rounded shrink-0">
                        <CheckCircle2 className="w-2.5 h-2.5" />
                        Compliant
                      </span>
                    )}
                  </div>
                  <p className="text-[9px] text-gray-400 font-mono truncate">
                    {user.arn}
                  </p>
                </div>
              </div>

              {/* MFA & Policies */}
              <div className="space-y-2 text-[10px]">
                {/* MFA Details */}
                <div className="flex items-center justify-between border-b border-gray-150/40 dark:border-gray-800/40 pb-1.5">
                  <span className="text-gray-400 font-semibold uppercase tracking-wider text-[8px]">MFA Device</span>
                  {user.mfaActive ? (
                    <span className="text-emerald-500 font-bold flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                      Active (Virtual)
                    </span>
                  ) : (
                    <span className="text-amber-500 font-bold flex items-center gap-1 animate-pulse">
                      <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                      Disabled
                    </span>
                  )}
                </div>

                {/* Attached Policies */}
                <div className="space-y-1">
                  <span className="text-gray-400 font-semibold uppercase tracking-wider text-[8px] block">Attached User Policies</span>
                  <div className="flex flex-wrap gap-1 max-h-[50px] overflow-y-auto">
                    {user.attachedPolicies.length === 0 ? (
                      <span className="text-[9px] text-gray-500 font-mono italic">No policies attached</span>
                    ) : (
                      user.attachedPolicies.map(policy => {
                        const isAdmin = policy.includes('AdministratorAccess');
                        return (
                          <span 
                            key={policy}
                            className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
                              isAdmin
                                ? 'bg-red-500/10 text-red-500 border border-red-500/20'
                                : 'bg-gray-100 dark:bg-slate-800 text-gray-600 dark:text-slate-350 border border-gray-200 dark:border-gray-800/60'
                            }`}
                          >
                            {policy}
                          </span>
                        );
                      })
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
      
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
