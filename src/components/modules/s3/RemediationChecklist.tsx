import React from 'react';
import type { S3BucketScanResult } from '../../../types/s3';
import { Check, X, ShieldAlert, Sparkles } from 'lucide-react';

interface RemediationChecklistProps {
  bucket: S3BucketScanResult | null;
  onOpenTerraformDrawer: (bucket: S3BucketScanResult) => void;
}

export const RemediationChecklist: React.FC<RemediationChecklistProps> = ({
  bucket,
  onOpenTerraformDrawer
}) => {
  if (!bucket) {
    return (
      <div className="glass-card p-4 flex flex-col h-[280px] items-center justify-center text-center text-xs text-gray-400 select-none">
        <ShieldAlert className="w-8 h-8 text-gray-400 mb-2" />
        <p className="font-semibold text-gray-650">No bucket selected</p>
        <p className="text-[10px] text-gray-500 max-w-[200px] mt-0.5">
          Select an S3 bucket from the list above to view remediation and compliance status
        </p>
      </div>
    );
  }

  // Define checklist items based on bucket compliance checks
  const checklistItems = [
    {
      id: 'pab',
      label: 'S3 Public Access Blocks Enabled (blockPublicAcls & blockPublicPolicy)',
      passed: bucket.checks.blockPublicAcls && bucket.checks.blockPublicPolicy,
      description: 'Stops external user ACL mappings and prevents public read bucket policies'
    },
    {
      id: 'principal',
      label: 'No Wildcard Public Principal Allowed (Principal: "*")',
      passed: bucket.checks.noPublicPolicyPrincipal,
      description: 'Restricts full open read/write access to root account or specific federated users'
    },
    {
      id: 'acl',
      label: 'No Permissive Public ACL Grantees (PublicRead/PublicReadWrite)',
      passed: bucket.checks.noPublicAcl,
      description: 'Prevents direct object exposure from specific AllUsers XML tags'
    },
    {
      id: 'website',
      label: 'Static Website Endpoint Disabled',
      passed: bucket.checks.websiteDisabled,
      description: 'Blocks index.html HTTP listing unless flagged for specific static review'
    }
  ];

  const passedCount = checklistItems.filter(item => item.passed).length;
  const isCompliant = passedCount === 4;

  return (
    <div className="glass-card p-4 flex flex-col h-[280px] justify-between select-none">
      
      {/* Title */}
      <div className="flex items-center justify-between pb-2.5 border-b border-gray-100 dark:border-gray-800/60 shrink-0">
        <div>
          <h3 className="text-xs font-black uppercase tracking-widest text-gray-900 dark:text-white">
            Remediation Checklist
          </h3>
          <span className="text-[9px] font-mono text-gray-400">
            Selected bucket: {bucket.name}
          </span>
        </div>
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded font-mono ${
          isCompliant 
            ? 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/15' 
            : 'bg-red-500/10 text-[#E24B4A] border border-red-500/15'
        }`}>
          {passedCount}/4 Compliance checks passed
        </span>
      </div>

      {/* Checklist items */}
      <div className="flex-1 overflow-y-auto pt-3.5 space-y-3 pr-0.5">
        {checklistItems.map((item) => (
          <div key={item.id} className="flex items-start gap-3">
            {/* Pass/Fail Indicator */}
            <div className={`mt-0.5 p-0.5 rounded-full shrink-0 border ${
              item.passed 
                ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' 
                : 'bg-red-500/10 text-[#E24B4A] border-red-500/20'
            }`}>
              {item.passed ? <Check className="w-3.5 h-3.5" /> : <X className="w-3.5 h-3.5" />}
            </div>
            
            {/* Labels */}
            <div className="space-y-0.5">
              <span className={`text-xs font-bold leading-none ${
                item.passed ? 'text-gray-700 dark:text-gray-250' : 'text-gray-800 dark:text-gray-100'
              }`}>
                {item.label}
              </span>
              <p className="text-[10px] text-gray-400 dark:text-gray-500 leading-normal">
                {item.description}
              </p>
            </div>
          </div>
        ))}
      </div>

      {/* Action Footer */}
      <div className="pt-2 border-t border-gray-100 dark:border-gray-800/60 shrink-0 flex items-center justify-between gap-4">
        <span className="text-[9px] text-gray-450 dark:text-gray-400">
          Remediation generates standard AWS Terraform declarations.
        </span>
        {!isCompliant && (
          <button
            onClick={() => onOpenTerraformDrawer(bucket)}
            className="flex items-center gap-1 px-3 py-1.5 text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-700 shadow-sm rounded-lg hover:shadow transition"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Fix with Terraform</span>
          </button>
        )}
      </div>
      
    </div>
  );
};

export default RemediationChecklist;
