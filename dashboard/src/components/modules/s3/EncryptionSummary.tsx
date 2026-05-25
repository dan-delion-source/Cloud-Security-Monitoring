import React from 'react';
import type { S3BucketScanResult } from '../../../types/s3';
import { formatFraction, formatPercentage } from '../../../utils/formatters';
import { ShieldCheck, Layers, Key, CheckCircle2 } from 'lucide-react';

interface EncryptionSummaryProps {
  buckets: S3BucketScanResult[];
}

export const EncryptionSummary: React.FC<EncryptionSummaryProps> = ({ buckets }) => {
  const total = buckets.length;
  
  // Count stats
  const kmsCount = buckets.filter((b) => b.encryptionType === 'SSE-KMS').length;
  const versioningCount = buckets.filter((b) => b.checks.versioningEnabled).length;

  const kmsFraction = formatFraction(kmsCount, total);
  const versioningFraction = formatFraction(versioningCount, total);
  
  const kmsPercent = formatPercentage(kmsCount, total);
  const versioningPercent = formatPercentage(versioningCount, total);

  return (
    <div className="glass-card p-4 flex flex-col h-[280px] justify-between select-none">
      
      {/* Header */}
      <div className="flex items-center justify-between pb-2.5 border-b border-gray-100 dark:border-gray-800/60 shrink-0">
        <h3 className="text-xs font-black uppercase tracking-widest text-gray-900 dark:text-white flex items-center gap-1.5">
          <ShieldCheck className="w-4 h-4 text-emerald-500" />
          System Security Summary
        </h3>
        <span className="text-[10px] text-gray-400 font-mono">
          Aggregate posture
        </span>
      </div>

      {/* Grid of fraction cards */}
      <div className="grid grid-cols-2 gap-3.5 flex-1 pt-3.5 min-h-0">
        
        {/* SSE-KMS card */}
        <div className="bg-gray-50 dark:bg-[#121B2F]/30 hover:bg-gray-100/60 dark:hover:bg-[#15213b]/45 border border-gray-150 dark:border-gray-850 rounded-xl p-3 flex flex-col justify-between transition duration-200">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-extrabold tracking-wide text-gray-500 dark:text-gray-400">
              SSE-KMS Encryption
            </span>
            <Key className="w-4 h-4 text-[#378ADD] shrink-0" />
          </div>
          <div>
            <div className="text-xl font-black text-gray-900 dark:text-white font-mono leading-none tracking-tight">
              {kmsFraction}
            </div>
            <span className="text-[9px] font-bold text-gray-450 dark:text-gray-400 mt-1 block">
              {kmsPercent} buckets utilize KMS
            </span>
          </div>
        </div>

        {/* Object Versioning card */}
        <div className="bg-gray-50 dark:bg-[#121B2F]/30 hover:bg-gray-100/60 dark:hover:bg-[#15213b]/45 border border-gray-150 dark:border-gray-850 rounded-xl p-3 flex flex-col justify-between transition duration-200">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-extrabold tracking-wide text-gray-500 dark:text-gray-400">
              Object Versioning
            </span>
            <Layers className="w-4 h-4 text-[#EF9F27] shrink-0" />
          </div>
          <div>
            <div className="text-xl font-black text-gray-900 dark:text-white font-mono leading-none tracking-tight">
              {versioningFraction}
            </div>
            <span className="text-[9px] font-bold text-gray-450 dark:text-gray-400 mt-1 block">
              {versioningPercent} versioning active
            </span>
          </div>
        </div>

      </div>

      {/* Aggregate compliance card */}
      <div className="mt-3.5 p-2 bg-emerald-500/[0.03] border border-emerald-500/15 rounded-lg flex items-center justify-between text-[10px] text-emerald-600 dark:text-emerald-400 font-mono shrink-0">
        <div className="flex items-center gap-1.5">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0 animate-pulse" />
          <span>Active check coverage:</span>
        </div>
        <span className="font-bold">100% of discovered S3 resource paths</span>
      </div>

    </div>
  );
};

export default EncryptionSummary;
