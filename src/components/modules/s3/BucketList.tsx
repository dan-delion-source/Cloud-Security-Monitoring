import React from 'react';
import type { S3BucketScanResult } from '../../../types/s3';
import StatusBadge from '../../shared/StatusBadge';
import { Database, ShieldCheck, HelpCircle } from 'lucide-react';

interface BucketListProps {
  buckets: S3BucketScanResult[];
  selectedBucketId: string | null;
  onSelectBucket: (id: string) => void;
}

export const BucketList: React.FC<BucketListProps> = ({
  buckets,
  selectedBucketId,
  onSelectBucket
}) => {
  return (
    <div className="glass-card p-4 flex flex-col h-[320px] select-none">
      
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800/60 shrink-0">
        <h3 className="text-xs font-black uppercase tracking-widest text-gray-900 dark:text-white flex items-center gap-1.5">
          <Database className="w-4 h-4 text-[#185FA5]" />
          Discovered S3 Buckets
        </h3>
        <span className="text-[10px] text-gray-400 font-mono">
          {buckets.length} resources scanned
        </span>
      </div>

      {/* Buckets Rows */}
      <div className="flex-1 overflow-y-auto pt-3 space-y-2 pr-0.5">
        {buckets.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-xs text-gray-450">
            <HelpCircle className="w-6 h-6 mb-1 text-gray-400" />
            <p className="font-semibold">No S3 storage buckets scanned</p>
          </div>
        ) : (
          buckets.map((bucket) => {
            const isSelected = selectedBucketId === bucket.id;
            
            // Icon color based on severity
            const iconColor = 
              bucket.remediated ? 'text-emerald-500' :
              bucket.severity === 'CRITICAL' ? 'text-[#E24B4A]' :
              bucket.severity === 'HIGH' ? 'text-[#EF9F27]' :
              bucket.severity === 'MEDIUM' ? 'text-[#378ADD]' : 'text-[#639922]';

            return (
              <div
                key={bucket.id}
                onClick={() => onSelectBucket(bucket.id)}
                className={`flex flex-col md:flex-row md:items-center justify-between gap-3 p-3 rounded-lg border cursor-pointer transition select-none ${
                  isSelected 
                    ? 'bg-[#185FA5]/10 border-[#185FA5]/40 dark:border-[#378ADD]/45 shadow-sm shadow-[#185FA5]/5' 
                    : 'bg-gray-50 dark:bg-[#121B2F]/30 hover:bg-gray-100 dark:hover:bg-[#15213b]/45 border-gray-150 dark:border-gray-850'
                }`}
              >
                {/* Bucket name */}
                <div className="flex items-center gap-3 min-w-0">
                  {bucket.remediated ? (
                    <ShieldCheck className="w-5 h-5 text-emerald-500 shrink-0" />
                  ) : (
                    <Database className={`w-5 h-5 ${iconColor} shrink-0`} />
                  )}
                  <span className="font-mono text-xs font-semibold text-gray-850 dark:text-gray-250 truncate">
                    {bucket.name}
                  </span>
                </div>

                {/* Risk badges & exposure time */}
                <div className="flex items-center gap-3 shrink-0 justify-between md:justify-end">
                  <div className="flex items-center gap-1.5">
                    {bucket.remediated && (
                      <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">
                        Remediated
                      </span>
                    )}
                    <StatusBadge severity={bucket.severity} />
                  </div>
                  
                  {/* Exposure duration */}
                  <span className="text-[10px] text-gray-450 dark:text-gray-450 font-mono shrink-0">
                    {!bucket.remediated && bucket.exposureDuration !== '0 days'
                      ? `Exposed ${bucket.exposureDuration}` 
                      : 'Compliant'
                    }
                  </span>
                </div>
                
              </div>
            );
          })
        )}
      </div>

    </div>
  );
};

export default BucketList;
