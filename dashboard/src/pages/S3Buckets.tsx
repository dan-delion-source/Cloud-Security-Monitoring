import React, { useState, useEffect } from 'react';
import { useS3Scanner } from '../hooks/useS3Scanner';
import { useSecurityStore } from '../store/securityStore';
import type { S3BucketScanResult } from '../types/s3';
import BucketList from '../components/modules/s3/BucketList';
import RemediationChecklist from '../components/modules/s3/RemediationChecklist';
import EncryptionSummary from '../components/modules/s3/EncryptionSummary';
import { Terminal, Copy, Check, ShieldAlert } from 'lucide-react';

export const S3Buckets: React.FC = () => {
  // Activate S3 resource scanner hook
  useS3Scanner();

  const { buckets, remediateBucket } = useSecurityStore();
  const [selectedBucketId, setSelectedBucketId] = useState<string | null>(null);
  const [terraformBucket, setTerraformBucket] = useState<S3BucketScanResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [applying, setApplying] = useState(false);

  // Default select first bucket if none selected
  useEffect(() => {
    if (buckets.length > 0 && selectedBucketId === null) {
      setSelectedBucketId(buckets[0].id);
    }
  }, [buckets, selectedBucketId]);

  const selectedBucket = buckets.find(b => b.id === selectedBucketId) || null;

  const terraformCode = terraformBucket ? `provider "aws" {
  region = "${terraformBucket.region}"
}

# 1. Base Remediated S3 Resource
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "${terraformBucket.name}"
}

# 2. Strict Public Access Isolation Block
resource "aws_s3_bucket_public_access_block" "remediated_pab" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 3. Default SSE-KMS Server Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "remediated_sse" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# 4. Strict Object Versioning Track
resource "aws_s3_bucket_versioning" "remediated_versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}` : '';

  const handleCopy = () => {
    navigator.clipboard.writeText(terraformCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleApplyRemediation = () => {
    if (!terraformBucket) return;
    setApplying(true);
    
    // Simulate API delay
    setTimeout(() => {
      remediateBucket(terraformBucket.id);
      setApplying(false);
      setTerraformBucket(null);
    }, 1500);
  };

  return (
    <div className="space-y-4">
      
      {/* Top: Bucket resource list */}
      <BucketList
        buckets={buckets}
        selectedBucketId={selectedBucketId}
        onSelectBucket={setSelectedBucketId}
      />

      {/* Bottom: Checklist & posture metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        
        <RemediationChecklist
          bucket={selectedBucket}
          onOpenTerraformDrawer={(b) => setTerraformBucket(b)}
        />

        <EncryptionSummary buckets={buckets} />

      </div>

      {/* Terraform Remediation overlay Drawer */}
      {terraformBucket && (
        <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/60 backdrop-blur-sm select-none">
          <div className="w-full max-w-xl h-full bg-white dark:bg-[#0E1524] border-l border-gray-200 dark:border-gray-800 shadow-2xl flex flex-col justify-between">
            
            {/* Drawer Header */}
            <div className="p-4 border-b border-gray-200 dark:border-gray-850 flex items-center justify-between bg-gray-50 dark:bg-[#121B2F]/60">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-indigo-500" />
                <div>
                  <h3 className="text-xs font-black uppercase tracking-wider text-gray-900 dark:text-white leading-none">
                    Terraform Remediation Plan
                  </h3>
                  <span className="text-[9px] font-mono text-gray-500">
                    Fixing bucket: {terraformBucket.name}
                  </span>
                </div>
              </div>
              <button
                onClick={() => setTerraformBucket(null)}
                className="text-xs font-bold text-gray-500 hover:text-gray-900 dark:hover:text-white"
              >
                Cancel
              </button>
            </div>

            {/* Code Body */}
            <div className="p-4 flex-1 overflow-y-auto space-y-4">
              
              <div className="p-3 bg-indigo-500/[0.03] border border-indigo-500/10 text-[10px] text-gray-650 dark:text-gray-400 rounded-lg flex items-start gap-2.5 leading-normal">
                <ShieldAlert className="w-4 h-4 text-indigo-500 shrink-0 mt-0.5" />
                <span>
                  The following declaration configures S3 public block filters, forces AES/KMS server defaults, and binds object logs to versioned tracks. Paste this HCL into your local Terraform deployment stack.
                </span>
              </div>

              {/* Code block */}
              <div className="relative rounded-lg overflow-hidden border border-gray-250 dark:border-gray-850">
                <button
                  onClick={handleCopy}
                  className="absolute top-3.5 right-3.5 p-1.5 rounded-md bg-gray-900/80 text-gray-400 hover:text-white border border-gray-800 transition"
                  title="Copy Terraform HCL"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
                <pre className="bg-gray-950 text-gray-100 p-4 text-[11px] font-mono overflow-x-auto leading-relaxed max-h-[380px]">
                  {terraformCode}
                </pre>
              </div>

            </div>

            {/* Drawer Footer Actions */}
            <div className="p-4 border-t border-gray-200 dark:border-gray-850 bg-gray-50 dark:bg-[#121B2F]/60 flex items-center justify-between gap-4">
              <span className="text-[9px] text-gray-400 leading-normal">
                Apply fixes to AWS immediately inside CloudSentinel.
              </span>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => setTerraformBucket(null)}
                  className="px-3.5 py-1.5 text-xs font-bold text-gray-600 dark:text-gray-300 hover:bg-gray-150 dark:hover:bg-gray-800 rounded-lg border border-gray-250 dark:border-gray-700 transition"
                >
                  Cancel
                </button>
                <button
                  onClick={handleApplyRemediation}
                  disabled={applying}
                  className="px-4 py-1.5 text-xs font-bold text-white bg-indigo-650 hover:bg-indigo-700 disabled:bg-indigo-650/50 shadow-sm rounded-lg transition"
                >
                  {applying ? 'Remediating...' : 'Apply Remediation'}
                </button>
              </div>
            </div>

          </div>
        </div>
      )}

    </div>
  );
};

export default S3Buckets;
