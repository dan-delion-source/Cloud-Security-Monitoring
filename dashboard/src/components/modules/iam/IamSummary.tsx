import React, { useState } from 'react';
import { useSecurityStore } from '../../../store/securityStore';
import { Shield, Sparkles, Terminal, Copy, Check, Info } from 'lucide-react';

export const IamSummary: React.FC = () => {
  const { iamAnomalies } = useSecurityStore();
  const [copied, setCopied] = useState(false);
  const [showCdkDrawer, setShowCdkDrawer] = useState(false);

  const criticalFindings = iamAnomalies.filter(i => i.severity === 'CRITICAL').length;
  const highFindings = iamAnomalies.filter(i => i.severity === 'HIGH').length;
  const mediumFindings = iamAnomalies.filter(i => i.severity === 'MEDIUM').length;

  const cdkCode = `import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as events from 'aws-cdk-lib/aws-events';
import * as sns from 'aws-cdk-lib/aws-sns';
import { Construct } from 'constructs';

export class IamDetectionStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // 1. Threat Alert Topic
    const alertTopic = new sns.Topic(this, 'SentinelIamAlerts', {
      displayName: 'CloudSentinel IAM Abuse Alerts',
    });

    // 2. Event Rule: Root Console Login Attempt
    const rootLoginRule = new events.Rule(this, 'RootLoginDetection', {
      description: 'Alert when AWS Root Account performs a ConsoleLogin',
      eventPattern: {
        source: ['aws.signin'],
        detailType: ['AWS Console Sign-in via CloudTrail'],
        detail: {
          eventSource: ['signin.amazonaws.com'],
          eventName: ['ConsoleLogin'],
          userIdentity: {
            type: ['Root'],
          },
        },
      },
    });
    rootLoginRule.addTarget(new targets.SnsTopic(alertTopic));

    // 3. Event Rule: IAM Privilege Escalation Pattern (PassRole + CreateFunction)
    const privEscalationRule = new events.Rule(this, 'PrivilegeEscalationDetection', {
      description: 'Alert on combined PassRole and Lambda actions',
      eventPattern: {
        source: ['aws.iam', 'aws.lambda'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventName: ['PassRole', 'CreateFunction20150331', 'RunInstances'],
        },
      },
    });
    privEscalationRule.addTarget(new targets.SnsTopic(alertTopic));
  }
}`;

  const handleCopy = () => {
    navigator.clipboard.writeText(cdkCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="glass-card p-4 space-y-4 select-none">
      
      {/* Metric summary banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-3.5 bg-gray-50 dark:bg-[#121B2F]/30 border border-gray-150 dark:border-gray-850 rounded-xl text-xs">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-indigo-500/10 text-indigo-500 rounded-lg shrink-0 border border-indigo-500/10">
            <Shield className="w-5 h-5 shrink-0" />
          </div>
          <div>
            <h4 className="font-extrabold text-gray-900 dark:text-white uppercase tracking-wider">
              Identity Access Management Audit
            </h4>
            <p className="text-[10px] text-gray-500 dark:text-gray-400 mt-0.5 leading-normal">
              Active checks monitor credential age, root activities, cross-account assume-roles, and privilege escalation patterns.
            </p>
          </div>
        </div>

        {/* Counts banner */}
        <div className="flex items-center gap-4 text-xs font-mono shrink-0">
          <div className="text-center">
            <span className="text-[10px] text-gray-500 dark:text-gray-400 block mb-0.5">Critical Risks</span>
            <span className="font-extrabold text-[#E24B4A]">{criticalFindings}</span>
          </div>
          <div className="w-px h-6 bg-gray-200 dark:bg-gray-800" />
          <div className="text-center">
            <span className="text-[10px] text-gray-500 dark:text-gray-400 block mb-0.5">High Risks</span>
            <span className="font-extrabold text-[#EF9F27]">{highFindings}</span>
          </div>
          <div className="w-px h-6 bg-gray-200 dark:bg-gray-800" />
          <div className="text-center">
            <span className="text-[10px] text-gray-500 dark:text-gray-400 block mb-0.5">Medium Risks</span>
            <span className="font-extrabold text-[#378ADD]">{mediumFindings}</span>
          </div>
        </div>
      </div>

      {/* Main Action Footer */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2 border-t border-gray-100 dark:border-gray-800/60">
        <span className="text-[10px] text-gray-500 dark:text-gray-400 leading-normal text-center sm:text-left">
          Deploy sentinel patterns directly in your cloud using AWS CDK.
        </span>
        <button
          onClick={() => setShowCdkDrawer(true)}
          className="flex items-center gap-1.5 px-4 py-2 text-xs font-bold text-white bg-[#185FA5] hover:bg-[#134D87] shadow-sm rounded-lg hover:shadow transition"
        >
          <Sparkles className="w-4 h-4 shrink-0" />
          <span>Generate IAM detection CDK stack ↗</span>
        </button>
      </div>

      {/* CDK Generation Drawer Modal */}
      {showCdkDrawer && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-[#0E1524] border border-gray-200 dark:border-gray-800 rounded-xl max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
            
            {/* Header */}
            <div className="p-4 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between bg-gray-50 dark:bg-[#121B2F]/60">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-indigo-500" />
                <h3 className="text-xs font-black uppercase tracking-widest text-gray-900 dark:text-white">
                  AWS CDK Detection Stack
                </h3>
              </div>
              <button 
                onClick={() => setShowCdkDrawer(false)}
                className="text-xs font-bold text-gray-500 hover:text-gray-900 dark:hover:text-white"
              >
                Close
              </button>
            </div>

            {/* Code Body */}
            <div className="p-4 overflow-y-auto space-y-3.5 flex-1">
              <div className="p-3 bg-indigo-500/[0.03] border border-indigo-500/10 text-[10px] text-gray-600 dark:text-gray-400 rounded-lg flex items-start gap-2.5 leading-normal">
                <Info className="w-4 h-4 text-indigo-500 shrink-0 mt-0.5" />
                <span>
                  This construct deploys automated EventBridge rules that evaluate real-time API traces, triggering SNS alarms immediately upon critical Root console logins or passrole sequences.
                </span>
              </div>

              <div className="relative rounded-lg overflow-hidden border border-gray-200 dark:border-gray-850">
                <button
                  onClick={handleCopy}
                  className="absolute top-3.5 right-3.5 p-1.5 rounded-md bg-gray-900/80 text-gray-400 hover:text-white border border-gray-800 transition"
                  title="Copy stack code"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
                <pre className="bg-gray-950 text-gray-100 p-4 text-[11px] font-mono overflow-x-auto leading-relaxed max-h-[350px]">
                  {cdkCode}
                </pre>
              </div>
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-gray-200 dark:border-gray-850 flex justify-end bg-gray-50 dark:bg-[#121B2F]/60">
              <button
                onClick={() => setShowCdkDrawer(false)}
                className="px-4 py-1.5 text-xs font-bold text-gray-700 dark:text-gray-300 hover:bg-gray-150 dark:hover:bg-gray-800 rounded-lg border border-gray-250 dark:border-gray-700 transition"
              >
                Done
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
};

export default IamSummary;
