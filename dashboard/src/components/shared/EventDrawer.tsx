import React, { useState } from 'react';
import { useSecurityStore } from '../../store/securityStore';
import { X, Sparkles } from 'lucide-react';
import { formatDateUTC } from '../../utils/formatters';

export const EventDrawer: React.FC = () => {
  const { selectedEvent, setSelectedEvent } = useSecurityStore();
  const [aiReport, setAiReport] = useState<string | null>(null);
  const [isAiLoading, setIsAiLoading] = useState(false);

  if (!selectedEvent) return null;

  const { type, data } = selectedEvent;

  // Extract raw JSON string or stringify data if not already string
  const rawJson = data.rawJson || data.rawEvent || JSON.stringify(data, null, 2);

  const handleClose = () => {
    setSelectedEvent(null);
    setAiReport(null);
  };

  const handleAiInvestigate = () => {
    setIsAiLoading(true);
    setAiReport(null);
    
    // Simulate real-time AI analysis with highly relevant context!
    setTimeout(() => {
      let analysis = '';
      if (type === 'log' && data.eventName === 'ConsoleLogin') {
        analysis = `### 🚨 ROOT LOG-IN ANALYSIS\n\n**Incident Severity**: CRITICAL\n\n**Findings**:\n- Root account logged in from IP **${data.sourceIP}** without Multi-Factor Authentication (MFA).\n\n**Remediation Steps**:\n1. Revoke the active session immediately via IAM Console.\n2. Enable strict Virtual or Hardware MFA on Root account.\n3. Implement SCP (Service Control Policy) to deny root access globally except under secure glass-breaker accounts.`;
      } else if (type === 's3') {
        analysis = `### 📂 S3 BUCKET EXPOSURE REPORT\n\n**Incident Severity**: ${data.severity}\n\n**Findings**:\n- Public access blocks are disabled.\n- Policy allows open permissions for "**Principal: ***".\n\n**Remediation Steps**:\n1. Apply strict S3 Public Access Blocks using the generated Terraform HCL.\n2. Restrict Bucket Policy to trusted IAM roles or specific VPC endpoints.`;
      } else if (type === 'iam' && data.pattern === 'passrole_privesc') {
        analysis = `### 🛡️ PRIVILEGE ESCALATION PATTERN DETECTED\n\n**Incident Severity**: CRITICAL\n\n**Findings**:\n- Caller invoked \`iam:PassRole\` and launched a Lambda function within a 5-minute session window.\n- This allows a restricted role to execute code using an Admin-level Service Role.\n\n**Remediation Steps**:\n1. Restrict \`iam:PassRole\` using resources-based limits in DevOperator policy.\n2. Review runtime code for backdoor function "**${data.detail.split(' · ')[0]}**".`;
      } else {
        analysis = `### 🔍 SECURITY ANOMALY REPORT\n\n**Incident Severity**: ${data.severity || 'HIGH'}\n\n**Context**: ${data.description || data.title || 'Generic Event Trigger'}\n\n**Findings**:\n- Log source originates from **${data.sourceIP || 'N/A'}** mapping to endpoint **${data.destination || 'N/A'}**.\n\n**Remediation Steps**:\n1. Quarantine source IP in security groups.\n2. Revoke associated temporary security credentials.\n3. Audit CloudTrail API calls in nearby temporal windows.`;
      }
      setAiReport(analysis);
      setIsAiLoading(false);
    }, 1200);
  };

  return (
    <>
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-black/40 dark:bg-black/60 z-40 backdrop-blur-sm transition-opacity"
        onClick={handleClose}
      />
      
      {/* Drawer */}
      <div className="fixed right-0 top-0 bottom-0 w-full sm:w-[450px] md:w-[500px] bg-white dark:bg-[#0E1524] shadow-2xl border-l border-gray-200 dark:border-gray-800/80 z-50 flex flex-col transition-all duration-300">
        
        {/* Header */}
        <div className="p-4 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between bg-gray-50 dark:bg-[#121B2F]/60">
          <div>
            <span className="text-[10px] uppercase font-bold tracking-widest text-[#185FA5] dark:text-[#378ADD] block">
              Event Details
            </span>
            <h3 className="text-sm font-bold text-gray-900 dark:text-white truncate max-w-[280px]">
              {data.eventName || data.title || data.name || 'Security Event'}
            </h3>
          </div>
          <button 
            onClick={handleClose}
            className="p-1 rounded-md text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800/50 hover:text-gray-900 dark:hover:text-white"
            aria-label="Close drawer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          
          {/* Metadata Cards */}
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="bg-gray-50 dark:bg-[#152035]/40 p-2.5 rounded-lg border border-gray-100 dark:border-gray-800/50">
              <span className="text-gray-500 block mb-1">Severity</span>
              <span className={`font-bold flex items-center gap-1.5 ${
                data.severity === 'CRITICAL' ? 'text-[#E24B4A]' :
                data.severity === 'HIGH' ? 'text-[#EF9F27]' :
                data.severity === 'MEDIUM' ? 'text-[#378ADD]' : 'text-[#639922]'
              }`}>
                <span className={`w-2 h-2 rounded-full ${
                  data.severity === 'CRITICAL' ? 'bg-[#E24B4A]' :
                  data.severity === 'HIGH' ? 'bg-[#EF9F27]' :
                  data.severity === 'MEDIUM' ? 'bg-[#378ADD]' : 'bg-[#639922]'
                }`} />
                {data.severity || 'LOW'}
              </span>
            </div>
            <div className="bg-gray-50 dark:bg-[#152035]/40 p-2.5 rounded-lg border border-gray-100 dark:border-gray-800/50">
              <span className="text-gray-500 block mb-1">Region</span>
              <span className="font-bold text-gray-900 dark:text-gray-200">
                {data.awsRegion || data.region || 'us-east-1'}
              </span>
            </div>
            {data.sourceIP && (
              <div className="bg-gray-50 dark:bg-[#152035]/40 p-2.5 rounded-lg border border-gray-100 dark:border-gray-800/50 col-span-2">
                <span className="text-gray-500 block mb-1">Source IP</span>
                <span className="font-mono font-bold text-gray-900 dark:text-gray-200">
                  {data.sourceIP}
                </span>
              </div>
            )}
            {data.principalArn && (
              <div className="bg-gray-50 dark:bg-[#152035]/40 p-2.5 rounded-lg border border-gray-100 dark:border-gray-800/50 col-span-2">
                <span className="text-gray-500 block mb-1">Principal ARN</span>
                <span className="font-mono text-[10px] break-all text-gray-900 dark:text-gray-300">
                  {data.principalArn}
                </span>
              </div>
            )}
          </div>

          {/* AI Investigation Section */}
          <div className="border border-indigo-500/20 dark:border-indigo-500/30 rounded-xl bg-indigo-500/[0.02] dark:bg-indigo-500/[0.04] p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-indigo-600 dark:text-indigo-400 flex items-center gap-1.5">
                <Sparkles className="w-4 h-4 text-indigo-500 animate-pulse" />
                AI Security Analyst
              </span>
              {!aiReport && (
                <button
                  onClick={handleAiInvestigate}
                  disabled={isAiLoading}
                  className="text-xs bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-600/50 text-white font-semibold px-3 py-1.5 rounded-lg shadow-sm flex items-center gap-1.5 transition"
                >
                  {isAiLoading ? 'Analyzing...' : 'Investigate with AI ↗'}
                </button>
              )}
            </div>

            {isAiLoading && (
              <div className="flex flex-col items-center justify-center py-6 space-y-2">
                <div className="w-8 h-8 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin" />
                <span className="text-xs text-gray-500">Deconstructing CloudTrail trace logs...</span>
              </div>
            )}

            {aiReport && (
              <div className="bg-white dark:bg-[#131E33] border border-gray-100 dark:border-gray-800/80 rounded-lg p-3 text-xs text-gray-700 dark:text-gray-300 space-y-2">
                <div className="prose prose-xs dark:prose-invert">
                  {aiReport.split('\n\n').map((paragraph, index) => {
                    if (paragraph.startsWith('###')) {
                      return <h4 key={index} className="font-bold text-gray-900 dark:text-white mt-2 mb-1">{paragraph.replace('###', '')}</h4>;
                    }
                    if (paragraph.startsWith('**Incident')) {
                      return <p key={index} className="font-semibold text-[#E24B4A]">{paragraph}</p>;
                    }
                    return <p key={index} className="leading-relaxed whitespace-pre-line">{paragraph}</p>;
                  })}
                </div>
                <div className="flex justify-end pt-2">
                  <button 
                    onClick={() => setAiReport(null)}
                    className="text-[10px] text-gray-500 hover:text-gray-900 dark:hover:text-white"
                  >
                    Clear Analysis
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Full Payload JSON View */}
          <div className="space-y-2">
            <span className="text-xs font-bold text-gray-600 dark:text-gray-400">
              Raw Event Payload (JSON)
            </span>
            <div className="relative rounded-lg overflow-hidden border border-gray-200 dark:border-gray-800">
              <pre className="bg-gray-950 text-gray-100 p-4 text-[11px] font-mono overflow-x-auto max-h-[300px] leading-relaxed select-all">
                {rawJson}
              </pre>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-200 dark:border-gray-800/80 bg-gray-50 dark:bg-[#121B2F]/60 flex items-center justify-end text-xs text-gray-500">
          <span>UTC Time: {formatDateUTC(data.timestamp || data.eventTime || new Date())}</span>
        </div>
      </div>
    </>
  );
};

export default EventDrawer;
