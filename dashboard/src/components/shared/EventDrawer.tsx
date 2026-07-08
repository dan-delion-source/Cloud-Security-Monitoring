import React, { useState } from 'react';
import { useSecurityStore } from '../../store/securityStore';
import {
  X, Sparkles, ShieldBan, BellOff, UserX, CheckCircle2,
  FileText, Copy, Download, ChevronDown, ChevronUp, Zap, Shield
} from 'lucide-react';
import { formatDateUTC } from '../../utils/formatters';

// ── helpers ──────────────────────────────────────────────────────────────────

function renderMarkdown(md: string) {
  return md.split('\n\n').map((block, i) => {
    if (block.startsWith('### ')) {
      return (
        <h4 key={i} className="font-bold text-gray-900 dark:text-white mt-3 mb-1 text-sm">
          {block.replace('### ', '')}
        </h4>
      );
    }
    if (block.startsWith('## ')) {
      return (
        <h3 key={i} className="font-black text-gray-900 dark:text-white mt-4 mb-1 text-xs uppercase tracking-wider">
          {block.replace('## ', '')}
        </h3>
      );
    }
    if (block.startsWith('**Incident')) {
      return <p key={i} className="font-semibold text-[#E24B4A] text-xs">{block}</p>;
    }
    return (
      <p key={i} className="leading-relaxed whitespace-pre-line text-xs text-gray-700 dark:text-gray-300">
        {block}
      </p>
    );
  });
}

// ── component ─────────────────────────────────────────────────────────────────

export const EventDrawer: React.FC = () => {
  const {
    selectedEvent, setSelectedEvent,
    blockedIps, mutedEvents, suspendedUsers, remediatedAnomalies,
    blockIpAddress, unblockIpAddress,
    muteEventName, unmuteEventName,
    suspendIamUser, unsuspendIamUser,
    remediateAnomaly,
    addRemediationLog,
  } = useSecurityStore();

  const [aiReport, setAiReport] = useState<string | null>(null);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [incidentReport, setIncidentReport] = useState<string | null>(null);
  const [showCountermeasures, setShowCountermeasures] = useState(true);
  const [showReport, setShowReport] = useState(false);
  const [copied, setCopied] = useState(false);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);
  const [showSuspendMenu, setShowSuspendMenu] = useState(false);
  const [customSuspendHours, setCustomSuspendHours] = useState('48');

  if (!selectedEvent) return null;

  const { type, data } = selectedEvent;
  const rawJson = data.rawJson || data.rawEvent || JSON.stringify(data, null, 2);

  // Derived state for this event
  const isIpBlocked   = data.sourceIP   && blockedIps.includes(data.sourceIP);
  const isEventMuted  = data.eventName  && mutedEvents.includes(data.eventName);
  const parsedUserName = data.userName || extractUserFromArn(data.principalArn || data.resourceArn || '');
  const isUserSuspended = parsedUserName && suspendedUsers.some(u => 
    u.userName === parsedUserName && (!u.suspendUntil || new Date(u.suspendUntil) > new Date())
  );
  const isRemediated  = data.id && remediatedAnomalies.includes(data.id);

  const targetUser = parsedUserName;

  // ── handlers ──────────────────────────────────────────────────────────────

  const handleClose = () => { setSelectedEvent(null); setAiReport(null); setIncidentReport(null); };

  const flash = (msg: string) => {
    setActionFeedback(msg);
    setTimeout(() => setActionFeedback(null), 2500);
  };

  const handleToggleBlockIp = () => {
    if (!data.sourceIP) return;
    if (isIpBlocked) {
      unblockIpAddress(data.sourceIP);
      flash(`✅ IP ${data.sourceIP} unblocked`);
    } else {
      blockIpAddress(data.sourceIP);
      flash(`🚫 IP ${data.sourceIP} blocked`);
    }
  };

  const handleToggleMuteEvent = () => {
    if (!data.eventName) return;
    if (isEventMuted) {
      unmuteEventName(data.eventName);
      flash(`🔔 Event "${data.eventName}" unmuted`);
    } else {
      muteEventName(data.eventName);
      flash(`🔕 Event "${data.eventName}" muted`);
    }
  };

  const handleToggleSuspendUser = (durationHours: number | null = null) => {
    if (!targetUser) return;
    if (isUserSuspended) {
      unsuspendIamUser(targetUser);
      flash(`✅ IAM user "${targetUser}" restored`);
      setShowSuspendMenu(false);
    } else {
      suspendIamUser(targetUser, durationHours);
      flash(`🔒 IAM user "${targetUser}" suspended${durationHours ? ` for ${durationHours}h` : ''}`);
      setShowSuspendMenu(false);
    }
  };

  const handleRemediateAnomaly = () => {
    if (!data.id) return;
    remediateAnomaly(data.id);
    flash(`✅ Anomaly "${data.id}" marked remediated`);
  };

  // ── AI Investigation ──────────────────────────────────────────────────────

  const handleAiInvestigate = () => {
    setIsAiLoading(true);
    setAiReport(null);
    setTimeout(() => {
      const prompt = `Please act as a Senior Cloud Security Engineer. I need you to analyze this AWS security event and provide a risk assessment, potential blast radius, and step-by-step remediation commands.

Here is the context:
- Event Type: ${type.toUpperCase()}
- Event Name: ${data.eventName || data.title || 'N/A'}
- Severity: ${data.severity || 'LOW'}
- Target Resource: ${data.principalArn || data.resourceArn || 'N/A'}
- Source IP: ${data.sourceIP || 'N/A'}
- Timestamp: ${data.timestamp || data.eventTime || new Date().toISOString()}
- Threat Context: ${data.detail || data.description || data.message || 'N/A'}

Raw Event Payload:
\`\`\`json
${rawJson}
\`\`\`
`;
      setAiReport(prompt);
      setIsAiLoading(false);
      addRemediationLog('GENERATE_AI_CONTEXT', data.eventName || data.title || data.id || 'event', 'SUCCESS');
    }, 600);
  };

  // ── Incident Report ───────────────────────────────────────────────────────

  const handleGenerateReport = () => {
    const now = new Date();
    const actions: string[] = [];
    if (isIpBlocked) actions.push(`- Source IP \`${data.sourceIP}\` added to blocklist`);
    if (isEventMuted) actions.push(`- Event type \`${data.eventName}\` muted in log stream`);
    if (isUserSuspended) actions.push(`- IAM user \`${targetUser}\` login credentials suspended`);
    if (isRemediated) actions.push(`- Anomaly \`${data.id}\` marked as remediated`);
    if (aiReport) actions.push('- AI security analysis completed — see analysis below');

    const report = `# 🛡️ Incident Response Report
**Generated**: ${now.toUTCString()}
**Analyst**: Security Operations (CloudSec Dashboard)

---

## 1. Event Summary
| Field | Value |
|---|---|
| **Event Type** | ${type.toUpperCase()} |
| **Event Name** | ${data.eventName || data.title || 'N/A'} |
| **Severity** | ${data.severity || 'LOW'} |
| **Source IP** | ${data.sourceIP || 'N/A'} |
| **Principal ARN** | ${data.principalArn || data.resourceArn || 'N/A'} |
| **AWS Region** | ${data.awsRegion || data.region || 'N/A'} |
| **Timestamp (UTC)** | ${formatDateUTC(data.timestamp || data.eventTime || now)} |

---

## 2. Threat Context
${data.detail || data.description || data.message || 'No additional threat context captured.'}

Pattern rule: \`${data.pattern || 'N/A'}\`

---

## 3. Countermeasures Applied
${actions.length > 0 ? actions.join('\n') : '- No automated countermeasures applied yet.'}

---

## 4. AI Analysis
${aiReport || 'AI investigation not yet triggered. Click "Investigate with AI" in the Event Details panel.'}

---

## 5. Raw Event Payload
\`\`\`json
${rawJson}
\`\`\`

---

## 6. Recommendations
1. Verify countermeasures are reflected in live AWS/LocalStack IAM and Security Group policies.
2. Escalate to senior cloud security team if severity is CRITICAL.
3. Document this incident in the organisation's security incident registry.
4. Review related CloudTrail events in the ±15-minute temporal window.
`;

    setIncidentReport(report);
    setShowReport(true);
    addRemediationLog('GENERATE_REPORT', data.eventName || data.id || 'event', 'SUCCESS');
  };

  const handleCopyReport = () => {
    if (!incidentReport) return;
    navigator.clipboard.writeText(incidentReport).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const handleDownloadReport = () => {
    if (!incidentReport) return;
    const blob = new Blob([incidentReport], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incident-report-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // ── countermeasure buttons config ─────────────────────────────────────────

  const countermeasures = [
    {
      id: 'block-ip',
      icon: <ShieldBan className="w-4 h-4" />,
      label: isIpBlocked ? 'Unblock IP' : 'Block Source IP',
      sublabel: data.sourceIP || 'No IP available',
      active: isIpBlocked,
      disabled: !data.sourceIP,
      onClick: handleToggleBlockIp,
      activeColor: 'border-red-500/40 bg-red-500/5 text-red-600 dark:text-red-400',
      inactiveColor: 'border-gray-200 dark:border-gray-700 hover:border-red-400/50 hover:bg-red-500/5',
    },
    {
      id: 'mute-event',
      icon: <BellOff className="w-4 h-4" />,
      label: isEventMuted ? 'Unmute Event' : 'Mute Event Type',
      sublabel: data.eventName || 'No event name',
      active: isEventMuted,
      disabled: !data.eventName,
      onClick: handleToggleMuteEvent,
      activeColor: 'border-amber-500/40 bg-amber-500/5 text-amber-600 dark:text-amber-400',
      inactiveColor: 'border-gray-200 dark:border-gray-700 hover:border-amber-400/50 hover:bg-amber-500/5',
    },
    {
      id: 'suspend-user',
      icon: <UserX className="w-4 h-4" />,
      label: isUserSuspended ? 'Restore IAM User' : 'Suspend IAM User',
      sublabel: targetUser || 'No user identified',
      active: isUserSuspended,
      disabled: !targetUser,
      onClick: () => {
        if (isUserSuspended) {
          handleToggleSuspendUser(null);
        } else {
          setShowSuspendMenu(!showSuspendMenu);
        }
      },
      activeColor: 'border-orange-500/40 bg-orange-500/5 text-orange-600 dark:text-orange-400',
      inactiveColor: 'border-gray-200 dark:border-gray-700 hover:border-orange-400/50 hover:bg-orange-500/5',
    },
    {
      id: 'remediate',
      icon: isRemediated ? <CheckCircle2 className="w-4 h-4" /> : <Zap className="w-4 h-4" />,
      label: isRemediated ? 'Marked Remediated' : 'Mark as Remediated',
      sublabel: data.id || 'No anomaly ID',
      active: isRemediated,
      disabled: !data.id || isRemediated,
      onClick: handleRemediateAnomaly,
      activeColor: 'border-emerald-500/40 bg-emerald-500/5 text-emerald-600 dark:text-emerald-400',
      inactiveColor: 'border-gray-200 dark:border-gray-700 hover:border-emerald-400/50 hover:bg-emerald-500/5',
    },
  ];

  // ── render ────────────────────────────────────────────────────────────────

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/40 dark:bg-black/60 z-40 backdrop-blur-sm transition-opacity"
        onClick={handleClose}
      />

      {/* Drawer */}
      <div className="fixed right-0 top-0 bottom-0 w-full sm:w-[480px] md:w-[520px] bg-white dark:bg-[#0E1524] shadow-2xl border-l border-gray-200 dark:border-gray-800/80 z-50 flex flex-col transition-all duration-300">

        {/* Header */}
        <div className="p-4 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between bg-gray-50 dark:bg-[#121B2F]/60 shrink-0">
          <div>
            <span className="text-[10px] uppercase font-bold tracking-widest text-[#185FA5] dark:text-[#378ADD] block">
              Event Details
            </span>
            <h3 className="text-sm font-bold text-gray-900 dark:text-white truncate max-w-[300px]">
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

        {/* Action Feedback Toast */}
        {actionFeedback && (
          <div className="mx-4 mt-3 px-3 py-2 bg-gray-900 dark:bg-gray-100 text-white dark:text-gray-900 text-xs rounded-lg font-medium shadow-lg animate-pulse shrink-0">
            {actionFeedback}
          </div>
        )}

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">

          {/* Metadata Cards */}
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="bg-gray-50 dark:bg-[#152035]/40 p-2.5 rounded-lg border border-gray-100 dark:border-gray-800/50">
              <span className="text-gray-500 block mb-1">Severity</span>
              <span className={`font-bold flex items-center gap-1.5 ${
                data.severity === 'CRITICAL' ? 'text-[#E24B4A]' :
                data.severity === 'HIGH'     ? 'text-[#EF9F27]' :
                data.severity === 'MEDIUM'   ? 'text-[#378ADD]' : 'text-[#639922]'
              }`}>
                <span className={`w-2 h-2 rounded-full ${
                  data.severity === 'CRITICAL' ? 'bg-[#E24B4A]' :
                  data.severity === 'HIGH'     ? 'bg-[#EF9F27]' :
                  data.severity === 'MEDIUM'   ? 'bg-[#378ADD]' : 'bg-[#639922]'
                }`} />
                {data.severity || 'LOW'}
              </span>
            </div>
            <div className="bg-gray-50 dark:bg-[#152035]/40 p-2.5 rounded-lg border border-gray-100 dark:border-gray-800/50">
              <span className="text-gray-500 block mb-1">Region</span>
              <span className="font-bold text-gray-900 dark:text-gray-200 font-mono text-[11px]">
                {data.awsRegion || data.region || 'us-east-1'}
              </span>
            </div>
            {data.sourceIP && (
              <div className="bg-gray-50 dark:bg-[#152035]/40 p-2.5 rounded-lg border border-gray-100 dark:border-gray-800/50 col-span-2">
                <span className="text-gray-500 block mb-1">Source IP</span>
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-gray-900 dark:text-gray-200">{data.sourceIP}</span>
                  {isIpBlocked && (
                    <span className="text-[9px] bg-red-500/10 text-red-500 px-1.5 py-0.5 rounded font-bold">BLOCKED</span>
                  )}
                </div>
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

          {/* ── Countermeasures Section ───────────────────────────────────── */}
          <div className="border border-gray-200/80 dark:border-gray-800/60 rounded-xl overflow-hidden">
            <button
              onClick={() => setShowCountermeasures(v => !v)}
              className="w-full flex items-center justify-between px-4 py-3 bg-gray-50 dark:bg-[#152035]/50 text-xs font-bold text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-[#1a2540]/50 transition"
            >
              <span className="flex items-center gap-2">
                <Shield className="w-3.5 h-3.5 text-[#185FA5]" />
                Countermeasures
              </span>
              {showCountermeasures ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>

            {showCountermeasures && (
              <div className="p-3 grid grid-cols-2 gap-2">
                {countermeasures.map((cm) => (
                  <React.Fragment key={cm.id}>
                    <button
                      onClick={cm.onClick}
                      disabled={cm.disabled}
                      title={cm.disabled ? 'Not available for this event' : undefined}
                      className={`flex flex-col items-start gap-1.5 p-3 rounded-lg border text-left transition-all ${
                        cm.disabled
                          ? 'opacity-30 cursor-not-allowed border-gray-200 dark:border-gray-800'
                          : cm.active
                          ? cm.activeColor
                          : `text-gray-600 dark:text-gray-300 ${cm.inactiveColor}`
                      }`}
                    >
                      <div className="flex items-center gap-1.5 font-bold text-[11px]">
                        {cm.icon}
                        {cm.label}
                      </div>
                      <div className="text-[9px] font-mono opacity-70 truncate w-full">{cm.sublabel}</div>
                    </button>
                    {cm.id === 'suspend-user' && showSuspendMenu && !isUserSuspended && (
                      <div className="col-span-2 bg-gray-100/50 dark:bg-[#0E1524]/80 border border-gray-200 dark:border-gray-800 p-3 rounded-lg mt-1 flex flex-col gap-2">
                        <span className="text-[10px] font-bold text-gray-500 w-full">Select Suspension Duration:</span>
                        <div className="flex flex-wrap gap-2">
                          <button onClick={() => handleToggleSuspendUser(12)} className="text-[10px] bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 px-3 py-1.5 rounded hover:bg-orange-50 dark:hover:bg-orange-900/30 transition font-bold">12 Hours</button>
                          <button onClick={() => handleToggleSuspendUser(24)} className="text-[10px] bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 px-3 py-1.5 rounded hover:bg-orange-50 dark:hover:bg-orange-900/30 transition font-bold">24 Hours</button>
                          <button onClick={() => handleToggleSuspendUser(36)} className="text-[10px] bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 px-3 py-1.5 rounded hover:bg-orange-50 dark:hover:bg-orange-900/30 transition font-bold">36 Hours</button>
                          <button onClick={() => handleToggleSuspendUser(null)} className="text-[10px] bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 px-3 py-1.5 rounded hover:bg-red-50 dark:hover:bg-red-900/30 transition font-bold text-red-600 dark:text-red-400">Indefinite</button>
                        </div>
                        
                        <div className="w-full flex items-center justify-between gap-4 mt-1 pt-3 border-t border-gray-200/60 dark:border-gray-700/60">
                          <div className="flex flex-col flex-1 gap-1.5">
                            <div className="flex justify-between items-center text-[10px] text-gray-500 font-bold">
                              <span>Custom Limit</span>
                              <span className="text-gray-900 dark:text-gray-200 bg-white dark:bg-gray-800 px-1.5 py-0.5 rounded border border-gray-200 dark:border-gray-700">{customSuspendHours} hrs</span>
                            </div>
                            <input 
                              type="range" 
                              min="1" 
                              max="168" 
                              step="1" 
                              value={customSuspendHours} 
                              onChange={(e) => setCustomSuspendHours(e.target.value)} 
                              className="w-full accent-orange-500 h-1 bg-gray-200 rounded-lg appearance-none cursor-pointer dark:bg-gray-700 outline-none" 
                            />
                          </div>
                          <button 
                            onClick={() => handleToggleSuspendUser(parseInt(customSuspendHours) || 48)} 
                            className="text-[10px] bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-400 px-4 py-2 font-bold border border-orange-200 dark:border-orange-800/50 rounded-lg hover:bg-orange-200 dark:hover:bg-orange-900/60 transition shrink-0"
                          >
                            Apply
                          </button>
                        </div>
                      </div>
                    )}
                  </React.Fragment>
                ))}
              </div>
            )}
          </div>

          {/* ── AI Investigation Section ──────────────────────────────────── */}
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
                  {isAiLoading ? 'Compiling context...' : 'Generate AI Context ↗'}
                </button>
              )}
            </div>

            {isAiLoading && (
              <div className="flex flex-col items-center justify-center py-6 space-y-2">
                <div className="w-8 h-8 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin" />
                <span className="text-xs text-gray-500">Compiling event context...</span>
              </div>
            )}

            {aiReport && (
              <div className="bg-white dark:bg-[#131E33] border border-indigo-100 dark:border-indigo-500/30 rounded-lg p-3 space-y-2">
                <div className="flex justify-between items-center mb-1">
                  <span className="text-[10px] font-bold text-indigo-500">AI Prompt Context</span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(aiReport);
                      flash('✅ AI Prompt Copied!');
                    }}
                    className="flex items-center gap-1 text-[10px] font-bold text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 transition"
                  >
                    <Copy className="w-3 h-3" />
                    Copy Prompt
                  </button>
                </div>
                <pre className="text-[10px] font-mono text-gray-700 dark:text-gray-300 whitespace-pre-wrap bg-gray-50 dark:bg-gray-900/50 p-2.5 rounded border border-gray-100 dark:border-gray-800 max-h-[200px] overflow-y-auto select-all">
                  {aiReport}
                </pre>
                <div className="flex justify-end pt-1">
                  <button
                    onClick={() => setAiReport(null)}
                    className="text-[10px] text-gray-500 hover:text-gray-900 dark:hover:text-white transition"
                  >
                    Clear
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* ── Incident Report Section ───────────────────────────────────── */}
          <div className="border border-emerald-500/20 dark:border-emerald-500/25 rounded-xl overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 bg-emerald-500/[0.03] dark:bg-emerald-500/[0.06]">
              <span className="text-xs font-bold text-emerald-700 dark:text-emerald-400 flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5" />
                Incident Report
              </span>
              <div className="flex items-center gap-2">
                {incidentReport && (
                  <>
                    <button
                      onClick={handleCopyReport}
                      className="flex items-center gap-1 text-[10px] font-bold text-gray-500 hover:text-emerald-600 transition"
                      title="Copy Markdown"
                    >
                      <Copy className="w-3 h-3" />
                      {copied ? 'Copied!' : 'Copy'}
                    </button>
                    <button
                      onClick={handleDownloadReport}
                      className="flex items-center gap-1 text-[10px] font-bold text-gray-500 hover:text-emerald-600 transition"
                      title="Download .md"
                    >
                      <Download className="w-3 h-3" />
                      .md
                    </button>
                    <button
                      onClick={() => setShowReport(v => !v)}
                      className="text-[10px] text-gray-500 hover:text-gray-700 dark:hover:text-gray-200"
                    >
                      {showReport ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </button>
                  </>
                )}
                <button
                  onClick={handleGenerateReport}
                  className="text-xs bg-emerald-600 hover:bg-emerald-700 text-white font-semibold px-3 py-1.5 rounded-lg shadow-sm flex items-center gap-1.5 transition"
                >
                  {incidentReport ? 'Regenerate' : 'Generate Report'}
                </button>
              </div>
            </div>

            {incidentReport && showReport && (
              <div className="relative">
                <pre className="bg-gray-950 text-emerald-300 p-4 text-[10px] font-mono overflow-x-auto max-h-[260px] leading-relaxed whitespace-pre-wrap select-all">
                  {incidentReport}
                </pre>
              </div>
            )}
          </div>

          {/* ── Raw JSON Payload ──────────────────────────────────────────── */}
          <div className="space-y-2">
            <span className="text-xs font-bold text-gray-600 dark:text-gray-400">
              Raw Event Payload (JSON)
            </span>
            <div className="relative rounded-lg overflow-hidden border border-gray-200 dark:border-gray-800">
              <pre className="bg-gray-950 text-gray-100 p-4 text-[11px] font-mono overflow-x-auto max-h-[280px] leading-relaxed select-all">
                {rawJson}
              </pre>
            </div>
          </div>

        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-200 dark:border-gray-800/80 bg-gray-50 dark:bg-[#121B2F]/60 flex items-center justify-between text-xs text-gray-500 shrink-0">
          <span className="font-mono">UTC: {formatDateUTC(data.timestamp || data.eventTime || new Date())}</span>
          <span className="text-[10px] bg-gray-200/70 dark:bg-gray-800 px-2 py-0.5 rounded font-mono">
            {type.toUpperCase()} event
          </span>
        </div>
      </div>
    </>
  );
};

// ── utility ───────────────────────────────────────────────────────────────────

function extractUserFromArn(arn: string): string {
  if (!arn) return '';
  const parts = arn.split(':');
  const last = parts[parts.length - 1];
  // handles "user/john-doe" or "assumed-role/DevOperator/session"
  const segments = last.split('/');
  return segments[segments.length - 1] || '';
}

export default EventDrawer;
