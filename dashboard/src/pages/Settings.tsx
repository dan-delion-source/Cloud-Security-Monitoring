import React, { useState } from 'react';
import { useSecurityStore } from '../store/securityStore';
import {
  Settings as SettingsIcon, ShieldCheck, RefreshCw, Eye, EyeOff,
  ShieldBan, BellOff, UserX, X, ScrollText, Clock, CheckCircle2, XCircle,
  Flame
} from 'lucide-react';

export const Settings: React.FC = () => {
  const {
    awsConfig, isMockMode, autoRemediate, updateAwsConfig, toggleMockMode, toggleAutoRemediate, resetStore,
    blockedIps, mutedEvents, suspendedUsers,
    unblockIpAddress, unmuteEventName, unsuspendIamUser,
    remediationLogs,
  } = useSecurityStore();

  const [accessKey, setAccessKey] = useState(awsConfig.accessKeyId);
  const [secretKey, setSecretKey] = useState(awsConfig.secretAccessKey);
  const [region, setRegion] = useState(awsConfig.region);
  const [showSecret, setShowSecret] = useState(false);
  const [saved, setSaved] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    updateAwsConfig({
      accessKeyId: accessKey,
      secretAccessKey: secretKey,
      region: region
    });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleReset = () => {
    if (window.confirm('Reset all security logs, alerts, and remediations to default settings?')) {
      resetStore();
      setAccessKey('');
      setSecretKey('');
      setRegion('us-east-1');
    }
  };

  const totalRules = blockedIps.length + mutedEvents.length + suspendedUsers.length;

  return (
    <div className="max-w-2xl mx-auto space-y-4 select-none">

      {/* ── Firewall & Countermeasures Panel ──────────────────────────────── */}
      <div className="glass-card p-5 space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800/60">
          <div className="flex items-center gap-2">
            <Flame className="w-5 h-5 text-orange-500" />
            <div>
              <h3 className="text-xs font-black uppercase tracking-widest text-gray-900 dark:text-white leading-none">
                Firewall & Incident Countermeasures
              </h3>
              <span className="text-[9px] text-gray-400 font-mono mt-0.5 block">
                Manage blocked IPs, muted events, and suspended IAM users
              </span>
            </div>
          </div>
          <span className={`text-[9px] px-2 py-0.5 rounded font-mono font-bold ${
            totalRules > 0
              ? 'bg-orange-500/10 text-orange-500'
              : 'bg-emerald-500/10 text-emerald-500'
          }`}>
            {totalRules} active rule{totalRules !== 1 ? 's' : ''}
          </span>
        </div>

        {/* Auto-Remediation Toggle */}
        <div className="p-3.5 bg-gray-50 dark:bg-[#121B2F]/30 border border-red-500/10 dark:border-red-500/20 rounded-xl space-y-2 mt-2 mb-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-gray-900 dark:text-gray-100 uppercase tracking-wide flex items-center gap-2">
              <ShieldBan className="w-4 h-4 text-orange-500" />
              Auto-Remediation (High/Critical)
            </span>
            <button
              type="button"
              onClick={() => toggleAutoRemediate()}
              className={`relative inline-flex h-5 w-10 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-250 ease-in-out focus:outline-none ${
                autoRemediate ? 'bg-orange-500' : 'bg-gray-300 dark:bg-slate-700'
              }`}
            >
              <span
                className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-250 ease-in-out ${
                  autoRemediate ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          </div>
          <p className="text-[10px] text-gray-500 dark:text-gray-400 leading-normal pl-6">
            When enabled, CloudSentinel will automatically block source IPs, suspend IAM users, and remediate buckets as soon as a CRITICAL or HIGH severity event is detected.
          </p>
        </div>

        {/* Blocked IPs */}
        <RuleSection
          icon={<ShieldBan className="w-4 h-4 text-red-500" />}
          title="Blocked IP Addresses"
          emptyText="No IP addresses currently blocked"
          items={blockedIps}
          color="red"
          onRemove={unblockIpAddress}
        />

        {/* Muted Events */}
        <RuleSection
          icon={<BellOff className="w-4 h-4 text-amber-500" />}
          title="Muted Event Types"
          emptyText="No event types currently muted"
          items={mutedEvents}
          color="amber"
          onRemove={unmuteEventName}
        />

        {/* Suspended Users */}
        <RuleSection
          icon={<UserX className="w-4 h-4 text-orange-500" />}
          title="Suspended IAM Users"
          emptyText="No IAM users currently suspended"
          items={suspendedUsers.map(u => {
            if (!u.suspendUntil) return `${u.userName} (Indefinite)`;
            return `${u.userName} (Until ${new Date(u.suspendUntil).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})})`;
          })}
          color="orange"
          onRemove={(formattedString) => {
            const userName = formattedString.split(' ')[0];
            unsuspendIamUser(userName);
          }}
        />
      </div>

      {/* ── Remediation Audit Trail ───────────────────────────────────────── */}
      <div className="glass-card p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800/60">
          <div className="flex items-center gap-2">
            <ScrollText className="w-5 h-5 text-[#185FA5]" />
            <div>
              <h3 className="text-xs font-black uppercase tracking-widest text-gray-900 dark:text-white leading-none">
                Remediation Audit Trail
              </h3>
              <span className="text-[9px] text-gray-400 font-mono mt-0.5 block">
                Immutable log of all countermeasure actions taken during this session
              </span>
            </div>
          </div>
          <span className="text-[9px] bg-blue-500/10 text-blue-500 px-2 py-0.5 rounded font-mono font-bold">
            {remediationLogs.length} entries
          </span>
        </div>

        {remediationLogs.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-center text-xs text-gray-400 space-y-2">
            <div className="p-3 bg-gray-50 dark:bg-gray-800/30 rounded-full border border-gray-100 dark:border-gray-800/40">
              <ScrollText className="w-6 h-6" />
            </div>
            <p className="font-semibold text-gray-700 dark:text-gray-300">Audit trail empty</p>
            <p className="text-[10px] text-gray-500">
              Actions you take (block IP, suspend user, etc.) will appear here in real-time.
            </p>
          </div>
        ) : (
          <div className="max-h-[320px] overflow-y-auto space-y-1.5 pr-1">
            {remediationLogs.map((log) => (
              <div
                key={log.id}
                className="flex items-center gap-3 p-2.5 rounded-lg bg-gray-50/50 dark:bg-[#121B2F]/20 border border-gray-100 dark:border-gray-800/40 text-[11px] hover:bg-gray-100/60 dark:hover:bg-[#152035]/40 transition"
              >
                {/* Status icon */}
                {log.status === 'SUCCESS' ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                ) : (
                  <XCircle className="w-4 h-4 text-red-500 shrink-0" />
                )}

                {/* Action */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-black uppercase tracking-wide ${
                      getActionColor(log.action)
                    }`}>
                      {formatAction(log.action)}
                    </span>
                    <span className="font-mono font-bold text-gray-700 dark:text-gray-200 truncate">
                      {log.target}
                    </span>
                  </div>
                </div>

                {/* Timestamp */}
                <div className="flex items-center gap-1 text-[9px] text-gray-400 font-mono shrink-0">
                  <Clock className="w-3 h-3" />
                  {new Date(log.timestamp).toLocaleTimeString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── AWS Configuration Form ───────────────────────────────────────── */}
      <form
        onSubmit={handleSave}
        className="glass-card p-5 space-y-4"
      >
        {/* Header */}
        <div className="flex items-center gap-2 pb-3 border-b border-gray-100 dark:border-gray-800/60">
          <SettingsIcon className="w-5 h-5 text-[#185FA5]" />
          <div>
            <h3 className="text-xs font-black uppercase tracking-widest text-gray-900 dark:text-white leading-none">
              Sentinel Connector Settings
            </h3>
            <span className="text-[9px] text-gray-400 font-mono">
              Configure AWS credential access mappings
            </span>
          </div>
        </div>

        {/* Mock Mode Selection */}
        <div className="p-3.5 bg-gray-50 dark:bg-[#121B2F]/30 border border-gray-150 dark:border-gray-850 rounded-xl space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-gray-900 dark:text-gray-100 uppercase tracking-wide">
              Operation Mode
            </span>
            <button
              type="button"
              onClick={() => toggleMockMode()}
              className={`relative inline-flex h-5 w-10 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-250 ease-in-out focus:outline-none ${
                isMockMode ? 'bg-[#185FA5]' : 'bg-gray-300 dark:bg-slate-700'
              }`}
            >
              <span
                className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-250 ease-in-out ${
                  isMockMode ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          </div>
          <p className="text-[10px] text-gray-500 dark:text-gray-400 leading-normal">
            {isMockMode
              ? 'Sandbox Simulation Mode active. Security anomalies and CloudTrail logs are auto-generated on standard timers.'
              : 'AWS Live mode selected. CloudSentinel will use modular SDK v3 targets to evaluate your live production perimeter.'
            }
          </p>
        </div>

        {/* Credentials Form */}
        <div className="space-y-3.5">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
            {/* Access Key */}
            <div className="space-y-1">
              <label className="text-[10px] uppercase font-bold tracking-wider text-gray-500 dark:text-gray-450 block">
                AWS Access Key ID
              </label>
              <input
                type="text"
                disabled={isMockMode}
                value={accessKey}
                onChange={(e) => setAccessKey(e.target.value)}
                placeholder={isMockMode ? 'SIMULATED_ACCESS_KEY' : 'AKIAIOSFODNN7EXAMPLE'}
                className="block w-full px-3 py-2 text-xs bg-gray-50 dark:bg-[#0E1524]/60 border border-gray-250 dark:border-gray-800 rounded-lg text-gray-900 dark:text-gray-100 placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-[#185FA5] disabled:opacity-50 transition"
              />
            </div>

            {/* Region Select */}
            <div className="space-y-1">
              <label className="text-[10px] uppercase font-bold tracking-wider text-gray-500 dark:text-gray-450 block">
                Default Audit Region
              </label>
              <select
                disabled={isMockMode}
                value={region}
                onChange={(e) => setRegion(e.target.value)}
                className="block w-full px-3 py-2 text-xs bg-gray-50 dark:bg-[#0E1524]/60 border border-gray-250 dark:border-gray-800 rounded-lg text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-1 focus:ring-[#185FA5] disabled:opacity-50 transition"
              >
                <option value="us-east-1">us-east-1 (N. Virginia)</option>
                <option value="us-west-2">us-west-2 (Oregon)</option>
                <option value="eu-west-1">eu-west-1 (Ireland)</option>
                <option value="ap-southeast-1">ap-southeast-1 (Singapore)</option>
              </select>
            </div>
          </div>

          {/* Secret Access Key */}
          <div className="space-y-1">
            <label className="text-[10px] uppercase font-bold tracking-wider text-gray-500 dark:text-gray-450 block">
              AWS Secret Access Key
            </label>
            <div className="relative">
              <input
                type={showSecret ? 'text' : 'password'}
                disabled={isMockMode}
                value={secretKey}
                onChange={(e) => setSecretKey(e.target.value)}
                placeholder={isMockMode ? '••••••••••••••••••••••••••••••••••••••••' : 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'}
                className="block w-full pl-3 pr-10 py-2 text-xs bg-gray-50 dark:bg-[#0E1524]/60 border border-gray-250 dark:border-gray-800 rounded-lg text-gray-900 dark:text-gray-100 placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-[#185FA5] disabled:opacity-50 transition"
              />
              <button
                type="button"
                disabled={isMockMode}
                onClick={() => setShowSecret(!showSecret)}
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 disabled:opacity-50"
              >
                {showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

        </div>

        {/* Submit Actions */}
        <div className="flex items-center justify-between border-t border-gray-100 dark:border-gray-800/60 pt-3.5">
          <span className="text-[10px] text-gray-400">
            Credentials are stored in-memory only and reset on page reload.
          </span>
          <button
            type="submit"
            disabled={isMockMode}
            className="flex items-center gap-1.5 px-4 py-2 text-xs font-bold text-white bg-[#185FA5] hover:bg-[#134D87] disabled:bg-[#185FA5]/50 shadow-sm rounded-lg transition"
          >
            <ShieldCheck className="w-4 h-4" />
            <span>{saved ? 'Saved!' : 'Save Config'}</span>
          </button>
        </div>

      </form>

      {/* ── Danger Zone ──────────────────────────────────────────────────── */}
      <div className="glass-card p-5 border border-red-500/10 dark:border-red-500/5 bg-red-500/[0.01] flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h4 className="text-xs font-black uppercase text-red-500 tracking-wider">
            Danger Zone
          </h4>
          <p className="text-[10px] text-gray-400 mt-0.5 leading-normal max-w-[420px]">
            Wipe out all local state, reset AWS connectors, clear active incident alarms, firewall rules, and reload default sandbox threat feeds.
          </p>
        </div>
        <button
          onClick={handleReset}
          className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-bold text-[#E24B4A] hover:text-white border border-[#E24B4A] hover:bg-[#E24B4A] rounded-lg transition shrink-0"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Wipe System State</span>
        </button>
      </div>

    </div>
  );
};

// ── Sub-components ────────────────────────────────────────────────────────────

interface RuleSectionProps {
  icon: React.ReactNode;
  title: string;
  emptyText: string;
  items: string[];
  color: 'red' | 'amber' | 'orange';
  onRemove: (item: string) => void;
}

const RuleSection: React.FC<RuleSectionProps> = ({ icon, title, emptyText, items, color, onRemove }) => {
  const colorMap = {
    red:    { tag: 'bg-red-500/10 text-red-500 border-red-500/20', hover: 'hover:bg-red-500/10' },
    amber:  { tag: 'bg-amber-500/10 text-amber-600 border-amber-500/20', hover: 'hover:bg-amber-500/10' },
    orange: { tag: 'bg-orange-500/10 text-orange-600 border-orange-500/20', hover: 'hover:bg-orange-500/10' },
  };
  const cm = colorMap[color];

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        {icon}
        <span className="text-[10px] font-bold uppercase tracking-wider text-gray-600 dark:text-gray-300">
          {title}
        </span>
        <span className="text-[9px] font-mono text-gray-400">({items.length})</span>
      </div>
      {items.length === 0 ? (
        <p className="text-[10px] text-gray-400 italic pl-6">{emptyText}</p>
      ) : (
        <div className="flex flex-wrap gap-1.5 pl-6">
          {items.map((item) => (
            <span
              key={item}
              className={`flex items-center gap-1 px-2 py-1 rounded-md border text-[10px] font-mono font-bold ${cm.tag}`}
            >
              {item}
              <button
                onClick={() => onRemove(item)}
                className={`p-0.5 rounded transition ${cm.hover}`}
                title={`Remove ${item}`}
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function getActionColor(action: string): string {
  switch (action) {
    case 'BLOCK_IP':          return 'bg-red-500/10 text-red-500';
    case 'UNBLOCK_IP':        return 'bg-emerald-500/10 text-emerald-600';
    case 'MUTE_EVENT':        return 'bg-amber-500/10 text-amber-600';
    case 'UNMUTE_EVENT':      return 'bg-blue-500/10 text-blue-600';
    case 'SUSPEND_IAM_USER':  return 'bg-orange-500/10 text-orange-600';
    case 'RESTORE_IAM_USER':  return 'bg-emerald-500/10 text-emerald-600';
    case 'REMEDIATE_ANOMALY': return 'bg-emerald-500/10 text-emerald-600';
    case 'AI_INVESTIGATE':    return 'bg-indigo-500/10 text-indigo-600';
    case 'GENERATE_REPORT':   return 'bg-cyan-500/10 text-cyan-600';
    default:                  return 'bg-gray-500/10 text-gray-600';
  }
}

function formatAction(action: string): string {
  return action.replace(/_/g, ' ');
}

export default Settings;
