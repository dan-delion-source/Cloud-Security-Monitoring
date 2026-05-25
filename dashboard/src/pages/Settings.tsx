import React, { useState } from 'react';
import { useSecurityStore } from '../store/securityStore';
import { Settings as SettingsIcon, ShieldCheck, RefreshCw, Eye, EyeOff } from 'lucide-react';

export const Settings: React.FC = () => {
  const { awsConfig, isMockMode, updateAwsConfig, toggleMockMode, resetStore } = useSecurityStore();
  
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

  return (
    <div className="max-w-2xl mx-auto space-y-4 select-none">
      
      {/* Configuration Form */}
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
            Credentials are only saved locally inside workspace sessionStorage.
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

      {/* Reset Action */}
      <div className="glass-card p-5 border border-red-500/10 dark:border-red-500/5 bg-red-500/[0.01] flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h4 className="text-xs font-black uppercase text-red-500 tracking-wider">
            Danger Zone
          </h4>
          <p className="text-[10px] text-gray-400 mt-0.5 leading-normal max-w-[420px]">
            Wipe out all local state, reset AWS connectors, clear active incident alarms, and reload default sandbox threat feeds.
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

export default Settings;
