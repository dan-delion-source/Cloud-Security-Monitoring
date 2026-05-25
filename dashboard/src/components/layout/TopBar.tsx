import React, { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { useSecurityStore } from '../../store/securityStore';
import { RefreshCw, Sun, Moon } from 'lucide-react';

export const TopBar: React.FC = () => {
  const location = useLocation();
  const { logs, unauthorizedEvents, buckets, iamAnomalies, isScanning, triggerScan } = useSecurityStore();
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  // Sync theme with HTML class
  useEffect(() => {
    const root = window.document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }, [theme]);

  // Compute page title based on current path
  const getPageTitle = () => {
    switch (location.pathname) {
      case '/':
        return 'Overview Dashboard';
      case '/logs':
        return 'AWS Log Monitor';
      case '/access':
        return 'Unauthorized Access Detector';
      case '/s3':
        return 'Public S3 Bucket Scanner';
      case '/iam':
        return 'IAM Misuse Detector';
      case '/settings':
        return 'Sentinel System Settings';
      default:
        return 'CloudSentinel Monitor';
    }
  };

  // Compute global critical counts
  const criticalCount = 
    logs.filter(l => l.severity === 'CRITICAL').length +
    unauthorizedEvents.filter(e => e.severity === 'CRITICAL').length +
    buckets.filter(b => !b.remediated && b.severity === 'CRITICAL').length +
    iamAnomalies.filter(i => i.severity === 'CRITICAL').length;

  return (
    <header 
      className="sticky top-0 bg-[#F8FAFC]/80 dark:bg-[#090D16]/80 backdrop-blur-md border-b border-gray-200/50 dark:border-gray-800/40 px-4 py-3 flex items-center justify-between z-20 select-none"
    >
      {/* Title */}
      <div>
        <h2 className="text-sm font-extrabold text-gray-900 dark:text-white tracking-wide uppercase">
          {getPageTitle()}
        </h2>
        <span className="text-[10px] text-gray-500 dark:text-gray-400 font-medium">
          CloudSentinel Security Command Center
        </span>
      </div>

      {/* Control Actions */}
      <div className="flex items-center gap-4">
        
        {/* Status Indicator */}
        <div className="flex items-center gap-2 bg-white dark:bg-[#121B2F]/40 border border-gray-200 dark:border-gray-850 px-2.5 py-1 rounded-lg text-[11px] font-bold">
          <span className="relative flex h-2 w-2 shrink-0">
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
              criticalCount > 0 ? 'bg-[#E24B4A]' : 'bg-[#639922]'
            }`} />
            <span className={`relative inline-flex rounded-full h-2 w-2 ${
              criticalCount > 0 ? 'bg-[#E24B4A]' : 'bg-[#639922]'
            }`} />
          </span>
          <span className={criticalCount > 0 ? 'text-[#E24B4A]' : 'text-[#639922]'}>
            {criticalCount > 0 
              ? `${criticalCount} critical ${criticalCount === 1 ? 'finding' : 'findings'}`
              : 'Systems nominal'
            }
          </span>
        </div>

        {/* Theme Toggler */}
        <button
          onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          className="p-1.5 rounded-lg border border-gray-200 dark:border-slate-800 hover:bg-gray-100 dark:hover:bg-slate-800/50 text-gray-500 hover:text-gray-900 dark:hover:text-white transition"
          aria-label="Toggle visual theme"
        >
          {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>

        {/* Full Scan Button */}
        <button
          onClick={() => triggerScan()}
          disabled={isScanning}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-white bg-[#185FA5] hover:bg-[#134D87] disabled:bg-[#185FA5]/55 shadow-sm rounded-lg hover:shadow transition-all"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
          <span>{isScanning ? 'Scanning...' : 'Run Scan'}</span>
        </button>

      </div>
    </header>
  );
};

export default TopBar;
