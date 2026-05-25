import React, { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import { useSecurityStore } from '../../store/securityStore';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  FileText, 
  Unlock, 
  Database, 
  UserCheck, 
  Settings,
  Clock
} from 'lucide-react';


export const Sidebar: React.FC = () => {
  const { logs, unauthorizedEvents, buckets, iamAnomalies } = useSecurityStore();
  const [utcTime, setUtcTime] = useState<string>('');

  // Live UTC Clock
  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      const pad = (n: number) => String(n).padStart(2, '0');
      const hours = pad(now.getUTCHours());
      const minutes = pad(now.getUTCMinutes());
      const seconds = pad(now.getUTCSeconds());
      setUtcTime(`${hours}:${minutes}:${seconds} UTC`);
    };

    updateClock();
    const interval = setInterval(updateClock, 1000);
    return () => clearInterval(interval);
  }, []);

  // Compute live Badge Counts
  const criticalCount = 
    logs.filter(l => l.severity === 'CRITICAL').length +
    unauthorizedEvents.filter(e => e.severity === 'CRITICAL').length +
    buckets.filter(b => !b.remediated && b.severity === 'CRITICAL').length +
    iamAnomalies.filter(i => i.severity === 'CRITICAL').length;

  const exposedS3Count = buckets.filter(b => !b.remediated && (b.severity === 'CRITICAL' || b.severity === 'HIGH')).length;
  const iamCount = iamAnomalies.length;
  const unauthCount = unauthorizedEvents.length;

  const navItems = [
    {
      to: '/',
      label: 'Overview',
      icon: LayoutDashboard,
      badge: criticalCount > 0 ? criticalCount : undefined,
      badgeType: 'critical'
    },
    {
      to: '/logs',
      label: 'AWS Logs',
      icon: FileText,
      badge: 'Live',
      badgeType: 'live'
    },
    {
      to: '/access',
      label: 'Unauthorized Access',
      icon: Unlock,
      badge: unauthCount > 0 ? unauthCount : undefined,
      badgeType: 'normal'
    },
    {
      to: '/s3',
      label: 'Public S3 Buckets',
      icon: Database,
      badge: exposedS3Count > 0 ? exposedS3Count : undefined,
      badgeType: 'warning'
    },
    {
      to: '/iam',
      label: 'IAM Misuse',
      icon: UserCheck,
      badge: iamCount > 0 ? iamCount : undefined,
      badgeType: 'normal'
    },
    {
      to: '/settings',
      label: 'Settings',
      icon: Settings
    }
  ];

  return (
    <>
      {/* Desktop Sidebar (Persistent left 200px) */}
      <aside 
        className="hidden md:flex flex-col fixed top-0 bottom-0 left-0 w-[220px] bg-slate-900 border-r border-slate-800 text-slate-400 select-none z-30"
      >
        {/* Brand Header */}
        <div className="p-4 border-b border-slate-800/80 flex items-center gap-2 shrink-0">
          <div className="bg-red-500/10 border border-red-500/20 p-2 rounded-lg">
            <ShieldAlert className="w-5 h-5 text-[#E24B4A]" />
          </div>
          <div>
            <h1 className="text-sm font-black text-white tracking-wider uppercase leading-none">
              CloudSentinel
            </h1>
            <span className="text-[10px] text-slate-500 uppercase font-semibold">
              AWS security monitor
            </span>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all group ${
                  isActive 
                    ? 'bg-[#185FA5] text-white' 
                    : 'hover:bg-slate-800/60 hover:text-slate-200'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <div className="flex items-center gap-2.5">
                    <item.icon className={`w-4 h-4 shrink-0 transition ${isActive ? 'text-white' : 'text-slate-500 group-hover:text-slate-300'}`} />
                    <span>{item.label}</span>
                  </div>
                  
                  {item.badge !== undefined && (
                    <span 
                      className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                        item.badgeType === 'critical' ? 'bg-[#E24B4A] text-white animate-pulse' :
                        item.badgeType === 'live' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 animate-pulse' :
                        item.badgeType === 'warning' ? 'bg-[#EF9F27] text-white' :
                        'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800/80 bg-slate-950/40 text-[10px] text-slate-500 space-y-1.5 shrink-0">
          <div className="flex items-center justify-between font-mono">
            <span>Region</span>
            <span className="font-bold text-[#378ADD]">us-east-1 · prod</span>
          </div>
          <div className="flex items-center gap-1.5 font-mono">
            <Clock className="w-3.5 h-3.5 text-slate-600" />
            <span>{utcTime}</span>
          </div>
        </div>
      </aside>

      {/* Mobile Bottom Navigation Bar (Screens < 768px) */}
      <nav 
        className="md:hidden fixed bottom-0 left-0 right-0 h-14 bg-slate-950/95 backdrop-blur-md border-t border-slate-800 flex items-center justify-around px-2 z-40"
      >
        {navItems.slice(0, 5).map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `relative flex flex-col items-center justify-center p-2 rounded-lg text-[9px] font-medium transition ${
                isActive ? 'text-white' : 'text-slate-500'
              }`
            }
          >
            <item.icon className="w-5 h-5 mb-0.5" />
            
            {/* Nav Label */}
            <span className="truncate max-w-[65px]">{item.label.split(' ')[0]}</span>

            {/* Badge Indicator */}
            {item.badge !== undefined && (
              <span 
                className={`absolute top-0 right-1 px-1.5 py-0.2 rounded-full text-[8px] font-bold scale-90 ${
                  item.badgeType === 'critical' ? 'bg-[#E24B4A] text-white animate-pulse' :
                  item.badgeType === 'live' ? 'bg-emerald-500 text-white font-extrabold animate-ping' :
                  item.badgeType === 'warning' ? 'bg-[#EF9F27] text-white' :
                  'bg-slate-800 text-slate-300'
                }`}
              >
                {item.badge === 'Live' ? '●' : item.badge}
              </span>
            )}
          </NavLink>
        ))}
      </nav>
    </>
  );
};

export default Sidebar;
