import React from 'react';
import type { IamAnomaly } from '../../../types/iam';
import { useSecurityStore } from '../../../store/securityStore';
import { 
  ShieldAlert, 
  UserX, 
  Key, 
  Lock, 
  Compass, 
  HelpCircle,
  AlertOctagon,
  Eye,
  FileCode,
  RotateCcw
} from 'lucide-react';
import StatusBadge from '../../shared/StatusBadge';

interface IamFindingCardProps {
  finding: IamAnomaly;
}

export const IamFindingCard: React.FC<IamFindingCardProps> = ({ finding }) => {
  const { setSelectedEvent } = useSecurityStore();

  // Get appropriate icon based on the pattern type
  const getPatternIcon = () => {
    switch (finding.pattern) {
      case 'root_login':
        return <AlertOctagon className="w-5 h-5" />;
      case 'passrole_privesc':
        return <UserX className="w-5 h-5" />;
      case 'foreign_sts_assume':
        return <Lock className="w-5 h-5" />;
      case 'access_key_age':
        return <Key className="w-5 h-5" />;
      case 'admin_service_role':
        return <ShieldAlert className="w-5 h-5" />;
      case 'mfa_missing':
        return <Compass className="w-5 h-5" />;
      default:
        return <HelpCircle className="w-5 h-5" />;
    }
  };

  // Color code icon bg/text based on severity
  const getSeverityStyle = () => {
    switch (finding.severity) {
      case 'CRITICAL':
        return {
          text: 'text-[#E24B4A]',
          bg: 'bg-[#E24B4A]/10 border-l-4 border-l-[#E24B4A]'
        };
      case 'HIGH':
        return {
          text: 'text-[#EF9F27]',
          bg: 'bg-[#EF9F27]/10 border-l-4 border-l-[#EF9F27]'
        };
      case 'MEDIUM':
        return {
          text: 'text-[#378ADD]',
          bg: 'bg-[#378ADD]/10 border-l-4 border-l-[#378ADD]'
        };
      case 'LOW':
        return {
          text: 'text-[#639922]',
          bg: 'bg-[#639922]/10 border-l-4 border-l-[#639922]'
        };
      default:
        return {
          text: 'text-gray-500',
          bg: 'bg-gray-100 border-l-4 border-l-gray-400'
        };
    }
  };

  const style = getSeverityStyle();

  // Pick button icon based on action text
  const getButtonIcon = () => {
    if (finding.actionText.includes('Investigate')) return <Eye className="w-3.5 h-3.5 shrink-0" />;
    if (finding.actionText.includes('Rotate')) return <RotateCcw className="w-3.5 h-3.5 shrink-0" />;
    return <FileCode className="w-3.5 h-3.5 shrink-0" />;
  };

  return (
    <div
      onClick={() => setSelectedEvent({ type: 'iam', data: finding })}
      className="glass-card hover:shadow-md border-gray-200/50 dark:border-gray-800/50 p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 cursor-pointer hover:border-gray-300 dark:hover:border-gray-700/80 transition duration-200 select-none"
    >
      
      {/* Finding Detail Block */}
      <div className="flex items-start gap-3.5 min-w-0 flex-1">
        {/* Icon wrapper */}
        <div className={`p-2.5 rounded-xl shrink-0 ${style.bg.split(' ')[0]} ${style.text} border border-transparent`}>
          {getPatternIcon()}
        </div>
        
        {/* Texts */}
        <div className="space-y-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h4 className="text-xs font-black text-gray-950 dark:text-white uppercase leading-none tracking-wide">
              {finding.title}
            </h4>
            <StatusBadge severity={finding.severity} />
          </div>
          <p className="text-[11px] text-gray-500 dark:text-gray-400 font-medium font-mono leading-relaxed truncate">
            {finding.detail}
          </p>
          <div className="text-[9px] text-gray-400 font-mono">
            Pattern rule: {finding.pattern} · Detected: {new Date(finding.timestamp).toUTCString()}
          </div>
        </div>
      </div>

      {/* Action Button */}
      <div className="shrink-0 flex items-center justify-end">
        <button
          onClick={(e) => {
            e.stopPropagation();
            setSelectedEvent({ type: 'iam', data: finding });
          }}
          className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-bold text-white rounded-lg transition-all shadow-sm hover:shadow ${
            finding.severity === 'CRITICAL' ? 'bg-[#E24B4A] hover:bg-red-650' :
            finding.severity === 'HIGH' ? 'bg-[#EF9F27] hover:bg-amber-600' :
            finding.severity === 'MEDIUM' ? 'bg-[#378ADD] hover:bg-blue-600' : 'bg-slate-700 hover:bg-slate-800'
          }`}
        >
          {getButtonIcon()}
          <span>{finding.actionText}</span>
        </button>
      </div>

    </div>
  );
};

export default IamFindingCard;
