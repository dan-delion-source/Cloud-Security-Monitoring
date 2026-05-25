import React, { useEffect } from 'react';
import { useSecurityStore } from '../store/securityStore';
import { useCloudTrail } from '../hooks/useCloudTrail';
import { useVpcFlowLogs } from '../hooks/useVpcFlowLogs';
import { useS3Scanner } from '../hooks/useS3Scanner';
import { useIamReport } from '../hooks/useIamReport';
import KpiCard from '../components/modules/overview/KpiCard';
import AlertFeed from '../components/modules/overview/AlertFeed';
import HourlyChart from '../components/modules/overview/HourlyChart';
import LogRow from '../components/shared/LogRow';

import { 
  ShieldAlert, 
  Unlock, 
  Database, 
  UserCheck, 
  History,
  FileSpreadsheet
} from 'lucide-react';

export const Overview: React.FC = () => {
  // Activate modular hooks to fetch initial or polling data
  useCloudTrail();
  useVpcFlowLogs();
  useS3Scanner();
  useIamReport();

  const { 
    logs, 
    unauthorizedEvents, 
    buckets, 
    iamAnomalies, 
    activeAlerts, 
    setActiveAlerts, 
    setSelectedEvent 
  } = useSecurityStore();

  // Populate active alerts dynamically if empty
  useEffect(() => {
    if (activeAlerts.length === 0 && (logs.length > 0 || unauthorizedEvents.length > 0 || buckets.length > 0 || iamAnomalies.length > 0)) {
      const alertsList: any[] = [];

      // Log alerts (Critical & High only)
      logs.filter(l => l.severity === 'CRITICAL' || l.severity === 'HIGH').forEach(l => {
        alertsList.push({
          id: `alert-log-${l.id}`,
          severity: l.severity,
          title: `CloudTrail: ${l.eventName}`,
          message: `Suspicious action by ${l.principalArn.substring(l.principalArn.lastIndexOf('/') + 1)}`,
          source: l.sourceIP,
          timestamp: l.timestamp,
          dismissed: false
        });
      });

      // S3 alerts (exposed S3 buckets)
      buckets.filter(b => !b.remediated && (b.severity === 'CRITICAL' || b.severity === 'HIGH')).forEach(b => {
        alertsList.push({
          id: `alert-s3-${b.id}`,
          severity: b.severity,
          title: `S3 Exposed: ${b.name}`,
          message: `Public read/write bucket policy is active in ${b.region}`,
          source: 'S3-Control',
          timestamp: new Date(Date.now() - 35 * 60000).toISOString(),
          dismissed: false
        });
      });

      // IAM anomalies (Critical & High)
      iamAnomalies.filter(i => i.severity === 'CRITICAL' || i.severity === 'HIGH').forEach(i => {
        alertsList.push({
          id: `alert-iam-${i.id}`,
          severity: i.severity,
          title: `IAM Abuse: ${i.title}`,
          message: i.detail,
          source: 'IAM-Identity',
          timestamp: i.timestamp,
          dismissed: false
        });
      });

      // VPC unauth
      unauthorizedEvents.filter(u => u.severity === 'CRITICAL' || u.severity === 'HIGH').forEach(u => {
        alertsList.push({
          id: `alert-unauth-${u.id}`,
          severity: u.severity,
          title: `Boundary Breach: ${u.routeType}`,
          message: u.description,
          source: u.sourceIP,
          timestamp: u.timestamp,
          dismissed: false
        });
      });

      // Sort desc
      alertsList.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      setActiveAlerts(alertsList.slice(0, 6));
    }
  }, [logs, unauthorizedEvents, buckets, iamAnomalies, activeAlerts, setActiveAlerts]);

  // Compute live KPI metrics
  const criticalCount = 
    logs.filter(l => l.severity === 'CRITICAL').length +
    unauthorizedEvents.filter(e => e.severity === 'CRITICAL').length +
    buckets.filter(b => !b.remediated && b.severity === 'CRITICAL').length +
    iamAnomalies.filter(i => i.severity === 'CRITICAL').length;

  const unauthCount = unauthorizedEvents.length;
  const exposedS3Count = buckets.filter(b => !b.remediated && (b.severity === 'CRITICAL' || b.severity === 'HIGH')).length;
  const iamAnomalyCount = iamAnomalies.length;

  // Last 6 logs for bottom panel
  const recentLogs = logs.slice(0, 6);

  return (
    <div className="space-y-4">
      
      {/* 4 KPI Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        
        <KpiCard
          label="Critical Findings"
          value={criticalCount}
          icon={ShieldAlert}
          trend="↑2 since yesterday"
          trendDirection="up"
          colorClass="text-[#E24B4A]"
          iconBgClass="bg-red-500/10 border-red-500/10 dark:border-red-500/5"
        />

        <KpiCard
          label="Unauthorized Events"
          value={unauthCount}
          icon={Unlock}
          trend="↑1 since yesterday"
          trendDirection="up"
          colorClass="text-[#EF9F27]"
          iconBgClass="bg-amber-500/10 border-amber-500/10 dark:border-amber-500/5"
        />

        <KpiCard
          label="Public S3 Buckets"
          value={exposedS3Count}
          icon={Database}
          trend="↓1 resolved"
          trendDirection="down"
          colorClass={exposedS3Count > 0 ? 'text-[#EF9F27]' : 'text-[#639922]'}
          iconBgClass={exposedS3Count > 0 
            ? 'bg-amber-500/10 border-amber-500/10' 
            : 'bg-emerald-500/10 border-emerald-500/10'
          }
        />

        <KpiCard
          label="IAM Anomalies"
          value={iamAnomalyCount}
          icon={UserCheck}
          trend="0 change today"
          trendDirection="neutral"
          colorClass={iamAnomalyCount > 3 ? 'text-[#E24B4A]' : 'text-[#378ADD]'}
          iconBgClass="bg-blue-500/10 border-blue-500/10 dark:border-blue-500/5"
        />

      </div>

      {/* Middle Grid (Alert Feed & Chart) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <AlertFeed />
        <HourlyChart />
      </div>

      {/* Bottom Panel (Recent CloudTrail Events) */}
      <div className="glass-card p-4 select-none">
        
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800/60 mb-2 shrink-0">
          <h3 className="text-xs font-black uppercase tracking-widest text-gray-900 dark:text-white flex items-center gap-1.5">
            <History className="w-4 h-4 text-[#185FA5]" />
            Recent Activity Audits
          </h3>
          <span className="text-[10px] text-gray-400 font-mono">
            Last 6 active CloudTrail actions
          </span>
        </div>

        {/* Table Layout */}
        <div className="border border-gray-200 dark:border-gray-800 rounded-lg overflow-hidden">
          <div className="flex items-center bg-gray-50 dark:bg-[#152035]/60 text-[10px] font-extrabold uppercase tracking-wider text-gray-500 dark:text-gray-400 py-3 px-4 select-none">
            <div className="w-12 text-center">Severity</div>
            <div className="w-[22%] pr-3">Event Name</div>
            <div className="w-[38%] pr-3">Principal ARN</div>
            <div className="w-[18%]">Source IP</div>
            <div className="w-[22%] text-right">Timestamp</div>
          </div>

          <div className="divide-y divide-gray-100 dark:divide-gray-800/60 relative h-[264px]">
            {recentLogs.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center text-xs text-gray-400">
                <FileSpreadsheet className="w-6 h-6 text-gray-400 mb-1" />
                <p className="font-semibold text-gray-700 dark:text-gray-300">Audits empty</p>
              </div>
            ) : (
              recentLogs.map((log, idx) => (
                <LogRow
                  key={log.id}
                  log={log}
                  onClick={() => setSelectedEvent({ type: 'log', data: log })}
                  style={{
                    height: '44px',
                    position: 'absolute',
                    top: `${idx * 44}px`,
                    width: '100%'
                  }}
                />
              ))
            )}
          </div>
        </div>

      </div>

    </div>
  );
};

export default Overview;
