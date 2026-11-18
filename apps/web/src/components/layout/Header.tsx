import React from 'react';

interface HeaderProps {
  totalNodes: number;
  onlineNodes: number;
  activeEnvironment?: string;
  operatorName?: string;
  operatorRole?: string;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  totalNodes,
  onlineNodes,
  activeEnvironment = 'POC15 — Local Cluster (23 Containers)',
  operatorName = 'dev-operator',
  operatorRole = 'admin',
  onRefresh,
  isRefreshing = false,
}) => {
  const isHealthy = totalNodes > 0 && onlineNodes >= totalNodes;

  return (
    <header style={{
      height: '64px',
      backgroundColor: '#0c121e',
      borderBottom: '1px solid #1e293b',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 24px',
      position: 'sticky',
      top: 0,
      zIndex: 20,
    }}>
      {/* Environment & Breadcrumbs */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{
          fontSize: '11px',
          fontWeight: 600,
          padding: '4px 10px',
          borderRadius: '4px',
          backgroundColor: '#1e293b',
          color: '#38bdf8',
          border: '1px solid #334155',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
        }}>
          <span>⚡</span>
          <span>{activeEnvironment}</span>
        </div>

        {/* Network Health Indicator */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontSize: '12px',
        }}>
          <span style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            backgroundColor: isHealthy ? '#10b981' : '#f59e0b',
            boxShadow: isHealthy ? '0 0 8px #10b981' : '0 0 8px #f59e0b',
          }} />
          <span style={{ color: '#e2e8f0', fontWeight: 600 }}>
            {onlineNodes} / {totalNodes > 0 ? totalNodes : 15} Nodes Online
          </span>
          <span style={{ color: '#64748b' }}>•</span>
          <span style={{ color: '#94a3b8', fontSize: '11px' }}>
            3 Domains Active
          </span>
        </div>
      </div>

      {/* Operator Status & Actions */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            style={{
              padding: '6px 12px',
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '6px',
              color: '#e2e8f0',
              fontSize: '12px',
              fontWeight: 500,
              cursor: isRefreshing ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <span style={{ display: 'inline-block', transform: isRefreshing ? 'rotate(180deg)' : 'none', transition: 'transform 0.4s' }}>
              🔄
            </span>
            <span>{isRefreshing ? 'Refreshing...' : 'Refresh'}</span>
          </button>
        )}

        {/* Operator Profile */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          padding: '4px 10px',
          borderRadius: '6px',
          backgroundColor: '#111827',
          border: '1px solid #1f2937',
        }}>
          <div style={{
            width: '28px',
            height: '28px',
            borderRadius: '50%',
            backgroundColor: '#2563eb',
            color: '#ffffff',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '12px',
            fontWeight: 700,
          }}>
            {operatorName.charAt(0).toUpperCase()}
          </div>
          <div>
            <div style={{ fontSize: '12px', fontWeight: 600, color: '#f8fafc' }}>
              {operatorName}
            </div>
            <div style={{ fontSize: '10px', color: '#38bdf8', textTransform: 'uppercase', fontWeight: 700 }}>
              {operatorRole}
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
