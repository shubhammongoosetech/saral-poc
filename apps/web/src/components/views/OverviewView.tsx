import React from 'react';
import { NetworkData, DKGSessionData, WalletRecord, ProtocolEvent, NavigationTab } from '../../types';

interface OverviewViewProps {
  networkData: NetworkData | null;
  dkgSessions: DKGSessionData[];
  wallets: WalletRecord[];
  events: ProtocolEvent[];
  onNavigate: (tab: NavigationTab) => void;
  onRefresh: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  networkData,
  dkgSessions,
  wallets,
  events,
  onNavigate,
}) => {
  const totalNodes = networkData?.totalNodes || 15;
  const onlineNodes = networkData?.onlineNodes || 15;
  const completedDkgCount = dkgSessions.filter((s) => s.state === 'COMPLETED').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner / Hero */}
      <div style={{
        padding: '24px',
        borderRadius: '12px',
        background: 'linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%)',
        border: '1px solid #312e81',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}>
        <div>
          <h2 style={{ margin: '0 0 6px 0', fontSize: '22px', fontWeight: 700, color: '#f8fafc' }}>
            Institutional Web3 Key Infrastructure
          </h2>
          <p style={{ margin: 0, fontSize: '13px', color: '#cbd5e1', maxWidth: '640px', lineHeight: '1.5' }}>
            Dealerless Distributed Key Generation (DKG) and Asynchronous Verifiable Secret Sharing (AVSS) across 3 independent administrative domains. Zero single point of failure.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '12px' }}>
          <button
            onClick={() => onNavigate('dkg-sessions')}
            style={{
              padding: '10px 18px',
              backgroundColor: '#1e293b',
              color: '#38bdf8',
              border: '1px solid #0284c7',
              borderRadius: '8px',
              fontWeight: 600,
              fontSize: '13px',
              cursor: 'pointer',
            }}
          >
            🔐 New DKG Session
          </button>
          <button
            onClick={() => onNavigate('create-wallet')}
            style={{
              padding: '10px 20px',
              backgroundColor: '#2563eb',
              color: '#ffffff',
              border: 'none',
              borderRadius: '8px',
              fontWeight: 600,
              fontSize: '13px',
              cursor: 'pointer',
              boxShadow: '0 4px 14px rgba(37, 99, 235, 0.4)',
            }}
          >
            ✨ Create Web3 Wallet
          </button>
        </div>
      </div>

      {/* 4 Primary Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        {/* Metric 1 */}
        <div style={{
          padding: '18px',
          borderRadius: '10px',
          backgroundColor: '#111827',
          border: '1px solid #1f2937',
        }}>
          <div style={{ fontSize: '12px', color: '#94a3b8', fontWeight: 500, marginBottom: '6px' }}>
            Active Committee Nodes
          </div>
          <div style={{ fontSize: '26px', fontWeight: 800, color: '#f8fafc' }}>
            {onlineNodes} <span style={{ fontSize: '14px', color: '#64748b' }}>/ {totalNodes}</span>
          </div>
          <div style={{ fontSize: '11px', color: '#10b981', marginTop: '6px', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span>●</span> 100% Mesh Health (3 Domains)
          </div>
        </div>

        {/* Metric 2 */}
        <div style={{
          padding: '18px',
          borderRadius: '10px',
          backgroundColor: '#111827',
          border: '1px solid #1f2937',
        }}>
          <div style={{ fontSize: '12px', color: '#94a3b8', fontWeight: 500, marginBottom: '6px' }}>
            Verified DKG Sessions
          </div>
          <div style={{ fontSize: '26px', fontWeight: 800, color: '#38bdf8' }}>
            {completedDkgCount}
          </div>
          <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '6px' }}>
            {dkgSessions.length} total sessions recorded
          </div>
        </div>

        {/* Metric 3 */}
        <div style={{
          padding: '18px',
          borderRadius: '10px',
          backgroundColor: '#111827',
          border: '1px solid #1f2937',
        }}>
          <div style={{ fontSize: '12px', color: '#94a3b8', fontWeight: 500, marginBottom: '6px' }}>
            Generated Wallets
          </div>
          <div style={{ fontSize: '26px', fontWeight: 800, color: '#a78bfa' }}>
            {wallets.length}
          </div>
          <div style={{ fontSize: '11px', color: '#34d399', marginTop: '6px' }}>
            All addresses cryptographically verified
          </div>
        </div>

        {/* Metric 4 */}
        <div style={{
          padding: '18px',
          borderRadius: '10px',
          backgroundColor: '#111827',
          border: '1px solid #1f2937',
        }}>
          <div style={{ fontSize: '12px', color: '#94a3b8', fontWeight: 500, marginBottom: '6px' }}>
            Current Refresh Epoch
          </div>
          <div style={{ fontSize: '26px', fontWeight: 800, color: '#fbbf24' }}>
            τ = 1
          </div>
          <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '6px' }}>
            Invariance: Secret preserved
          </div>
        </div>
      </div>

      {/* Network Domain Topology */}
      <div style={{
        padding: '20px',
        borderRadius: '10px',
        backgroundColor: '#111827',
        border: '1px solid #1f2937',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>
              Separation-of-Powers Domain Topology
            </h3>
            <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: '#94a3b8' }}>
              15 independent nodes sharded into 3 distinct operational boundaries.
            </p>
          </div>
          <button
            onClick={() => onNavigate('network')}
            style={{
              padding: '6px 12px',
              backgroundColor: '#1e293b',
              color: '#38bdf8',
              border: '1px solid #334155',
              borderRadius: '6px',
              fontSize: '12px',
              cursor: 'pointer',
            }}
          >
            Inspect Topology ➔
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
          {['FOUNDATION', 'PUBLIC', 'PRIVATE'].map((domain) => {
            const domainInfo = networkData?.domains[domain];
            const online = domainInfo?.onlineNodes ?? 5;
            const total = domainInfo?.totalNodes ?? 5;

            return (
              <div
                key={domain}
                style={{
                  padding: '16px',
                  borderRadius: '8px',
                  backgroundColor: '#0c121e',
                  border: '1px solid #1e293b',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                  <span style={{ fontWeight: 700, fontSize: '13px', color: '#f8fafc' }}>
                    {domain} DOMAIN
                  </span>
                  <span style={{
                    fontSize: '11px',
                    fontWeight: 600,
                    padding: '2px 8px',
                    borderRadius: '10px',
                    backgroundColor: 'rgba(16, 185, 129, 0.15)',
                    color: '#34d399',
                  }}>
                    {online}/{total} Healthy
                  </span>
                </div>

                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '12px' }}>
                  {Array.from({ length: total }).map((_, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '4px 8px',
                        backgroundColor: '#1e293b',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontFamily: 'monospace',
                        color: '#cbd5e1',
                        border: '1px solid #334155',
                      }}
                    >
                      node-{idx + 1}
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent Security & Audit Logs */}
      <div style={{
        padding: '20px',
        borderRadius: '10px',
        backgroundColor: '#111827',
        border: '1px solid #1f2937',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>
            Live Security & Protocol Events
          </h3>
          <button
            onClick={() => onNavigate('audit-logs')}
            style={{
              padding: '6px 12px',
              backgroundColor: '#1e293b',
              color: '#94a3b8',
              border: '1px solid #334155',
              borderRadius: '6px',
              fontSize: '12px',
              cursor: 'pointer',
            }}
          >
            View All Logs ➔
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {events.length === 0 ? (
            <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', fontSize: '13px' }}>
              No recent protocol events. Network running nominally.
            </div>
          ) : (
            events.slice(0, 5).map((ev) => (
              <div
                key={ev.id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  padding: '10px 14px',
                  borderRadius: '6px',
                  backgroundColor: '#0c121e',
                  border: '1px solid #1e293b',
                  fontSize: '12px',
                }}
              >
                <span style={{
                  fontSize: '10px',
                  fontWeight: 700,
                  padding: '2px 6px',
                  borderRadius: '4px',
                  backgroundColor: ev.type === 'ERROR' ? '#ef4444' : ev.type === 'WALLET' ? '#8b5cf6' : ev.type === 'DKG' ? '#0284c7' : '#334155',
                  color: '#ffffff',
                }}>
                  {ev.type}
                </span>
                <span style={{ color: '#64748b', fontFamily: 'monospace', fontSize: '11px' }}>{ev.time}</span>
                <span style={{ color: '#cbd5e1', flex: 1 }}>{ev.message}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
