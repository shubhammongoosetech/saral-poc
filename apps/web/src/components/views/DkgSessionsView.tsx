import React, { useState } from 'react';
import { DKGSessionData, NavigationTab } from '../../types';
import { apiService } from '../../services/api';

interface DkgSessionsViewProps {
  dkgSessions: DKGSessionData[];
  onDkgStarted: (sessionId: string) => void;
  onNavigate: (tab: NavigationTab) => void;
  onRefresh: () => void;
}

export const DkgSessionsView: React.FC<DkgSessionsViewProps> = ({
  dkgSessions,
  onDkgStarted,
  onNavigate,
  onRefresh,
}) => {
  const [selectedCommittee, setSelectedCommittee] = useState<'GLOBAL' | 'FOUNDATION'>('GLOBAL');
  const [starting, setStarting] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string>('');
  const [successMsg, setSuccessMsg] = useState<string>('');

  const handleStartDkg = async () => {
    setStarting(true);
    setErrorMsg('');
    setSuccessMsg('');

    try {
      const isGlobal = selectedCommittee === 'GLOBAL';
      const n = isGlobal ? 15 : 5;
      const k = isGlobal ? 5 : 2;
      const t = isGlobal ? 4 : 1;
      const committeeId = isGlobal ? 'saral-global-15' : 'saral-foundation-5';

      const result = await apiService.startDkg({ n, k, t, committeeId });
      setSuccessMsg(`DKG session ${result.sessionId} initiated! Contributions underway.`);
      onDkgStarted(result.sessionId);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to start DKG');
    } finally {
      setStarting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header and Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 700, margin: '0 0 4px 0', color: '#f8fafc' }}>
            Dealerless Distributed Key Generation (DKG)
          </h2>
          <p style={{ margin: 0, fontSize: '13px', color: '#94a3b8' }}>
            Kate, Huang, Goldberg (ASIACCS 2012) — Asynchronous Bivariate AVSS & Common Coin Agreement
          </p>
        </div>
        <button
          onClick={onRefresh}
          style={{
            padding: '8px 14px',
            backgroundColor: '#1e293b',
            color: '#cbd5e1',
            border: '1px solid #334155',
            borderRadius: '6px',
            fontSize: '12px',
            cursor: 'pointer',
          }}
        >
          🔄 Refresh Sessions
        </button>
      </div>

      {/* DKG Session Creation Wizard Box */}
      <div style={{
        backgroundColor: '#111827',
        border: '1px solid #1f2937',
        borderRadius: '10px',
        padding: '24px',
        display: 'flex',
        flexDirection: 'column',
        gap: '18px',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>
              Launch New DKG Session
            </h3>
            <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: '#94a3b8' }}>
              Each participant independently samples secret contribution scalars. No trusted dealer exists.
            </p>
          </div>
          <span style={{
            fontSize: '11px',
            fontWeight: 700,
            padding: '3px 8px',
            borderRadius: '4px',
            backgroundColor: 'rgba(56, 189, 248, 0.15)',
            color: '#38bdf8',
          }}>
            NIST P-256 Curve
          </span>
        </div>

        {/* Committee Topology Selector */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
          <div
            onClick={() => setSelectedCommittee('GLOBAL')}
            style={{
              padding: '14px',
              borderRadius: '8px',
              cursor: 'pointer',
              backgroundColor: selectedCommittee === 'GLOBAL' ? '#1e293b' : '#0c121e',
              border: `2px solid ${selectedCommittee === 'GLOBAL' ? '#38bdf8' : '#1e293b'}`,
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <strong style={{ fontSize: '13px', color: '#f8fafc' }}>Global Committee (15 Nodes)</strong>
              <span style={{ fontSize: '11px', color: '#38bdf8', fontWeight: 600 }}>n=15, t=4, k=5</span>
            </div>
            <p style={{ margin: 0, fontSize: '11px', color: '#94a3b8', lineHeight: '1.4' }}>
              Cross-domain committee across Foundation, Public, and Private. Tolerates 4 Byzantine faults. Minimum qualified set: |QUAL*| ≥ 11 nodes.
            </p>
          </div>

          <div
            onClick={() => setSelectedCommittee('FOUNDATION')}
            style={{
              padding: '14px',
              borderRadius: '8px',
              cursor: 'pointer',
              backgroundColor: selectedCommittee === 'FOUNDATION' ? '#1e293b' : '#0c121e',
              border: `2px solid ${selectedCommittee === 'FOUNDATION' ? '#38bdf8' : '#1e293b'}`,
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <strong style={{ fontSize: '13px', color: '#f8fafc' }}>Domain Committee (5 Nodes)</strong>
              <span style={{ fontSize: '11px', color: '#38bdf8', fontWeight: 600 }}>n=5, t=1, k=2</span>
            </div>
            <p style={{ margin: 0, fontSize: '11px', color: '#94a3b8', lineHeight: '1.4' }}>
              Single-domain committee. Fault tolerance: t=1. Reconstruction threshold: k=2. Minimum qualified set: |QUAL*| ≥ 4 nodes.
            </p>
          </div>
        </div>

        {errorMsg && (
          <div style={{ padding: '10px 14px', borderRadius: '6px', backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', color: '#f87171', fontSize: '12px' }}>
            {errorMsg}
          </div>
        )}

        {successMsg && (
          <div style={{ padding: '10px 14px', borderRadius: '6px', backgroundColor: 'rgba(16, 185, 129, 0.1)', border: '1px solid #10b981', color: '#34d399', fontSize: '12px' }}>
            {successMsg}
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button
            onClick={handleStartDkg}
            disabled={starting}
            style={{
              padding: '10px 22px',
              backgroundColor: '#2563eb',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              fontWeight: 600,
              fontSize: '13px',
              cursor: starting ? 'not-allowed' : 'pointer',
              opacity: starting ? 0.7 : 1,
            }}
          >
            {starting ? 'Initiating AVSS Shares...' : '🚀 Start Dealerless DKG'}
          </button>
        </div>
      </div>

      {/* DKG Sessions List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>
          Active & Completed DKG Sessions
        </h3>

        {dkgSessions.length === 0 ? (
          <div style={{ padding: '36px', textAlign: 'center', backgroundColor: '#111827', borderRadius: '10px', border: '1px dashed #334155', color: '#94a3b8', fontSize: '13px' }}>
            No DKG sessions recorded on coordinator. Click "Start Dealerless DKG" above to run session.
          </div>
        ) : (
          dkgSessions.map((s) => (
            <div
              key={s.sessionId}
              style={{
                backgroundColor: '#111827',
                border: '1px solid #1f2937',
                borderRadius: '10px',
                padding: '20px',
                display: 'flex',
                flexDirection: 'column',
                gap: '14px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={{ fontSize: '14px', fontWeight: 700, color: '#38bdf8', fontFamily: 'monospace' }}>
                      {s.sessionId}
                    </span>
                    <span style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: '4px',
                      backgroundColor: s.state === 'COMPLETED' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(56, 189, 248, 0.2)',
                      color: s.state === 'COMPLETED' ? '#34d399' : '#38bdf8',
                    }}>
                      ● {s.state}
                    </span>
                  </div>
                  <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px' }}>
                    Committee: <strong style={{ color: '#cbd5e1' }}>{s.committeeId}</strong> | Progress: <strong style={{ color: '#34d399' }}>{s.completedNodes} / {s.totalNodes} Nodes Finalized</strong>
                  </div>
                </div>

                {s.state === 'COMPLETED' && (
                  <button
                    onClick={() => onNavigate('create-wallet')}
                    style={{
                      padding: '8px 16px',
                      backgroundColor: '#2563eb',
                      color: '#ffffff',
                      border: 'none',
                      borderRadius: '6px',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    ✨ Create Wallet from Key ➔
                  </button>
                )}
              </div>

              {/* Progress Bar */}
              <div style={{ height: '6px', backgroundColor: '#0c121e', borderRadius: '3px', overflow: 'hidden' }}>
                <div style={{
                  height: '100%',
                  width: `${(s.completedNodes / Math.max(s.totalNodes, 1)) * 100}%`,
                  backgroundColor: s.state === 'COMPLETED' ? '#10b981' : '#38bdf8',
                }} />
              </div>

              {/* Master Signing Key Display */}
              {s.masterPublicKey && (
                <div style={{
                  backgroundColor: '#0c121e',
                  borderRadius: '6px',
                  padding: '10px 12px',
                  border: '1px solid #1e293b',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                }}>
                  <div style={{ color: '#94a3b8', marginBottom: '2px' }}>
                    Unblinded Master Signing Public Key (Y = x*G):
                  </div>
                  <div style={{ color: '#34d399', wordBreak: 'break-all' }}>
                    {s.masterPublicKey}
                  </div>
                </div>
              )}

              {/* Qualified Set Badges */}
              {s.qualifiedSet && s.qualifiedSet.length > 0 && (
                <div>
                  <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '4px' }}>
                    Agreed Qualified Contributor Set (QUAL*):
                  </div>
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {s.qualifiedSet.map((nodeId) => (
                      <span
                        key={nodeId}
                        style={{
                          fontSize: '10px',
                          fontFamily: 'monospace',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          backgroundColor: 'rgba(16, 185, 129, 0.15)',
                          color: '#34d399',
                          border: '1px solid rgba(16, 185, 129, 0.3)',
                        }}
                      >
                        {nodeId}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};
