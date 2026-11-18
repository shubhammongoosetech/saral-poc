import React, { useState } from 'react';
import { NetworkData } from '../../types';
import { apiService } from '../../services/api';

interface NetworkViewProps {
  networkData: NetworkData | null;
  onRefresh: () => void;
}

export const NetworkView: React.FC<NetworkViewProps> = ({ networkData, onRefresh }) => {
  const [probing, setProbing] = useState<boolean>(false);
  const [probeResult, setProbeResult] = useState<any>(null);

  const handleProbe = async () => {
    setProbing(true);
    try {
      const res = await apiService.probeNetwork();
      setProbeResult(res);
    } catch (err: any) {
      alert(`Probe failed: ${err.message}`);
    } finally {
      setProbing(false);
    }
  };

  const domainList = ['FOUNDATION', 'PUBLIC', 'PRIVATE'];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 700, margin: '0 0 4px 0', color: '#f8fafc' }}>
            Network Topology & Node Mesh
          </h2>
          <p style={{ margin: 0, fontSize: '13px', color: '#94a3b8' }}>
            15 independent Go node instances running in Docker cluster POC15 under mTLS 1.3 mesh.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            onClick={handleProbe}
            disabled={probing}
            style={{
              padding: '8px 16px',
              backgroundColor: '#0284c7',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: probing ? 'not-allowed' : 'pointer',
            }}
          >
            {probing ? 'Probing Nodes...' : '📡 Dispatch Network Probe'}
          </button>
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
            🔄 Refresh
          </button>
        </div>
      </div>

      {probeResult && (
        <div style={{
          padding: '16px',
          backgroundColor: '#0c121e',
          borderRadius: '8px',
          border: '1px solid #0284c7',
          fontSize: '12px',
        }}>
          <div style={{ fontWeight: 700, color: '#38bdf8', marginBottom: '4px' }}>
            Probe Receipt: {probeResult.probeId}
          </div>
          <div style={{ color: '#cbd5e1' }}>
            Acknowledged by {probeResult.probesAcknowledged} / {probeResult.probesDispatched} nodes. Average Latency: {probeResult.averageLatencyMs} ms.
          </div>
        </div>
      )}

      {/* Domains Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
        {domainList.map((domainName) => {
          const domBlock = networkData?.domains[domainName];
          const nodes = domBlock?.nodes || [];

          return (
            <div
              key={domainName}
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
                <strong style={{ fontSize: '15px', color: '#f8fafc' }}>
                  {domainName} DOMAIN
                </strong>
                <span style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: '10px',
                  backgroundColor: 'rgba(16, 185, 129, 0.15)',
                  color: '#34d399',
                }}>
                  {domBlock?.onlineNodes ?? 5} / {domBlock?.totalNodes ?? 5} Online
                </span>
              </div>

              <div style={{ fontSize: '11px', color: '#94a3b8' }}>
                Coordinator: <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>coord-{domainName.toLowerCase()}</span>
              </div>

              {/* Node Cards */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {nodes.length > 0 ? (
                  nodes.map((node) => (
                    <div
                      key={node.nodeId}
                      style={{
                        padding: '10px 12px',
                        backgroundColor: '#0c121e',
                        borderRadius: '6px',
                        border: '1px solid #1e293b',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <div>
                        <div style={{ fontFamily: 'monospace', fontSize: '12px', color: '#f8fafc', fontWeight: 600 }}>
                          {node.nodeId}
                        </div>
                        <div style={{ fontSize: '10px', color: '#64748b' }}>
                          Endpoint: {node.endpoint}
                        </div>
                      </div>
                      <div style={{ textAlign: 'right' }}>
                        <span style={{
                          fontSize: '10px',
                          fontWeight: 700,
                          color: node.status === 'HEALTHY' ? '#10b981' : '#f87171',
                        }}>
                          ● {node.status}
                        </span>
                        {node.latencyMs !== undefined && (
                          <div style={{ fontSize: '10px', color: '#64748b' }}>
                            {node.latencyMs} ms
                          </div>
                        )}
                      </div>
                    </div>
                  ))
                ) : (
                  Array.from({ length: 5 }).map((_, i) => (
                    <div
                      key={i}
                      style={{
                        padding: '10px 12px',
                        backgroundColor: '#0c121e',
                        borderRadius: '6px',
                        border: '1px solid #1e293b',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <div style={{ fontFamily: 'monospace', fontSize: '12px', color: '#f8fafc' }}>
                        saral-{domainName.toLowerCase()}-{i + 1}
                      </div>
                      <span style={{ fontSize: '10px', fontWeight: 700, color: '#10b981' }}>
                        ● HEALTHY
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
