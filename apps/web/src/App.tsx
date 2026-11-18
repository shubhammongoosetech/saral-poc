import React, { useState, useEffect, useCallback } from 'react';

interface NodeItem {
  nodeId: string;
  domain: string;
  nodeIndex: number;
  endpoint: string;
  status: string;
  latencyMs?: number;
  peerCount?: number;
  publicKeyHex?: string;
}

interface DomainBlock {
  domain: string;
  coordinator: string;
  totalNodes: number;
  onlineNodes: number;
  nodes: NodeItem[];
}

interface ProbeResultItem {
  requestId: string;
  probeId: string;
  sender: string;
  receiverId: string;
  domain: string;
  timestamp: number;
  acknowledged: boolean;
  latencyMs: number;
  signatureHex?: string;
  error?: string;
}

interface NetworkProbeData {
  probeId: string;
  requestId: string;
  senderCoordinator: string;
  probesDispatched: number;
  probesAcknowledged: number;
  averageLatencyMs: number;
  probes: ProbeResultItem[];
  timestamp: string;
}

interface ProtocolEvent {
  id: string;
  time: string;
  type: 'INFO' | 'PROBE' | 'AUTH' | 'ERROR';
  message: string;
}

export const App: React.FC = () => {
  const [coordUrl, setCoordUrl] = useState<string>('http://localhost:9001');
  const [authUrl] = useState<string>('http://localhost:3001');
  const [networkData, setNetworkData] = useState<{
    totalNodes: number;
    onlineNodes: number;
    domains: Record<string, DomainBlock>;
  } | null>(null);

  const [lastProbe, setLastProbe] = useState<NetworkProbeData | null>(null);
  const [events, setEvents] = useState<ProtocolEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [probing, setProbing] = useState<boolean>(false);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [errorMsg, setErrorMsg] = useState<string>('');

  const addEvent = useCallback((type: ProtocolEvent['type'], message: string) => {
    setEvents((prev) => [
      {
        id: Math.random().toString(36).substring(2, 9),
        time: new Date().toLocaleTimeString(),
        type,
        message,
      },
      ...prev.slice(0, 49),
    ]);
  }, []);

  // Fetch Token and Network Status
  const fetchNetworkStatus = useCallback(async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      // 1. Get dev token from Auth Server
      let token = '';
      try {
        const tokenRes = await fetch(`${authUrl}/auth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ subject: 'dashboard-viewer', role: 'admin' }),
        });
        if (tokenRes.ok) {
          const tData = await tokenRes.json();
          token = tData.token;
        }
      } catch {
        // Fallback without token
      }

      // 2. Call saral_getNetworkStatus on Coordinator
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const rpcRes = await fetch(`${coordUrl}/rpc`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method: 'saral_getNetworkStatus',
          params: {},
        }),
      });

      if (!rpcRes.ok) {
        throw new Error(`Coordinator returned HTTP ${rpcRes.status}`);
      }

      const json = await rpcRes.json();
      if (json.error) {
        throw new Error(json.error.message);
      }

      setNetworkData(json.result);
      addEvent('INFO', `Updated network status from ${coordUrl} (${json.result.onlineNodes}/${json.result.totalNodes} nodes online)`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setErrorMsg(msg);
      addEvent('ERROR', `Failed to poll coordinator: ${msg}`);
    } finally {
      setLoading(false);
    }
  }, [coordUrl, authUrl, addEvent]);

  // Execute Real Network Probe
  const handleRunProbe = async () => {
    setProbing(true);
    addEvent('PROBE', 'Initiating cross-domain network probe...');
    try {
      let token = '';
      try {
        const tokenRes = await fetch(`${authUrl}/auth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ subject: 'dashboard-prober', role: 'admin' }),
        });
        if (tokenRes.ok) {
          const tData = await tokenRes.json();
          token = tData.token;
        }
      } catch {
        // Ignore
      }

      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const rpcRes = await fetch(`${coordUrl}/rpc`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method: 'saral_probeNetwork',
          params: {},
        }),
      });

      const json = await rpcRes.json();
      if (json.error) {
        throw new Error(json.error.message);
      }

      setLastProbe(json.result);
      addEvent(
        'PROBE',
        `Probe ${json.result.probeId} complete: ${json.result.probesAcknowledged}/${json.result.probesDispatched} nodes acknowledged (${json.result.averageLatencyMs}ms avg)`
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      addEvent('ERROR', `Probe error: ${msg}`);
    } finally {
      setProbing(false);
    }
  };

  useEffect(() => {
    fetchNetworkStatus();
    if (!autoRefresh) return;
    const interval = setInterval(fetchNetworkStatus, 4000);
    return () => clearInterval(interval);
  }, [fetchNetworkStatus, autoRefresh]);

  const domainList = ['FOUNDATION', 'PUBLIC', 'PRIVATE'];

  return (
    <div style={{ backgroundColor: '#090d16', color: '#f3f4f6', minHeight: '100vh', fontFamily: 'system-ui, sans-serif' }}>
      {/* Header */}
      <header style={{ borderBottom: '1px solid #1f293d', padding: '16px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '50%', backgroundColor: errorMsg ? '#ef4444' : '#10b981' }} />
            <h1 style={{ fontSize: '20px', fontWeight: 'bold', margin: 0, letterSpacing: '0.5px' }}>
              SARAL Protocol V3 — Network Architecture Dashboard
            </h1>
          </div>
          <p style={{ color: '#9ca3af', fontSize: '13px', margin: '4px 0 0 22px' }}>
            Separation-of-Powers Cryptographic Key Infrastructure
          </p>
        </div>

        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <select
            value={coordUrl}
            onChange={(e) => setCoordUrl(e.target.value)}
            style={{
              backgroundColor: '#131b2e',
              border: '1px solid #2d3748',
              color: '#f3f4f6',
              padding: '6px 12px',
              borderRadius: '6px',
              fontSize: '13px',
            }}
          >
            <option value="http://localhost:9001">Foundation Coord (:9001)</option>
            <option value="http://localhost:9002">Public Coord (:9002)</option>
            <option value="http://localhost:9003">Private Coord (:9003)</option>
          </select>

          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            style={{
              backgroundColor: autoRefresh ? '#1e293b' : '#334155',
              border: '1px solid #475569',
              color: '#cbd5e1',
              padding: '6px 12px',
              borderRadius: '6px',
              fontSize: '13px',
              cursor: 'pointer',
            }}
          >
            {autoRefresh ? (loading ? 'Refreshing...' : 'Auto-refresh: ON') : 'Auto-refresh: OFF'}
          </button>

          <button
            onClick={handleRunProbe}
            disabled={probing}
            style={{
              backgroundColor: probing ? '#475569' : '#2563eb',
              border: 'none',
              color: '#ffffff',
              padding: '7px 16px',
              borderRadius: '6px',
              fontWeight: 600,
              fontSize: '13px',
              cursor: probing ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            {probing ? 'Probing Network...' : '⚡ Run Network Probe'}
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main style={{ padding: '24px', maxWidth: '1440px', margin: '0 auto' }}>
        {errorMsg && (
          <div style={{ backgroundColor: '#7f1d1d', border: '1px solid #b91c1c', padding: '12px 16px', borderRadius: '8px', marginBottom: '20px', color: '#fecaca', fontSize: '14px' }}>
            <strong>Connection Warning:</strong> {errorMsg} (Ensure 15-node POC containers or local nodes are running).
          </div>
        )}

        {/* Status Metrics Bar */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>
          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', padding: '16px', borderRadius: '8px' }}>
            <div style={{ color: '#9ca3af', fontSize: '12px', textTransform: 'uppercase', fontWeight: 600 }}>Total Enrolled Nodes</div>
            <div style={{ fontSize: '28px', fontWeight: 'bold', marginTop: '6px', color: '#38bdf8' }}>
              {networkData?.totalNodes ?? 0}
            </div>
          </div>
          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', padding: '16px', borderRadius: '8px' }}>
            <div style={{ color: '#9ca3af', fontSize: '12px', textTransform: 'uppercase', fontWeight: 600 }}>Active Online Nodes</div>
            <div style={{ fontSize: '28px', fontWeight: 'bold', marginTop: '6px', color: '#34d399' }}>
              {networkData?.onlineNodes ?? 0}
            </div>
          </div>
          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', padding: '16px', borderRadius: '8px' }}>
            <div style={{ color: '#9ca3af', fontSize: '12px', textTransform: 'uppercase', fontWeight: 600 }}>Active Domains</div>
            <div style={{ fontSize: '28px', fontWeight: 'bold', marginTop: '6px', color: '#a78bfa' }}>
              3 / 3
            </div>
          </div>
          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', padding: '16px', borderRadius: '8px' }}>
            <div style={{ color: '#9ca3af', fontSize: '12px', textTransform: 'uppercase', fontWeight: 600 }}>Avg Network Latency</div>
            <div style={{ fontSize: '28px', fontWeight: 'bold', marginTop: '6px', color: '#fbbf24' }}>
              {lastProbe ? `${lastProbe.averageLatencyMs} ms` : '—'}
            </div>
          </div>
        </div>

        {/* Three Domain Grid */}
        <h2 style={{ fontSize: '16px', fontWeight: 600, color: '#e5e7eb', marginBottom: '12px' }}>
          Cross-Domain Architecture Topologies
        </h2>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '24px' }}>
          {domainList.map((dName) => {
            const domainData = networkData?.domains?.[dName];
            const nodes = domainData?.nodes || [];
            const isHealthy = domainData?.coordinator === 'HEALTHY' || (domainData?.onlineNodes || 0) > 0;

            return (
              <div
                key={dName}
                style={{
                  backgroundColor: '#111827',
                  border: `1px solid ${isHealthy ? '#1e293b' : '#374151'}`,
                  borderRadius: '8px',
                  padding: '16px',
                  display: 'flex',
                  flexDirection: 'column',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1f2937', paddingBottom: '12px', marginBottom: '12px' }}>
                  <div>
                    <span style={{ fontSize: '11px', fontWeight: 700, color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      Administrative Realm
                    </span>
                    <h3 style={{ fontSize: '16px', fontWeight: 'bold', margin: '2px 0 0 0', color: dName === 'FOUNDATION' ? '#60a5fa' : dName === 'PUBLIC' ? '#34d399' : '#f472b6' }}>
                      {dName} Domain
                    </h3>
                  </div>
                  <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                    <span
                      style={{
                        fontSize: '11px',
                        fontWeight: 600,
                        padding: '3px 8px',
                        borderRadius: '4px',
                        backgroundColor: isHealthy ? '#064e3b' : '#450a0a',
                        color: isHealthy ? '#6ee7b7' : '#fca5a5',
                      }}
                    >
                      {isHealthy ? 'COORDINATOR ONLINE' : 'OFFLINE'}
                    </span>
                    <span
                      style={{
                        fontSize: '11px',
                        fontWeight: 600,
                        padding: '3px 8px',
                        borderRadius: '4px',
                        backgroundColor: isHealthy ? '#1e1b4b' : '#312e81',
                        color: '#c7d2fe',
                      }}
                    >
                      VERIFIER ACTIVE
                    </span>
                  </div>
                </div>

                <div style={{ fontSize: '13px', color: '#9ca3af', marginBottom: '12px', display: 'flex', justifyContent: 'space-between' }}>
                  <span>Enrolled Nodes: <strong>{nodes.length}</strong></span>
                  <span>Online: <strong style={{ color: '#10b981' }}>{domainData?.onlineNodes ?? 0}</strong></span>
                </div>

                {/* Nodes List */}
                <div style={{ flex: 1, maxHeight: '240px', overflowY: 'auto' }}>
                  {nodes.length === 0 ? (
                    <div style={{ color: '#6b7280', fontSize: '12px', textAlign: 'center', padding: '20px 0' }}>
                      No nodes discovered in this domain.
                    </div>
                  ) : (
                    nodes.map((node) => (
                      <div
                        key={node.nodeId}
                        style={{
                          backgroundColor: '#182234',
                          padding: '8px 10px',
                          borderRadius: '6px',
                          marginBottom: '6px',
                          fontSize: '12px',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                        }}
                      >
                        <div>
                          <div style={{ fontWeight: 600, color: '#e2e8f0' }}>{node.nodeId}</div>
                          <div style={{ color: '#64748b', fontSize: '11px', fontFamily: 'monospace' }}>
                            {node.publicKeyHex ? `${node.publicKeyHex.substring(0, 12)}...` : node.endpoint}
                          </div>
                        </div>
                        <div style={{ textAlign: 'right' }}>
                          <span
                            style={{
                              fontSize: '10px',
                              fontWeight: 700,
                              color: node.status === 'HEALTHY' ? '#34d399' : '#f87171',
                            }}
                          >
                            ● {node.status}
                          </span>
                          {node.peerCount !== undefined && (
                            <div style={{ color: '#94a3b8', fontSize: '10px' }}>
                              {node.peerCount} P2P peers
                            </div>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* Lower Grid: Probe Results & Protocol Events */}
        <div style={{ display: 'grid', gridTemplateColumns: '3fr 2fr', gap: '16px' }}>
          {/* Probe Results Panel */}
          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <h3 style={{ fontSize: '15px', fontWeight: 600, margin: 0, color: '#f3f4f6' }}>
                Live Network Probe Evidence
              </h3>
              {lastProbe && (
                <span style={{ fontSize: '12px', color: '#9ca3af' }}>
                  ID: <code style={{ color: '#38bdf8' }}>{lastProbe.probeId}</code> ({lastProbe.probesAcknowledged}/{lastProbe.probesDispatched} Acks)
                </span>
              )}
            </div>

            {!lastProbe ? (
              <div style={{ color: '#6b7280', fontSize: '13px', padding: '36px 0', textAlign: 'center' }}>
                Click <strong>"Run Network Probe"</strong> above to send authenticated P2P probe messages across all nodes and coordinators.
              </div>
            ) : (
              <div style={{ maxHeight: '280px', overflowY: 'auto' }}>
                <table style={{ width: '100%', fontSize: '12px', borderCollapse: 'collapse', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ color: '#9ca3af', borderBottom: '1px solid #1f2937' }}>
                      <th style={{ padding: '6px 8px' }}>Node ID</th>
                      <th style={{ padding: '6px 8px' }}>Domain</th>
                      <th style={{ padding: '6px 8px' }}>Latency</th>
                      <th style={{ padding: '6px 8px' }}>Ack Status</th>
                      <th style={{ padding: '6px 8px' }}>Ed25519 Sig</th>
                    </tr>
                  </thead>
                  <tbody>
                    {lastProbe.probes.map((pr) => (
                      <tr key={pr.receiverId} style={{ borderBottom: '1px solid #1e293b' }}>
                        <td style={{ padding: '6px 8px', fontWeight: 600 }}>{pr.receiverId}</td>
                        <td style={{ padding: '6px 8px', color: '#94a3b8' }}>{pr.domain}</td>
                        <td style={{ padding: '6px 8px', color: '#fbbf24' }}>{pr.latencyMs} ms</td>
                        <td style={{ padding: '6px 8px' }}>
                          <span style={{ color: pr.acknowledged ? '#34d399' : '#f87171', fontWeight: 600 }}>
                            {pr.acknowledged ? '✓ ACK' : '✗ FAILED'}
                          </span>
                        </td>
                        <td style={{ padding: '6px 8px', fontFamily: 'monospace', color: '#64748b' }}>
                          {pr.signatureHex ? `${pr.signatureHex.substring(0, 14)}...` : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Protocol Event Log */}
          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '16px' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 600, margin: '0 0 12px 0', color: '#f3f4f6' }}>
              Protocol Event Stream
            </h3>
            <div style={{ maxHeight: '280px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {events.length === 0 ? (
                <div style={{ color: '#6b7280', fontSize: '13px', padding: '24px 0', textAlign: 'center' }}>
                  Awaiting protocol events...
                </div>
              ) : (
                events.map((evt) => (
                  <div
                    key={evt.id}
                    style={{
                      fontSize: '11px',
                      padding: '6px 8px',
                      borderRadius: '4px',
                      backgroundColor: '#182234',
                      borderLeft: `3px solid ${
                        evt.type === 'PROBE' ? '#38bdf8' : evt.type === 'ERROR' ? '#ef4444' : '#10b981'
                      }`,
                    }}
                  >
                    <span style={{ color: '#64748b', marginRight: '6px' }}>[{evt.time}]</span>
                    <span style={{ fontWeight: 600, color: evt.type === 'ERROR' ? '#fca5a5' : '#e2e8f0' }}>
                      {evt.message}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default App;
