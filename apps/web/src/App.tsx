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

interface RelayAckItem {
  messageId: string;
  targetNode: string;
  targetDomain: string;
  sourceNode: string;
  sourceDomain: string;
  status: string;
  timestamp: number;
  latencyMs: number;
  recipientSigHex?: string;
  recipientPubKey?: string;
  forwardedBy?: string[];
  error?: string;
}

interface DeliveryRecordItem {
  messageId: string;
  sourceNode: string;
  sourceDomain: string;
  targetNode: string;
  targetDomain: string;
  state: string;
  createdAt: number;
  updatedAt: number;
  hops: string[];
  ack?: RelayAckItem;
  error?: string;
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

  // Relay State
  const [relaySource, setRelaySource] = useState<string>('saral-foundation-1');
  const [relayTarget, setRelayTarget] = useState<string>('saral-public-2');
  const [relayPayloadText, setRelayPayloadText] = useState<string>('{"message":"Hello cross-domain from Foundation to Public"}');
  const [relaySending, setRelaySending] = useState<boolean>(false);
  const [lastRelayRecord, setLastRelayRecord] = useState<DeliveryRecordItem | null>(null);
  const [relayAuditLog, setRelayAuditLog] = useState<DeliveryRecordItem[]>([]);

  // AVSS & Proactive Cryptosystems State (Cachin et al. CCS 2002)
  const [avssConfig, setAvssConfig] = useState<'A' | 'B' | 'C'>('A');
  const [avssDealer, setAvssDealer] = useState<string>('saral-foundation-1');
  const [activeSessionId, setActiveSessionId] = useState<string>('');
  const [avssSessionData, setAvssSessionData] = useState<{
    sessionId: string;
    status: string;
    completedNodes: number;
    totalNodes: number;
    secretCommitment?: string;
    nodes: Record<string, {
      nodeId: string;
      state: string;
      echoCount: number;
      readyCount: number;
      completed: boolean;
      publicShareCommitment?: string;
    }>;
  } | null>(null);
  const [avssStarting, setAvssStarting] = useState<boolean>(false);
  const [avssStatusLoading, setAvssStatusLoading] = useState<boolean>(false);
  const [proactiveEpoch, setProactiveEpoch] = useState<number>(1);
  const [proactiveState, setProactiveState] = useState<string>('ACTIVE');
  const [proactiveRefreshing, setProactiveRefreshing] = useState<boolean>(false);
  const [cryptoNotice, setCryptoNotice] = useState<string>('');

  // DKG State (Kate et al. 2012 / Cachin et al. 2002)
  const [dkgConfig, setDkgConfig] = useState<'GLOBAL' | 'DOMAIN'>('GLOBAL');
  const [dkgSessionData, setDkgSessionData] = useState<{
    sessionId: string;
    committeeId: string;
    epoch: number;
    n: number;
    k: number;
    t: number;
    state: string;
    committee: string[];
    qualifiedSet?: string[];
    masterPublicKey?: string;
    completedNodes: number;
    totalNodes: number;
    participants: Record<string, {
      nodeId: string;
      nodeIndex: number;
      contributionDealt: boolean;
      inQualifiedSet: boolean;
      status: string;
    }>;
  } | null>(null);
  const [dkgStarting, setDkgStarting] = useState<boolean>(false);
  const [dkgStatusLoading, setDkgStatusLoading] = useState<boolean>(false);

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

  // Dispatch Authenticated Relay Message
  const handleSendRelay = async () => {
    setRelaySending(true);
    addEvent('INFO', `Dispatching relay message: ${relaySource} -> ${relayTarget}...`);
    try {
      let token = '';
      try {
        const tokenRes = await fetch(`${authUrl}/auth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ subject: 'dashboard-relay-operator', role: 'operator' }),
        });
        if (tokenRes.ok) {
          const tData = await tokenRes.json();
          token = tData.token;
        }
      } catch {}

      let parsedPayload: Record<string, unknown> = { message: 'Hello SARAL Relay' };
      try {
        parsedPayload = JSON.parse(relayPayloadText);
      } catch {
        parsedPayload = { text: relayPayloadText };
      }

      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const rpcRes = await fetch(`${coordUrl}/rpc`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method: 'saral_sendRelayMessage',
          params: {
            sourceNode: relaySource,
            targetNode: relayTarget,
            type: 'RELAY_MESSAGE',
            payload: parsedPayload,
            timeoutMs: 10000,
          },
        }),
      });

      const json = await rpcRes.json();
      if (json.error) {
        throw new Error(json.error.message);
      }

      setLastRelayRecord(json.result);
      setRelayAuditLog((prev) => [json.result, ...prev.slice(0, 49)]);

      const state = json.result.state;
      const isOk = state === 'ACKNOWLEDGED' || state === 'DELIVERED';
      addEvent(
        isOk ? 'INFO' : 'ERROR',
        `Relay ${json.result.messageId} [${state}]: ${relaySource} -> ${relayTarget} (${json.result.ack?.latencyMs ?? 0}ms latency)`
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      addEvent('ERROR', `Relay failed: ${msg}`);
    } finally {
      setRelaySending(false);
    }
  };

  // Start AVSS Session
  const handleStartAVSSSession = async () => {
    setAvssStarting(true);
    setCryptoNotice('');
    try {
      let n = 15;
      let k = 5;
      let t = 4;
      if (avssConfig === 'B') {
        n = 5;
        k = 2;
        t = 1;
      } else if (avssConfig === 'C') {
        n = 5;
        k = 3;
        t = 1;
      }

      addEvent('INFO', `Starting AVSS session (Config ${avssConfig}: n=${n}, k=${k}, t=${t}, dealer=${avssDealer})...`);

      let token = '';
      try {
        const tokenRes = await fetch(`${authUrl}/auth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ subject: 'dashboard-crypto-admin', role: 'admin' }),
        });
        if (tokenRes.ok) {
          const tData = await tokenRes.json();
          token = tData.token;
        }
      } catch {}

      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const sessId = `avss-${Date.now()}`;
      const rpcRes = await fetch(`${coordUrl}/rpc`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method: 'saral_createAVSSSession',
          params: {
            sessionId: sessId,
            committeeId: `saral-committee-${n}`,
            dealerId: avssDealer,
            n,
            k,
            t,
          },
        }),
      });

      const json = await rpcRes.json();
      if (json.error) {
        throw new Error(json.error.message);
      }

      setActiveSessionId(json.result.sessionId);
      addEvent('INFO', `AVSS session ${json.result.sessionId} initialized. Dealer broadcasting bivariate polynomials & Pedersen commitments.`);
      setCryptoNotice(`Session ${json.result.sessionId} initiated successfully. Dealer commitment: ${json.result.secretCommitment ? json.result.secretCommitment.substring(0, 16) + '...' : 'pending'}`);
      // Initial poll after short delay
      setTimeout(() => handlePollAVSSSession(json.result.sessionId), 1000);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      addEvent('ERROR', `AVSS session creation failed: ${msg}`);
      setCryptoNotice(`Error: ${msg}`);
    } finally {
      setAvssStarting(false);
    }
  };

  // Poll AVSS Session Status
  const handlePollAVSSSession = async (sessId?: string) => {
    const sId = sessId || activeSessionId;
    if (!sId) return;
    setAvssStatusLoading(true);
    try {
      const rpcRes = await fetch(`${coordUrl}/rpc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method: 'saral_getAVSSSessionStatus',
          params: { sessionId: sId },
        }),
      });
      const json = await rpcRes.json();
      if (json.error) throw new Error(json.error.message);
      setAvssSessionData(json.result);
      if (json.result.status === 'SHARING_COMPLETED') {
        addEvent('INFO', `AVSS session ${sId} completed across committee! Valid shares persistently vaulted.`);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      addEvent('ERROR', `Failed to poll AVSS status: ${msg}`);
    } finally {
      setAvssStatusLoading(false);
    }
  };

  // Trigger Proactive Refresh
  const handleTriggerRefresh = async () => {
    if (avssConfig === 'C') {
      setCryptoNotice('Proactive Refresh Rejected: Configuration C (k=3, t=1) does not satisfy Cachin et al. requirement k=t+1.');
      addEvent('ERROR', 'Proactive refresh rejected: Cachin et al. requires ordinary sharing k = t + 1.');
      return;
    }

    setProactiveRefreshing(true);
    setCryptoNotice('');
    try {
      let n = 15;
      let k = 5;
      let t = 4;
      if (avssConfig === 'B') {
        n = 5;
        k = 2;
        t = 1;
      }

      addEvent('INFO', `Triggering Asynchronous Proactive Share Refresh (Config ${avssConfig}: n=${n}, k=${k}, t=${t})...`);

      let token = '';
      try {
        const tokenRes = await fetch(`${authUrl}/auth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ subject: 'dashboard-crypto-admin', role: 'admin' }),
        });
        if (tokenRes.ok) {
          const tData = await tokenRes.json();
          token = tData.token;
        }
      } catch {}

      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const rpcRes = await fetch(`${coordUrl}/rpc`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method: 'saral_requestProactiveRefresh',
          params: {
            committeeId: `saral-committee-${n}`,
            k,
            t,
          },
        }),
      });

      const json = await rpcRes.json();
      if (json.error) {
        throw new Error(json.error.message);
      }

      setProactiveEpoch((prev) => prev + 1);
      setProactiveState('TRANSITIONING');
      addEvent('INFO', `Proactive refresh dispatched to ${json.result.dispatchedNodes} nodes. Subprotocol AVSS & Validated Byzantine Agreement underway.`);
      setCryptoNotice(`Proactive refresh initiated across committee. Previous epoch shares will be cryptographically erased upon completion.`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      addEvent('ERROR', `Proactive refresh failed: ${msg}`);
      setCryptoNotice(`Error: ${msg}`);
    } finally {
      setProactiveRefreshing(false);
    }
  };

  // Start Dealerless DKG
  const handleStartDKG = async () => {
    setDkgStarting(true);
    try {
      const isGlobal = dkgConfig === 'GLOBAL';
      const n = isGlobal ? 15 : 5;
      const k = isGlobal ? 5 : 2;
      const t = isGlobal ? 4 : 1;
      const committeeId = isGlobal ? 'saral-global-15' : 'saral-foundation-5';

      addEvent('INFO', `Initiating Dealerless DKG (${dkgConfig}: n=${n}, k=${k}, t=${t})...`);

      const resp = await fetch(`${coordUrl}/rpc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method: 'saral_startDkg',
          params: { n, k, t, committeeId },
        }),
      });

      const json = await resp.json();
      if (json.error) {
        throw new Error(json.error.message);
      }

      setCryptoNotice(`Dealerless DKG session ${json.result.sessionId} initiated. Honest contributors independently generating polynomial shares.`);
      addEvent('INFO', `DKG ${json.result.sessionId} started across ${n} nodes. AVSS sharing and Qualified Set agreement underway.`);
      setTimeout(() => handlePollDKGStatus(json.result.sessionId), 1000);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setCryptoNotice(`DKG failed to start: ${msg}`);
      addEvent('ERROR', `DKG failed: ${msg}`);
    } finally {
      setDkgStarting(false);
    }
  };

  // Poll DKG Status
  const handlePollDKGStatus = async (sessId?: string) => {
    setDkgStatusLoading(true);
    try {
      const resp = await fetch(`${coordUrl}/rpc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method: 'saral_getDkgStatus',
          params: sessId ? { sessionId: sessId } : {},
        }),
      });

      const json = await resp.json();
      if (json.error) {
        throw new Error(json.error.message);
      }

      setDkgSessionData(json.result);
      if (json.result.state === 'COMPLETED') {
        addEvent('INFO', `DKG Session ${json.result.sessionId} COMPLETED! Master Public Key: ${json.result.masterPublicKey?.substring(0, 16)}...`);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      addEvent('ERROR', `Failed to poll DKG status: ${msg}`);
    } finally {
      setDkgStatusLoading(false);
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

        {/* ─── DEVELOPER-ONLY RELAY TESTING INTERFACE ─────────────────────────── */}
        <div style={{ marginTop: '20px', backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div>
              <h2 style={{ fontSize: '16px', fontWeight: 700, margin: 0, color: '#f3f4f6' }}>
                ⚡ Authenticated Bidirectional Relay Testing Interface
              </h2>
              <p style={{ color: '#94a3b8', fontSize: '12px', margin: '4px 0 0 0' }}>
                Dispatches cross-domain cryptographically signed messages and validates recipient Ed25519 ACKs
              </p>
            </div>
            {lastRelayRecord && (
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '4px 10px',
                  borderRadius: '9999px',
                  backgroundColor:
                    lastRelayRecord.state === 'ACKNOWLEDGED' || lastRelayRecord.state === 'DELIVERED'
                      ? 'rgba(16, 185, 129, 0.2)'
                      : 'rgba(239, 68, 68, 0.2)',
                  color:
                    lastRelayRecord.state === 'ACKNOWLEDGED' || lastRelayRecord.state === 'DELIVERED'
                      ? '#34d399'
                      : '#f87171',
                  border: `1px solid ${
                    lastRelayRecord.state === 'ACKNOWLEDGED' || lastRelayRecord.state === 'DELIVERED'
                      ? '#10b981'
                      : '#ef4444'
                  }`,
                }}
              >
                ● {lastRelayRecord.state}
              </span>
            )}
          </div>

          {/* Controls */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 2fr auto', gap: '12px', alignItems: 'flex-end', marginBottom: '16px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px', fontWeight: 500 }}>
                Source Node
              </label>
              <select
                value={relaySource}
                onChange={(e) => setRelaySource(e.target.value)}
                style={{
                  width: '100%',
                  backgroundColor: '#182234',
                  border: '1px solid #334155',
                  color: '#f8fafc',
                  padding: '8px 10px',
                  borderRadius: '6px',
                  fontSize: '12px',
                }}
              >
                <optgroup label="Foundation Domain">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <option key={`f-${i}`} value={`saral-foundation-${i}`}>saral-foundation-{i}</option>
                  ))}
                </optgroup>
                <optgroup label="Public Domain">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <option key={`p-${i}`} value={`saral-public-${i}`}>saral-public-{i}</option>
                  ))}
                </optgroup>
                <optgroup label="Private Domain">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <option key={`r-${i}`} value={`saral-private-${i}`}>saral-private-{i}</option>
                  ))}
                </optgroup>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px', fontWeight: 500 }}>
                Target Destination Node
              </label>
              <select
                value={relayTarget}
                onChange={(e) => setRelayTarget(e.target.value)}
                style={{
                  width: '100%',
                  backgroundColor: '#182234',
                  border: '1px solid #334155',
                  color: '#f8fafc',
                  padding: '8px 10px',
                  borderRadius: '6px',
                  fontSize: '12px',
                }}
              >
                <optgroup label="Public Domain">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <option key={`p-${i}`} value={`saral-public-${i}`}>saral-public-{i}</option>
                  ))}
                </optgroup>
                <optgroup label="Private Domain">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <option key={`r-${i}`} value={`saral-private-${i}`}>saral-private-{i}</option>
                  ))}
                </optgroup>
                <optgroup label="Foundation Domain">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <option key={`f-${i}`} value={`saral-foundation-${i}`}>saral-foundation-{i}</option>
                  ))}
                </optgroup>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px', fontWeight: 500 }}>
                Message Payload (JSON)
              </label>
              <input
                type="text"
                value={relayPayloadText}
                onChange={(e) => setRelayPayloadText(e.target.value)}
                style={{
                  width: '100%',
                  backgroundColor: '#182234',
                  border: '1px solid #334155',
                  color: '#f8fafc',
                  padding: '8px 10px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontFamily: 'monospace',
                }}
              />
            </div>

            <div>
              <button
                onClick={handleSendRelay}
                disabled={relaySending}
                style={{
                  backgroundColor: '#6366f1',
                  color: '#ffffff',
                  border: 'none',
                  padding: '8px 16px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: relaySending ? 'not-allowed' : 'pointer',
                  opacity: relaySending ? 0.6 : 1,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  height: '34px',
                }}
              >
                {relaySending ? 'Relaying...' : '🚀 Dispatch Message'}
              </button>
            </div>
          </div>

          {/* Active Delivery Result Details */}
          {lastRelayRecord && (
            <div style={{ backgroundColor: '#182234', borderRadius: '6px', padding: '12px 14px', marginBottom: '16px', border: '1px solid #2d3748' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontSize: '12px', color: '#94a3b8' }}>
                  Message ID: <strong style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{lastRelayRecord.messageId}</strong>
                </span>
                <span style={{ fontSize: '12px', color: '#94a3b8' }}>
                  Round-trip Latency: <strong style={{ color: '#fbbf24' }}>{lastRelayRecord.ack?.latencyMs ?? 0} ms</strong>
                </span>
              </div>

              {/* Hops Flow */}
              <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '6px' }}>
                Verified Routing Hops:
                <div style={{ display: 'flex', gap: '6px', marginTop: '4px', flexWrap: 'wrap' }}>
                  {lastRelayRecord.hops?.map((hop, idx) => (
                    <span key={idx} style={{ backgroundColor: '#0f172a', padding: '2px 8px', borderRadius: '4px', fontFamily: 'monospace', color: '#cbd5e1' }}>
                      {idx > 0 && '➔ '}
                      {hop}
                    </span>
                  ))}
                </div>
              </div>

              {/* Recipient ACK Evidence */}
              {lastRelayRecord.ack?.recipientSigHex && (
                <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '6px', fontFamily: 'monospace' }}>
                  Recipient Signature (Ed25519 Verified):{' '}
                  <span style={{ color: '#34d399' }}>{lastRelayRecord.ack.recipientSigHex.substring(0, 32)}...</span>
                </div>
              )}

              {lastRelayRecord.error && (
                <div style={{ color: '#f87171', fontSize: '11px', marginTop: '6px', fontWeight: 600 }}>
                  Error: {lastRelayRecord.error}
                </div>
              )}
            </div>
          )}

          {/* Recent Relay Deliveries Table */}
          {relayAuditLog.length > 0 && (
            <div>
              <h4 style={{ fontSize: '13px', fontWeight: 600, margin: '0 0 8px 0', color: '#cbd5e1' }}>
                Recent Relay Message Ledger
              </h4>
              <div style={{ maxHeight: '180px', overflowY: 'auto' }}>
                <table style={{ width: '100%', fontSize: '11px', borderCollapse: 'collapse', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ color: '#9ca3af', borderBottom: '1px solid #1f2937' }}>
                      <th style={{ padding: '6px 8px' }}>Msg ID</th>
                      <th style={{ padding: '6px 8px' }}>Source</th>
                      <th style={{ padding: '6px 8px' }}>Target</th>
                      <th style={{ padding: '6px 8px' }}>State</th>
                      <th style={{ padding: '6px 8px' }}>Latency</th>
                      <th style={{ padding: '6px 8px' }}>Hops</th>
                    </tr>
                  </thead>
                  <tbody>
                    {relayAuditLog.map((rec, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid #1e293b' }}>
                        <td style={{ padding: '6px 8px', fontFamily: 'monospace', color: '#38bdf8' }}>{rec.messageId}</td>
                        <td style={{ padding: '6px 8px' }}>{rec.sourceNode}</td>
                        <td style={{ padding: '6px 8px' }}>{rec.targetNode}</td>
                        <td style={{ padding: '6px 8px' }}>
                          <span
                            style={{
                              color: rec.state === 'ACKNOWLEDGED' || rec.state === 'DELIVERED' ? '#34d399' : '#f87171',
                              fontWeight: 600,
                            }}
                          >
                            {rec.state}
                          </span>
                        </td>
                        <td style={{ padding: '6px 8px', color: '#fbbf24' }}>{rec.ack?.latencyMs ?? 0} ms</td>
                        <td style={{ padding: '6px 8px', fontFamily: 'monospace', color: '#64748b' }}>
                          {rec.hops?.join(' ➔ ') || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* ─── DEALERLESS DISTRIBUTED KEY GENERATION (DKG) (Kate et al. 2012 / Cachin et al. 2002) ─────────── */}
        <div style={{ marginTop: '24px', backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid #1f2937', paddingBottom: '14px' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '18px' }}>🔑</span>
                <h2 style={{ fontSize: '17px', fontWeight: 700, margin: 0, color: '#f3f4f6' }}>
                  Dealerless Distributed Key Generation (DKG)
                </h2>
              </div>
              <p style={{ color: '#94a3b8', fontSize: '12px', margin: '4px 0 0 26px' }}>
                Kate, Huang, Goldberg (ASIACCS 2012 / ePrint 2012/377) — Asynchronous AVSS-Backed DKG & Common Coin Agreement
              </p>
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '4px 10px',
                  borderRadius: '9999px',
                  backgroundColor: dkgSessionData?.state === 'COMPLETED' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(56, 189, 248, 0.2)',
                  color: dkgSessionData?.state === 'COMPLETED' ? '#34d399' : '#38bdf8',
                  border: `1px solid ${dkgSessionData?.state === 'COMPLETED' ? '#10b981' : '#0284c7'}`,
                }}
              >
                ● {dkgSessionData?.state || 'READY'}
              </span>
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '4px 10px',
                  borderRadius: '9999px',
                  backgroundColor: 'rgba(99, 102, 241, 0.2)',
                  color: '#818cf8',
                  border: '1px solid #6366f1',
                }}
              >
                Epoch τ=1 (Initial DKG)
              </span>
            </div>
          </div>

          {/* Committee Configuration Selector */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
            <div
              onClick={() => setDkgConfig('GLOBAL')}
              style={{
                padding: '12px',
                borderRadius: '6px',
                cursor: 'pointer',
                backgroundColor: dkgConfig === 'GLOBAL' ? '#1e293b' : '#0f172a',
                border: `2px solid ${dkgConfig === 'GLOBAL' ? '#38bdf8' : '#1e293b'}`,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <strong style={{ fontSize: '13px', color: '#f8fafc' }}>Global Committee (15 Nodes)</strong>
                <span style={{ fontSize: '11px', color: '#38bdf8', fontWeight: 600 }}>n=15, t=4, k=5</span>
              </div>
              <p style={{ margin: '6px 0 0 0', fontSize: '11px', color: '#94a3b8' }}>
                Full cross-domain committee. Fault tolerance: t=4. Qualified set: |QUAL*| ≥ 11 nodes.
              </p>
            </div>

            <div
              onClick={() => setDkgConfig('DOMAIN')}
              style={{
                padding: '12px',
                borderRadius: '6px',
                cursor: 'pointer',
                backgroundColor: dkgConfig === 'DOMAIN' ? '#1e293b' : '#0f172a',
                border: `2px solid ${dkgConfig === 'DOMAIN' ? '#38bdf8' : '#1e293b'}`,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <strong style={{ fontSize: '13px', color: '#f8fafc' }}>Domain Committee (5 Nodes)</strong>
                <span style={{ fontSize: '11px', color: '#38bdf8', fontWeight: 600 }}>n=5, t=1, k=2</span>
              </div>
              <p style={{ margin: '6px 0 0 0', fontSize: '11px', color: '#94a3b8' }}>
                Single domain committee. Fault tolerance: t=1. Qualified set: |QUAL*| ≥ 4 nodes.
              </p>
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
            <button
              onClick={handleStartDKG}
              disabled={dkgStarting}
              style={{
                flex: 1,
                padding: '10px 16px',
                backgroundColor: '#2563eb',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                fontWeight: 600,
                fontSize: '13px',
                cursor: dkgStarting ? 'not-allowed' : 'pointer',
                opacity: dkgStarting ? 0.6 : 1,
              }}
            >
              {dkgStarting ? 'Initiating Distributed Contributions...' : '🚀 Start Dealerless DKG'}
            </button>
            <button
              onClick={() => handlePollDKGStatus(dkgSessionData?.sessionId)}
              disabled={dkgStatusLoading || !dkgSessionData?.sessionId}
              style={{
                padding: '10px 18px',
                backgroundColor: '#1e293b',
                color: '#e2e8f0',
                border: '1px solid #334155',
                borderRadius: '6px',
                fontWeight: 600,
                fontSize: '13px',
                cursor: dkgStatusLoading || !dkgSessionData?.sessionId ? 'not-allowed' : 'pointer',
              }}
            >
              {dkgStatusLoading ? 'Checking...' : '🔄 Poll DKG Status'}
            </button>
          </div>

          {/* DKG Session Progress & Output */}
          {dkgSessionData && (
            <div style={{ backgroundColor: '#182234', borderRadius: '6px', padding: '14px', marginBottom: '16px', border: '1px solid #2d3748' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <div>
                  <span style={{ fontSize: '12px', color: '#94a3b8' }}>Session: </span>
                  <strong style={{ color: '#38bdf8', fontFamily: 'monospace', fontSize: '12px' }}>{dkgSessionData.sessionId}</strong>
                  <span style={{ marginLeft: '12px', fontSize: '11px', color: '#94a3b8' }}>
                    Committee: <span style={{ color: '#cbd5e1' }}>{dkgSessionData.committeeId}</span>
                  </span>
                </div>
                <div style={{ fontSize: '12px', color: '#94a3b8' }}>
                  Progress: <strong style={{ color: '#34d399' }}>{dkgSessionData.completedNodes} / {dkgSessionData.totalNodes} Nodes Completed</strong>
                </div>
              </div>

              {/* Progress Bar */}
              <div style={{ height: '8px', backgroundColor: '#0f172a', borderRadius: '4px', overflow: 'hidden', marginBottom: '12px' }}>
                <div
                  style={{
                    height: '100%',
                    width: `${(dkgSessionData.completedNodes / Math.max(dkgSessionData.totalNodes, 1)) * 100}%`,
                    backgroundColor: dkgSessionData.state === 'COMPLETED' ? '#10b981' : '#38bdf8',
                    transition: 'width 0.3s ease',
                  }}
                />
              </div>

              {/* Master Public Key Y */}
              {dkgSessionData.masterPublicKey && (
                <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '12px', fontFamily: 'monospace' }}>
                  <span style={{ color: '#34d399', fontWeight: 600 }}>Agreed Master Public Key Y = ∑ C⁽ⁱ⁾₀,₀ (NIST P-256):</span>
                  <div style={{ color: '#a78bfa', wordBreak: 'break-all', backgroundColor: '#0f172a', padding: '8px 10px', borderRadius: '4px', marginTop: '4px', border: '1px solid #10b981' }}>
                    {dkgSessionData.masterPublicKey}
                  </div>
                </div>
              )}

              {/* Qualified Set QUAL* */}
              {dkgSessionData.qualifiedSet && dkgSessionData.qualifiedSet.length > 0 && (
                <div style={{ marginBottom: '12px' }}>
                  <span style={{ fontSize: '11px', color: '#94a3b8' }}>Agreed Qualified Set (QUAL*): </span>
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '4px' }}>
                    {dkgSessionData.qualifiedSet.map((nodeId) => (
                      <span
                        key={nodeId}
                        style={{
                          fontSize: '10px',
                          fontFamily: 'monospace',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          backgroundColor: 'rgba(16, 185, 129, 0.15)',
                          color: '#34d399',
                          border: '1px solid #059669',
                        }}
                      >
                        {nodeId}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Participants Table */}
              <h4 style={{ fontSize: '12px', fontWeight: 600, margin: '12px 0 6px 0', color: '#cbd5e1' }}>
                Committee Participant Status
              </h4>
              <div style={{ maxHeight: '180px', overflowY: 'auto' }}>
                <table style={{ width: '100%', fontSize: '11px', borderCollapse: 'collapse', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ color: '#9ca3af', borderBottom: '1px solid #1f2937' }}>
                      <th style={{ padding: '4px 8px' }}>Node ID</th>
                      <th style={{ padding: '4px 8px' }}>Index</th>
                      <th style={{ padding: '4px 8px' }}>Contribution Dealt</th>
                      <th style={{ padding: '4px 8px' }}>In QUAL*</th>
                      <th style={{ padding: '4px 8px' }}>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.values(dkgSessionData.participants || {}).map((p) => (
                      <tr key={p.nodeId} style={{ borderBottom: '1px solid #1e293b' }}>
                        <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#f8fafc' }}>{p.nodeId}</td>
                        <td style={{ padding: '4px 8px', color: '#94a3b8' }}>#{p.nodeIndex}</td>
                        <td style={{ padding: '4px 8px' }}>
                          <span style={{ color: p.contributionDealt ? '#34d399' : '#f87171' }}>
                            {p.contributionDealt ? '✓ Dealt' : '✗ Pending'}
                          </span>
                        </td>
                        <td style={{ padding: '4px 8px' }}>
                          <span style={{ color: p.inQualifiedSet ? '#34d399' : '#64748b' }}>
                            {p.inQualifiedSet ? '✓ QUAL*' : '—'}
                          </span>
                        </td>
                        <td style={{ padding: '4px 8px' }}>
                          <span style={{ color: p.status === 'COMPLETED' ? '#34d399' : '#38bdf8', fontWeight: 600 }}>
                            {p.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Zero-Knowledge Guarantee Notice */}
          <div style={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '6px', padding: '12px', fontSize: '11px', color: '#94a3b8' }}>
            🛡️ <strong style={{ color: '#e2e8f0' }}>Dealerless Security Guarantee:</strong> No single entity or coordinator acts as a trusted dealer. Master secret shares xⱼ = ∑ᵢ sᵢ,ⱼ are computed strictly within each node's local process space, and the master private key is never centralized or reconstructed.
          </div>
        </div>

        {/* ─── AVSS & PROACTIVE CRYPTOSYSTEMS INTERFACE (Cachin et al. CCS 2002) ─────────── */}
        <div style={{ marginTop: '24px', backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid #1f2937', paddingBottom: '14px' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '18px' }}>🛡️</span>
                <h2 style={{ fontSize: '17px', fontWeight: 700, margin: 0, color: '#f3f4f6' }}>
                  Asynchronous Verifiable Secret Sharing (AVSS) & Proactive Refresh
                </h2>
              </div>
              <p style={{ color: '#94a3b8', fontSize: '12px', margin: '4px 0 0 26px' }}>
                Cachin, Kursawe, Lysyanskaya, Strobl (ACM CCS 2002) — Dual-Threshold Bivariate Polynomials & Multi-Valued Agreement
              </p>
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '4px 10px',
                  borderRadius: '9999px',
                  backgroundColor: avssSessionData?.status === 'SHARING_COMPLETED' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(56, 189, 248, 0.2)',
                  color: avssSessionData?.status === 'SHARING_COMPLETED' ? '#34d399' : '#38bdf8',
                  border: `1px solid ${avssSessionData?.status === 'SHARING_COMPLETED' ? '#10b981' : '#0284c7'}`,
                }}
              >
                ● {avssSessionData?.status || 'READY'}
              </span>
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '4px 10px',
                  borderRadius: '9999px',
                  backgroundColor: 'rgba(167, 139, 250, 0.2)',
                  color: '#c084fc',
                  border: '1px solid #a855f7',
                }}
              >
                Epoch τ={proactiveEpoch} ({proactiveState})
              </span>
            </div>
          </div>

          {/* Configuration Selector */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '18px' }}>
            <div
              onClick={() => setAvssConfig('A')}
              style={{
                backgroundColor: avssConfig === 'A' ? '#1e293b' : '#0f172a',
                border: `2px solid ${avssConfig === 'A' ? '#38bdf8' : '#1e293b'}`,
                borderRadius: '6px',
                padding: '12px',
                cursor: 'pointer',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, color: '#f8fafc', fontSize: '13px' }}>Configuration A</span>
                <span style={{ fontSize: '10px', backgroundColor: '#0369a1', color: '#e0f2fe', padding: '2px 6px', borderRadius: '4px', fontWeight: 600 }}>
                  15-Node POC
                </span>
              </div>
              <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '6px' }}>
                n = 15, k = 5, t = 4
              </div>
              <div style={{ fontSize: '10px', color: '#34d399', marginTop: '4px' }}>
                ✓ AVSS Dual-Threshold (15 - 8 ≥ 5)<br />
                ✓ Proactive Refresh (k = t + 1 = 5)
              </div>
            </div>

            <div
              onClick={() => setAvssConfig('B')}
              style={{
                backgroundColor: avssConfig === 'B' ? '#1e293b' : '#0f172a',
                border: `2px solid ${avssConfig === 'B' ? '#38bdf8' : '#1e293b'}`,
                borderRadius: '6px',
                padding: '12px',
                cursor: 'pointer',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, color: '#f8fafc', fontSize: '13px' }}>Configuration B</span>
                <span style={{ fontSize: '10px', backgroundColor: '#047857', color: '#d1fae5', padding: '2px 6px', borderRadius: '4px', fontWeight: 600 }}>
                  5-Node Domain
                </span>
              </div>
              <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '6px' }}>
                n = 5, k = 2, t = 1
              </div>
              <div style={{ fontSize: '10px', color: '#34d399', marginTop: '4px' }}>
                ✓ AVSS Dual-Threshold (5 - 2 ≥ 2)<br />
                ✓ Proactive Refresh (k = t + 1 = 2)
              </div>
            </div>

            <div
              onClick={() => setAvssConfig('C')}
              style={{
                backgroundColor: avssConfig === 'C' ? '#1e293b' : '#0f172a',
                border: `2px solid ${avssConfig === 'C' ? '#f59e0b' : '#1e293b'}`,
                borderRadius: '6px',
                padding: '12px',
                cursor: 'pointer',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, color: '#f8fafc', fontSize: '13px' }}>Configuration C</span>
                <span style={{ fontSize: '10px', backgroundColor: '#b45309', color: '#fef3c7', padding: '2px 6px', borderRadius: '4px', fontWeight: 600 }}>
                  Dual-Threshold Only
                </span>
              </div>
              <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '6px' }}>
                n = 5, k = 3, t = 1
              </div>
              <div style={{ fontSize: '10px', color: '#f87171', marginTop: '4px' }}>
                ✓ AVSS Dual-Threshold (5 - 2 ≥ 3)<br />
                ✗ Proactive Refresh Blocked (k ≠ t + 1)
              </div>
            </div>
          </div>

          {/* Controls Bar */}
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap' }}>
            <div style={{ minWidth: '180px' }}>
              <label style={{ display: 'block', fontSize: '11px', color: '#94a3b8', marginBottom: '4px', fontWeight: 500 }}>
                Sharing Dealer Node
              </label>
              <select
                value={avssDealer}
                onChange={(e) => setAvssDealer(e.target.value)}
                style={{
                  width: '100%',
                  backgroundColor: '#182234',
                  border: '1px solid #334155',
                  color: '#f8fafc',
                  padding: '7px 10px',
                  borderRadius: '6px',
                  fontSize: '12px',
                }}
              >
                <optgroup label="Foundation Domain">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <option key={`f-d-${i}`} value={`saral-foundation-${i}`}>saral-foundation-{i}</option>
                  ))}
                </optgroup>
                <optgroup label="Public Domain">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <option key={`p-d-${i}`} value={`saral-public-${i}`}>saral-public-{i}</option>
                  ))}
                </optgroup>
                <optgroup label="Private Domain">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <option key={`r-d-${i}`} value={`saral-private-${i}`}>saral-private-{i}</option>
                  ))}
                </optgroup>
              </select>
            </div>

            <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-end', marginTop: '16px' }}>
              <button
                onClick={handleStartAVSSSession}
                disabled={avssStarting}
                style={{
                  backgroundColor: '#0284c7',
                  color: '#ffffff',
                  border: 'none',
                  padding: '8px 16px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: avssStarting ? 'not-allowed' : 'pointer',
                  opacity: avssStarting ? 0.6 : 1,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                {avssStarting ? 'Distributing Shares...' : '🚀 Start AVSS Sharing Session'}
              </button>

              <button
                onClick={() => handlePollAVSSSession()}
                disabled={avssStatusLoading || !activeSessionId}
                style={{
                  backgroundColor: '#334155',
                  color: '#cbd5e1',
                  border: '1px solid #475569',
                  padding: '8px 14px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontWeight: 500,
                  cursor: avssStatusLoading || !activeSessionId ? 'not-allowed' : 'pointer',
                  opacity: !activeSessionId ? 0.5 : 1,
                }}
              >
                {avssStatusLoading ? 'Checking...' : '🔄 Poll Session Progress'}
              </button>

              <button
                onClick={handleTriggerRefresh}
                disabled={proactiveRefreshing || avssConfig === 'C'}
                style={{
                  backgroundColor: avssConfig === 'C' ? '#475569' : '#7c3aed',
                  color: '#ffffff',
                  border: 'none',
                  padding: '8px 16px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: proactiveRefreshing || avssConfig === 'C' ? 'not-allowed' : 'pointer',
                  opacity: avssConfig === 'C' ? 0.5 : proactiveRefreshing ? 0.6 : 1,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
                title={avssConfig === 'C' ? 'Proactive Refresh unsupported in Configuration C (k ≠ t + 1)' : 'Trigger proactive share refresh'}
              >
                {proactiveRefreshing ? 'Refreshing Epoch...' : '⚡ Trigger Proactive Share Refresh'}
              </button>
            </div>
          </div>

          {/* Feedback Notice */}
          {cryptoNotice && (
            <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '10px 14px', marginBottom: '16px', fontSize: '12px', color: '#e2e8f0', fontFamily: 'monospace' }}>
              {cryptoNotice}
            </div>
          )}

          {/* Active Sharing Status & Progress */}
          {avssSessionData && (
            <div style={{ backgroundColor: '#182234', borderRadius: '6px', padding: '14px', marginBottom: '16px', border: '1px solid #2d3748' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <div>
                  <span style={{ fontSize: '12px', color: '#94a3b8' }}>Session: </span>
                  <strong style={{ color: '#38bdf8', fontFamily: 'monospace', fontSize: '12px' }}>{avssSessionData.sessionId}</strong>
                </div>
                <div style={{ fontSize: '12px', color: '#94a3b8' }}>
                  Progress: <strong style={{ color: '#34d399' }}>{avssSessionData.completedNodes} / {avssSessionData.totalNodes} Nodes Completed</strong>
                </div>
              </div>

              {/* Progress Bar */}
              <div style={{ height: '8px', backgroundColor: '#0f172a', borderRadius: '4px', overflow: 'hidden', marginBottom: '12px' }}>
                <div
                  style={{
                    height: '100%',
                    width: `${(avssSessionData.completedNodes / Math.max(avssSessionData.totalNodes, 1)) * 100}%`,
                    backgroundColor: avssSessionData.status === 'SHARING_COMPLETED' ? '#10b981' : '#38bdf8',
                    transition: 'width 0.3s ease',
                  }}
                />
              </div>

              {/* Public Pedersen Secret Commitment */}
              {avssSessionData.secretCommitment && (
                <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '12px', fontFamily: 'monospace' }}>
                  Pedersen Public Secret Commitment C₀,₀ = s·G + s'·H:
                  <div style={{ color: '#a78bfa', wordBreak: 'break-all', backgroundColor: '#0f172a', padding: '6px 8px', borderRadius: '4px', marginTop: '4px' }}>
                    {avssSessionData.secretCommitment}
                  </div>
                </div>
              )}

              {/* Participant Node Verification Table */}
              <h4 style={{ fontSize: '12px', fontWeight: 600, margin: '12px 0 6px 0', color: '#cbd5e1' }}>
                Committee Participant Verification Status
              </h4>
              <div style={{ maxHeight: '180px', overflowY: 'auto' }}>
                <table style={{ width: '100%', fontSize: '11px', borderCollapse: 'collapse', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ color: '#9ca3af', borderBottom: '1px solid #1f2937' }}>
                      <th style={{ padding: '4px 8px' }}>Node ID</th>
                      <th style={{ padding: '4px 8px' }}>State</th>
                      <th style={{ padding: '4px 8px' }}>ECHOs</th>
                      <th style={{ padding: '4px 8px' }}>READYs</th>
                      <th style={{ padding: '4px 8px' }}>Share Commitment C(i,0)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.values(avssSessionData.nodes || {}).map((nd) => (
                      <tr key={nd.nodeId} style={{ borderBottom: '1px solid #1e293b' }}>
                        <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#f8fafc' }}>{nd.nodeId}</td>
                        <td style={{ padding: '4px 8px' }}>
                          <span style={{ color: nd.completed ? '#34d399' : '#38bdf8', fontWeight: 600 }}>
                            {nd.state}
                          </span>
                        </td>
                        <td style={{ padding: '4px 8px', color: '#fbbf24' }}>{nd.echoCount}</td>
                        <td style={{ padding: '4px 8px', color: '#a78bfa' }}>{nd.readyCount}</td>
                        <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#64748b' }}>
                          {nd.publicShareCommitment ? nd.publicShareCommitment.substring(0, 24) + '...' : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Secure Vault & Isolation Notice */}
          <div style={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '6px', padding: '12px', fontSize: '11px', color: '#94a3b8' }}>
            🔒 <strong style={{ color: '#e2e8f0' }}>Cryptographic Vault Isolation:</strong> Private polynomial shares and master secrets are stored strictly within local node AES-256-GCM encrypted vaults (0600 file permissions). Raw private shares are NEVER exposed over RPC, coordinator logs, or the frontend dashboard.
          </div>
        </div>
      </main>
    </div>
  );
};

export default App;
