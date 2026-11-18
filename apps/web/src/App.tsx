import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { OverviewView } from './components/views/OverviewView';
import { NetworkView } from './components/views/NetworkView';
import { DkgSessionsView } from './components/views/DkgSessionsView';
import { KeyManagementView } from './components/views/KeyManagementView';
import { CreateWalletView } from './components/views/CreateWalletView';
import { WalletsView } from './components/views/WalletsView';
import { WalletDetailsView } from './components/views/WalletDetailsView';
import { ProactiveRefreshView } from './components/views/ProactiveRefreshView';
import { AuditLogsView } from './components/views/AuditLogsView';
import { SettingsView } from './components/views/SettingsView';
import { NavigationTab, NetworkData, DKGSessionData, WalletRecord, ProtocolEvent } from './types';
import { apiService } from './services/api';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavigationTab>('overview');
  const [coordUrl, setCoordUrl] = useState<string>('http://localhost:9001');
  const [authUrl] = useState<string>('http://localhost:3001');

  const [networkData, setNetworkData] = useState<NetworkData | null>(null);
  const [dkgSessions, setDkgSessions] = useState<DKGSessionData[]>([]);
  const [wallets, setWallets] = useState<WalletRecord[]>([]);
  const [selectedWallet, setSelectedWallet] = useState<WalletRecord | null>(null);
  const [events, setEvents] = useState<ProtocolEvent[]>([]);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

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

  // Fetch initial operator JWT token
  useEffect(() => {
    apiService.setCoordinatorUrl(coordUrl);
    apiService
      .authenticate('dev-operator', 'admin')
      .then(() => {
        addEvent('AUTH', 'Authenticated with Auth Server (RS256 JWT obtained)');
      })
      .catch((err) => {
        addEvent('INFO', `Auth server notice: ${err.message}`);
      });
  }, [coordUrl, addEvent]);

  // Load live data from coordinator
  const refreshAll = useCallback(async () => {
    setIsRefreshing(true);
    try {
      // 1. Network Status
      try {
        const net = await apiService.getNetworkStatus();
        setNetworkData(net);
      } catch (err) {
        // Fallback default topology if coordinator is unreachable during test
      }

      // 2. DKG Status
      try {
        const dkg = await apiService.getDkgStatus();
        if (dkg && dkg.sessionId) {
          setDkgSessions((prev) => {
            const map = new Map<string, DKGSessionData>();
            prev.forEach((s) => map.set(s.sessionId, s));
            map.set(dkg.sessionId, dkg);
            return Array.from(map.values());
          });
        }
      } catch (err) {
        // No active DKG session
      }

      // 3. Wallets
      try {
        const wList = await apiService.getWallets();
        if (Array.isArray(wList)) {
          setWallets(wList);
        }
      } catch (err) {
        // No wallets
      }
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  // Poll live status every 5 seconds
  useEffect(() => {
    refreshAll();
    const interval = setInterval(refreshAll, 5000);
    return () => clearInterval(interval);
  }, [refreshAll]);

  // Handle DKG initiation
  const handleDkgStarted = (sessionId: string) => {
    addEvent('DKG', `DKG session ${sessionId} started across committee nodes.`);
    refreshAll();
  };

  // Handle Wallet creation
  const handleWalletCreated = (wallet: WalletRecord) => {
    addEvent('WALLET', `Created ${wallet.blockchain.toUpperCase()} wallet: ${wallet.address.substring(0, 16)}...`);
    setWallets((prev) => [wallet, ...prev]);
    setSelectedWallet(wallet);
  };

  const handleSelectWallet = (wallet: WalletRecord) => {
    setSelectedWallet(wallet);
    setActiveTab('wallet-details');
  };

  return (
    <div style={{
      display: 'flex',
      backgroundColor: '#090d16',
      color: '#f8fafc',
      minHeight: '100vh',
      fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
    }}>
      {/* Main Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        walletCount={wallets.length}
        dkgSessionCount={dkgSessions.length}
      />

      {/* Main Content Area */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {/* Top Header */}
        <Header
          totalNodes={networkData?.totalNodes ?? 15}
          onlineNodes={networkData?.onlineNodes ?? 15}
          onRefresh={refreshAll}
          isRefreshing={isRefreshing}
        />

        {/* Dynamic Page Views */}
        <main style={{ flex: 1, padding: '28px 32px', overflowY: 'auto' }}>
          {activeTab === 'overview' && (
            <OverviewView
              networkData={networkData}
              dkgSessions={dkgSessions}
              wallets={wallets}
              events={events}
              onNavigate={setActiveTab}
              onRefresh={refreshAll}
            />
          )}

          {activeTab === 'network' && (
            <NetworkView
              networkData={networkData}
              onRefresh={refreshAll}
            />
          )}

          {activeTab === 'dkg-sessions' && (
            <DkgSessionsView
              dkgSessions={dkgSessions}
              onDkgStarted={handleDkgStarted}
              onNavigate={setActiveTab}
              onRefresh={refreshAll}
            />
          )}

          {activeTab === 'key-management' && (
            <KeyManagementView
              dkgSessions={dkgSessions}
              onNavigate={setActiveTab}
            />
          )}

          {activeTab === 'create-wallet' && (
            <CreateWalletView
              dkgSessions={dkgSessions}
              onWalletCreated={handleWalletCreated}
              onNavigate={setActiveTab}
            />
          )}

          {activeTab === 'wallets' && (
            <WalletsView
              wallets={wallets}
              onSelectWallet={handleSelectWallet}
              onNavigate={setActiveTab}
              onRefresh={refreshAll}
            />
          )}

          {activeTab === 'wallet-details' && (
            <WalletDetailsView
              wallet={selectedWallet}
              onBack={() => setActiveTab('wallets')}
              onNavigate={setActiveTab}
            />
          )}

          {activeTab === 'proactive-refresh' && (
            <ProactiveRefreshView />
          )}

          {activeTab === 'audit-logs' && (
            <AuditLogsView
              events={events}
              onClear={() => setEvents([])}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsView
              coordUrl={coordUrl}
              authUrl={authUrl}
              onUpdateCoordUrl={setCoordUrl}
            />
          )}
        </main>
      </div>
    </div>
  );
};

export default App;
