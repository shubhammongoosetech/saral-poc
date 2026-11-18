import React, { useState } from 'react';
import { WalletRecord, NavigationTab } from '../../types';

interface WalletsViewProps {
  wallets: WalletRecord[];
  onSelectWallet: (wallet: WalletRecord) => void;
  onNavigate: (tab: NavigationTab) => void;
  onRefresh: () => void;
}

export const WalletsView: React.FC<WalletsViewProps> = ({
  wallets,
  onSelectWallet,
  onNavigate,
  onRefresh,
}) => {
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [filterChain, setFilterChain] = useState<string>('ALL');
  const [copiedId, setCopiedId] = useState<string>('');

  const copyAddress = (id: string, addr: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(addr);
    setCopiedId(id);
    setTimeout(() => setCopiedId(''), 2000);
  };

  const filteredWallets = wallets.filter((w) => {
    const matchesSearch =
      w.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      w.address.toLowerCase().includes(searchTerm.toLowerCase()) ||
      w.walletId.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesChain = filterChain === 'ALL' || w.blockchain.toLowerCase() === filterChain.toLowerCase();

    return matchesSearch && matchesChain;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header and Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 700, margin: '0 0 4px 0', color: '#f8fafc' }}>
            My Web3 Threshold Wallets
          </h2>
          <p style={{ margin: 0, fontSize: '13px', color: '#94a3b8' }}>
            Managed accounts backed by SARAL V3 distributed key shares.
          </p>
        </div>
        <button
          onClick={() => onNavigate('create-wallet')}
          style={{
            padding: '10px 18px',
            backgroundColor: '#2563eb',
            color: '#ffffff',
            border: 'none',
            borderRadius: '6px',
            fontWeight: 600,
            fontSize: '13px',
            cursor: 'pointer',
          }}
        >
          + Create New Wallet
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div style={{
        display: 'flex',
        gap: '12px',
        alignItems: 'center',
        padding: '12px 16px',
        backgroundColor: '#111827',
        border: '1px solid #1f2937',
        borderRadius: '8px',
      }}>
        <div style={{ flex: 1, position: 'relative' }}>
          <input
            type="text"
            placeholder="Search by wallet name, address or ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: '100%',
              padding: '8px 12px',
              backgroundColor: '#0c121e',
              border: '1px solid #334155',
              borderRadius: '6px',
              color: '#f8fafc',
              fontSize: '13px',
            }}
          />
        </div>

        <select
          value={filterChain}
          onChange={(e) => setFilterChain(e.target.value)}
          style={{
            padding: '8px 14px',
            backgroundColor: '#0c121e',
            border: '1px solid #334155',
            borderRadius: '6px',
            color: '#cbd5e1',
            fontSize: '13px',
          }}
        >
          <option value="ALL">All Blockchains</option>
          <option value="passkey-p256">WebAuthn / Passkey</option>
          <option value="ethereum">Ethereum (EVM)</option>
          <option value="bitcoin">Bitcoin Taproot</option>
          <option value="solana">Solana</option>
        </select>

        <button
          onClick={onRefresh}
          style={{
            padding: '8px 14px',
            backgroundColor: '#1e293b',
            color: '#94a3b8',
            border: '1px solid #334155',
            borderRadius: '6px',
            fontSize: '13px',
            cursor: 'pointer',
          }}
        >
          🔄 Refresh
        </button>
      </div>

      {/* Wallets Grid */}
      {filteredWallets.length === 0 ? (
        <div style={{
          padding: '48px',
          textAlign: 'center',
          backgroundColor: '#111827',
          borderRadius: '10px',
          border: '1px dashed #334155',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '12px',
        }}>
          <div style={{ fontSize: '32px' }}>💼</div>
          <div style={{ fontSize: '16px', fontWeight: 600, color: '#f8fafc' }}>
            No Wallets Found
          </div>
          <p style={{ margin: 0, fontSize: '13px', color: '#94a3b8', maxWidth: '440px' }}>
            {searchTerm || filterChain !== 'ALL'
              ? 'No wallets match your current search and filter criteria.'
              : 'You have not created any Web3 threshold wallets yet. Generate one backed by a verified DKG session.'}
          </p>
          <button
            onClick={() => onNavigate('create-wallet')}
            style={{
              marginTop: '8px',
              padding: '10px 20px',
              backgroundColor: '#2563eb',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              fontWeight: 600,
              fontSize: '13px',
              cursor: 'pointer',
            }}
          >
            Create Your First Wallet ➔
          </button>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(400px, 1fr))', gap: '16px' }}>
          {filteredWallets.map((wallet) => (
            <div
              key={wallet.walletId}
              onClick={() => onSelectWallet(wallet)}
              style={{
                backgroundColor: '#111827',
                border: '1px solid #1f2937',
                borderRadius: '10px',
                padding: '20px',
                cursor: 'pointer',
                display: 'flex',
                flexDirection: 'column',
                gap: '14px',
                transition: 'all 0.15s ease-in-out',
              }}
            >
              {/* Card Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc', marginBottom: '2px' }}>
                    {wallet.name}
                  </div>
                  <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'monospace' }}>
                    {wallet.walletId}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '6px' }}>
                  <span style={{
                    fontSize: '10px',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: '4px',
                    backgroundColor: 'rgba(56, 189, 248, 0.15)',
                    color: '#38bdf8',
                  }}>
                    {wallet.blockchain.toUpperCase()}
                  </span>
                  <span style={{
                    fontSize: '10px',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: '4px',
                    backgroundColor: '#1e293b',
                    color: '#94a3b8',
                  }}>
                    {wallet.network}
                  </span>
                </div>
              </div>

              {/* Address Display Box */}
              <div style={{
                backgroundColor: '#0c121e',
                borderRadius: '6px',
                padding: '10px 12px',
                border: '1px solid #1e293b',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}>
                <span style={{
                  fontFamily: 'monospace',
                  fontSize: '13px',
                  color: '#34d399',
                  fontWeight: 600,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  maxWidth: '300px',
                }}>
                  {wallet.address}
                </span>
                <button
                  onClick={(e) => copyAddress(wallet.walletId, wallet.address, e)}
                  style={{
                    padding: '4px 8px',
                    backgroundColor: '#1e293b',
                    color: copiedId === wallet.walletId ? '#34d399' : '#94a3b8',
                    border: '1px solid #334155',
                    borderRadius: '4px',
                    fontSize: '11px',
                    cursor: 'pointer',
                  }}
                >
                  {copiedId === wallet.walletId ? '✓ Copied' : 'Copy'}
                </button>
              </div>

              {/* Meta Info */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '11px', color: '#94a3b8' }}>
                <div>
                  Curve: <strong style={{ color: '#cbd5e1' }}>{wallet.curve}</strong>
                </div>
                <div>
                  Committee: <span style={{ color: '#cbd5e1' }}>{wallet.committeeId}</span>
                </div>
                <div>
                  Balance: <span style={{ color: '#64748b' }}>Not connected</span>
                </div>
                <div>
                  Status: <span style={{ color: '#10b981', fontWeight: 600 }}>● {wallet.status}</span>
                </div>
              </div>

              {/* Footer Action */}
              <div style={{
                borderTop: '1px solid #1f2937',
                paddingTop: '10px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                fontSize: '11px',
              }}>
                <span style={{ color: '#64748b' }}>
                  DKG: <span style={{ fontFamily: 'monospace' }}>{wallet.dkgSessionId}</span>
                </span>
                <span style={{ color: '#38bdf8', fontWeight: 600 }}>
                  View Full Details ➔
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
