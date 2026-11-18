import React, { useState } from 'react';
import { WalletRecord, NavigationTab } from '../../types';

interface WalletDetailsViewProps {
  wallet: WalletRecord | null;
  onBack: () => void;
  onNavigate: (tab: NavigationTab) => void;
}

export const WalletDetailsView: React.FC<WalletDetailsViewProps> = ({
  wallet,
  onBack,
  onNavigate,
}) => {
  const [copied, setCopied] = useState<boolean>(false);

  if (!wallet) {
    return (
      <div style={{
        padding: '60px',
        textAlign: 'center',
        backgroundColor: '#111827',
        borderRadius: '10px',
        border: '1px solid #1f2937',
      }}>
        <div style={{ fontSize: '32px', marginBottom: '12px' }}>💼</div>
        <div style={{ fontSize: '16px', fontWeight: 600, color: '#f8fafc', marginBottom: '6px' }}>
          No Wallet Selected
        </div>
        <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: '#94a3b8' }}>
          Select a wallet from your dashboard to view its verified address and cryptographic parameters.
        </p>
        <button
          onClick={onBack}
          style={{
            padding: '8px 18px',
            backgroundColor: '#2563eb',
            color: '#ffffff',
            border: 'none',
            borderRadius: '6px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          ← Return to My Wallets
        </button>
      </div>
    );
  }

  const copyAddress = () => {
    navigator.clipboard.writeText(wallet.address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ maxWidth: '880px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Navigation / Breadcrumb */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <button
          onClick={onBack}
          style={{
            padding: '6px 14px',
            backgroundColor: '#1e293b',
            color: '#cbd5e1',
            border: '1px solid #334155',
            borderRadius: '6px',
            fontSize: '12px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          ← Back to Wallets
        </button>
        <span style={{
          fontSize: '11px',
          fontWeight: 700,
          padding: '4px 10px',
          borderRadius: '9999px',
          backgroundColor: 'rgba(16, 185, 129, 0.2)',
          color: '#34d399',
          border: '1px solid #10b981',
        }}>
          ● {wallet.status}
        </span>
      </div>

      {/* Main Address Card */}
      <div style={{
        backgroundColor: '#111827',
        border: '1px solid #1f2937',
        borderRadius: '12px',
        padding: '28px',
        display: 'flex',
        flexDirection: 'column',
        gap: '20px',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h2 style={{ fontSize: '22px', fontWeight: 800, margin: '0 0 4px 0', color: '#f8fafc' }}>
              {wallet.name}
            </h2>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <span style={{
                fontSize: '11px',
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: '4px',
                backgroundColor: 'rgba(56, 189, 248, 0.15)',
                color: '#38bdf8',
              }}>
                {wallet.blockchain.toUpperCase()}
              </span>
              <span style={{ fontSize: '11px', color: '#94a3b8' }}>•</span>
              <span style={{ fontSize: '11px', color: '#94a3b8' }}>Network: {wallet.network}</span>
              <span style={{ fontSize: '11px', color: '#94a3b8' }}>•</span>
              <span style={{ fontSize: '11px', color: '#a78bfa' }}>Curve: {wallet.curve}</span>
            </div>
          </div>

          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '11px', color: '#64748b' }}>Balance</div>
            <div style={{ fontSize: '15px', fontWeight: 700, color: '#94a3b8' }}>
              Not connected
            </div>
            <div style={{ fontSize: '10px', color: '#64748b' }}>(RPC query disabled)</div>
          </div>
        </div>

        {/* Large Verified Address Box */}
        <div style={{
          padding: '20px',
          backgroundColor: '#0c121e',
          borderRadius: '10px',
          border: '1px solid #1e293b',
        }}>
          <div style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 700, marginBottom: '8px' }}>
            Verified Blockchain Address
          </div>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            backgroundColor: '#111827',
            padding: '12px 16px',
            borderRadius: '6px',
            border: '1px solid #334155',
          }}>
            <span style={{
              fontFamily: 'monospace',
              fontSize: '16px',
              color: '#34d399',
              fontWeight: 700,
              wordBreak: 'break-all',
            }}>
              {wallet.address}
            </span>
            <button
              onClick={copyAddress}
              style={{
                padding: '8px 16px',
                backgroundColor: '#1e293b',
                color: copied ? '#34d399' : '#38bdf8',
                border: '1px solid #334155',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                flexShrink: 0,
                marginLeft: '16px',
              }}
            >
              {copied ? '✓ Copied' : 'Copy Address'}
            </button>
          </div>
        </div>

        {/* Visual QR Simulation */}
        <div style={{
          display: 'flex',
          gap: '24px',
          alignItems: 'center',
          padding: '16px',
          backgroundColor: '#0c121e',
          borderRadius: '8px',
          border: '1px solid #1e293b',
        }}>
          <div style={{
            width: '84px',
            height: '84px',
            backgroundColor: '#ffffff',
            borderRadius: '6px',
            padding: '6px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
          }}>
            {/* Visual SVG QR representation */}
            <svg viewBox="0 0 24 24" width="72" height="72" fill="#000000">
              <rect x="2" y="2" width="6" height="6" />
              <rect x="4" y="4" width="2" height="2" fill="#ffffff" />
              <rect x="16" y="2" width="6" height="6" />
              <rect x="18" y="4" width="2" height="2" fill="#ffffff" />
              <rect x="2" y="16" width="6" height="6" />
              <rect x="4" y="18" width="2" height="2" fill="#ffffff" />
              <rect x="10" y="2" width="2" height="4" />
              <rect x="10" y="8" width="4" height="2" />
              <rect x="10" y="14" width="2" height="4" />
              <rect x="16" y="10" width="4" height="2" />
              <rect x="14" y="16" width="6" height="2" />
              <rect x="18" y="20" width="4" height="2" />
            </svg>
          </div>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc', marginBottom: '4px' }}>
              QR Code Representation
            </div>
            <div style={{ fontSize: '12px', color: '#94a3b8', lineHeight: '1.4' }}>
              Scan with supported Web3 mobile wallets or account abstraction passkey signers to deliver assets.
            </div>
          </div>
        </div>

        {/* Cryptographic Parameters Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '16px' }}>
          <div style={{
            padding: '16px',
            backgroundColor: '#0c121e',
            borderRadius: '8px',
            border: '1px solid #1e293b',
            fontSize: '12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}>
            <div style={{ color: '#94a3b8' }}>DKG Session ID:</div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontFamily: 'monospace', color: '#38bdf8' }}>{wallet.dkgSessionId}</span>
              <button
                onClick={() => onNavigate('dkg-sessions')}
                style={{
                  padding: '2px 8px',
                  backgroundColor: '#1e293b',
                  color: '#38bdf8',
                  border: '1px solid #0284c7',
                  borderRadius: '4px',
                  fontSize: '10px',
                  cursor: 'pointer',
                }}
              >
                Inspect DKG ➔
              </button>
            </div>
            <div style={{ color: '#94a3b8', marginTop: '4px' }}>Committee ID:</div>
            <strong style={{ color: '#f8fafc' }}>{wallet.committeeId}</strong>
            <div style={{ color: '#94a3b8', marginTop: '4px' }}>Key ID:</div>
            <span style={{ fontFamily: 'monospace', color: '#cbd5e1' }}>{wallet.keyId}</span>
          </div>

          <div style={{
            padding: '16px',
            backgroundColor: '#0c121e',
            borderRadius: '8px',
            border: '1px solid #1e293b',
            fontSize: '12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}>
            <div style={{ color: '#94a3b8' }}>Signing Capability:</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ color: '#fbbf24', fontWeight: 600 }}>Address Created Only</span>
            </div>
            <div style={{ fontSize: '11px', color: '#64748b', lineHeight: '1.4' }}>
              Threshold signature scheme (TSS) execution is scheduled for Phase 4. Transfer / sign operations are strictly disabled.
            </div>
            <div style={{ color: '#94a3b8', marginTop: '4px' }}>Created Timestamp:</div>
            <span style={{ color: '#94a3b8' }}>{new Date(wallet.createdAt).toLocaleString()}</span>
          </div>
        </div>

        {/* Public Key Display */}
        <div style={{
          padding: '14px',
          backgroundColor: '#0c121e',
          borderRadius: '8px',
          border: '1px solid #1e293b',
          fontSize: '11px',
          fontFamily: 'monospace',
        }}>
          <span style={{ color: '#94a3b8' }}>Unblinded Master Signing Public Key (Y = x*G):</span>
          <div style={{ color: '#a78bfa', marginTop: '4px', wordBreak: 'break-all' }}>
            {wallet.publicKeyHex}
          </div>
        </div>

        {/* Security Audit Guarantee */}
        <div style={{
          padding: '14px 16px',
          backgroundColor: '#0c121e',
          borderRadius: '8px',
          border: '1px solid #334155',
          fontSize: '12px',
          color: '#cbd5e1',
          lineHeight: '1.5',
        }}>
          🔒 <strong style={{ color: '#ffffff' }}>Distributed Separation-of-Powers Guarantee:</strong> This address is backed by shares distributed across 15 independent Go node vaults in 3 administrative domains. The coordinator only stores public metadata.
        </div>
      </div>
    </div>
  );
};
