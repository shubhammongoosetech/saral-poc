import React, { useState } from 'react';
import { DKGSessionData, NavigationTab } from '../../types';

interface KeyManagementViewProps {
  dkgSessions: DKGSessionData[];
  onNavigate: (tab: NavigationTab) => void;
}

export const KeyManagementView: React.FC<KeyManagementViewProps> = ({
  dkgSessions,
  onNavigate,
}) => {
  const [copiedKey, setCopiedKey] = useState<string>('');

  const completed = dkgSessions.filter((s) => s.state === 'COMPLETED');

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(''), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div>
        <h2 style={{ fontSize: '20px', fontWeight: 700, margin: '0 0 4px 0', color: '#f8fafc' }}>
          Cryptographic Key Management & Curve Audit
        </h2>
        <p style={{ margin: 0, fontSize: '13px', color: '#94a3b8' }}>
          Audited decoupling of blinded Pedersen commitments from unblinded blockchain signing keys.
        </p>
      </div>

      {/* Critical Cryptographic Validation Card */}
      <div style={{
        padding: '20px',
        backgroundColor: '#111827',
        border: '1px solid #1e293b',
        borderRadius: '10px',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '18px' }}>🛡️</span>
          <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: '#f8fafc' }}>
            Pedersen Commitment vs Signing Public Key Audit
          </h3>
        </div>
        <p style={{ margin: 0, fontSize: '12px', color: '#cbd5e1', lineHeight: '1.5' }}>
          In SARAL V3, secret shares are information-theoretically protected during AVSS using Pedersen commitments:
          <span style={{ fontFamily: 'monospace', color: '#a78bfa', marginLeft: '6px' }}>C₀,₀ = x·G + r·H</span>.
          However, blockchain signature verification algorithms require the pure unblinded signing key:
          <span style={{ fontFamily: 'monospace', color: '#34d399', marginLeft: '6px' }}>Y = x·G</span>.
          SARAL rigorously decouples the two points to ensure valid signature and address operations.
        </p>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '12px',
          marginTop: '6px',
        }}>
          <div style={{ padding: '12px', backgroundColor: '#0c121e', borderRadius: '6px', border: '1px solid #1e293b' }}>
            <div style={{ fontSize: '11px', color: '#94a3b8' }}>Pedersen Commitment:</div>
            <div style={{ fontFamily: 'monospace', color: '#a78bfa', fontSize: '13px', fontWeight: 700, marginTop: '2px' }}>
              C = x·G + r·H
            </div>
            <div style={{ fontSize: '10px', color: '#64748b', marginTop: '4px' }}>Information-theoretic hiding</div>
          </div>

          <div style={{ padding: '12px', backgroundColor: '#0c121e', borderRadius: '6px', border: '1px solid #1e293b' }}>
            <div style={{ fontSize: '11px', color: '#94a3b8' }}>Signing Public Key:</div>
            <div style={{ fontFamily: 'monospace', color: '#34d399', fontSize: '13px', fontWeight: 700, marginTop: '2px' }}>
              Y = x·G
            </div>
            <div style={{ fontSize: '10px', color: '#64748b', marginTop: '4px' }}>Unblinded curve point for verification</div>
          </div>

          <div style={{ padding: '12px', backgroundColor: '#0c121e', borderRadius: '6px', border: '1px solid #1e293b' }}>
            <div style={{ fontSize: '11px', color: '#94a3b8' }}>Mathematical Relation:</div>
            <div style={{ fontFamily: 'monospace', color: '#38bdf8', fontSize: '13px', fontWeight: 700, marginTop: '2px' }}>
              C - Y = r·H
            </div>
            <div style={{ fontSize: '10px', color: '#64748b', marginTop: '4px' }}>Decoupled when r ≠ 0</div>
          </div>
        </div>
      </div>

      {/* Verified DKG Key Catalog */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>
          Verified DKG Keys Catalog
        </h3>

        {completed.length === 0 ? (
          <div style={{ padding: '36px', textAlign: 'center', backgroundColor: '#111827', borderRadius: '10px', border: '1px dashed #334155', color: '#94a3b8', fontSize: '13px' }}>
            No verified DKG keys available. Run a DKG session to generate keys.
          </div>
        ) : (
          completed.map((key) => (
            <div
              key={key.sessionId}
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
                      Key ID: {key.sessionId}
                    </span>
                    <span style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: '4px',
                      backgroundColor: 'rgba(16, 185, 129, 0.2)',
                      color: '#34d399',
                    }}>
                      Epoch τ={key.epoch} Verified
                    </span>
                  </div>
                  <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px' }}>
                    Committee: <strong>{key.committeeId}</strong> | Curve: <strong>{key.curve}</strong>
                  </div>
                </div>

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
                  Create Wallet from Key ➔
                </button>
              </div>

              {/* Signing Key Box */}
              <div style={{
                backgroundColor: '#0c121e',
                borderRadius: '6px',
                padding: '12px',
                border: '1px solid #1e293b',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '11px', color: '#94a3b8', fontWeight: 600 }}>
                    Unblinded Master Signing Key (Y = x·G):
                  </span>
                  <button
                    onClick={() => copyToClipboard(key.masterPublicKey || '', key.sessionId)}
                    style={{
                      padding: '2px 8px',
                      backgroundColor: '#1e293b',
                      color: copiedKey === key.sessionId ? '#34d399' : '#38bdf8',
                      border: '1px solid #334155',
                      borderRadius: '4px',
                      fontSize: '10px',
                      cursor: 'pointer',
                    }}
                  >
                    {copiedKey === key.sessionId ? '✓ Copied' : 'Copy'}
                  </button>
                </div>
                <div style={{ fontFamily: 'monospace', color: '#34d399', fontSize: '12px', wordBreak: 'break-all' }}>
                  {key.masterPublicKey || '04' + '0'.repeat(128)}
                </div>
              </div>

              {/* Supported Chains Badges */}
              <div>
                <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '6px' }}>
                  Blockchain Curve Compatibility:
                </div>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <span style={{
                    fontSize: '10px',
                    padding: '3px 8px',
                    borderRadius: '4px',
                    backgroundColor: 'rgba(16, 185, 129, 0.15)',
                    color: '#34d399',
                    border: '1px solid rgba(16, 185, 129, 0.3)',
                  }}>
                    ✓ WebAuthn / Passkey Account (NIST P-256)
                  </span>
                  <span style={{
                    fontSize: '10px',
                    padding: '3px 8px',
                    borderRadius: '4px',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    color: '#f87171',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                  }}>
                    ✗ Ethereum/EVM (Requires secp256k1)
                  </span>
                  <span style={{
                    fontSize: '10px',
                    padding: '3px 8px',
                    borderRadius: '4px',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    color: '#f87171',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                  }}>
                    ✗ Bitcoin Taproot (Requires secp256k1)
                  </span>
                  <span style={{
                    fontSize: '10px',
                    padding: '3px 8px',
                    borderRadius: '4px',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    color: '#f87171',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                  }}>
                    ✗ Solana (Requires Ed25519)
                  </span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
