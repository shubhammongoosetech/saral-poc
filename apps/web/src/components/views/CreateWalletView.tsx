import React, { useState } from 'react';
import { DKGSessionData, WalletRecord, NavigationTab } from '../../types';
import { apiService } from '../../services/api';
import { validateChainCurveCompatibility } from '@saral/saral-sdk';

interface CreateWalletViewProps {
  dkgSessions: DKGSessionData[];
  onWalletCreated: (wallet: WalletRecord) => void;
  onNavigate: (tab: NavigationTab) => void;
}

export const CreateWalletView: React.FC<CreateWalletViewProps> = ({
  dkgSessions,
  onWalletCreated,
  onNavigate,
}) => {
  const [step, setStep] = useState<number>(1);
  const [selectedChain, setSelectedChain] = useState<string>('passkey-p256');
  const [selectedNetwork, setSelectedNetwork] = useState<string>('sepolia');
  const [selectedSessionId, setSelectedSessionId] = useState<string>('');
  const [walletName, setWalletName] = useState<string>('SARAL Primary Web3 Account');
  const [loading, setLoading] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string>('');
  const [createdWallet, setCreatedWallet] = useState<WalletRecord | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  // Filter completed DKG sessions
  const completedSessions = dkgSessions.filter((s) => s.state === 'COMPLETED');

  // Currently selected session
  const currentSession = completedSessions.find((s) => s.sessionId === selectedSessionId) || completedSessions[0];

  // Curve compatibility check for selected chain against selected DKG key curve
  const activeKeyCurve = currentSession?.curve || 'NIST P-256';
  const compatibility = validateChainCurveCompatibility(selectedChain, activeKeyCurve);

  const chains = [
    {
      id: 'ethereum',
      name: 'Ethereum (EVM)',
      symbol: 'ETH',
      icon: 'Ξ',
      requiredCurve: 'secp256k1',
      description: 'Native secp256k1 ECDSA. EIP-55 checksum address.',
      networks: ['mainnet', 'sepolia', 'holesky'],
    },
    {
      id: 'bitcoin',
      name: 'Bitcoin Taproot',
      symbol: 'BTC',
      icon: '₿',
      requiredCurve: 'secp256k1',
      description: 'BIP-340 / BIP-341 Taproot x-only key with BIP-350 Bech32m address.',
      networks: ['mainnet', 'testnet'],
    },
    {
      id: 'solana',
      name: 'Solana',
      symbol: 'SOL',
      icon: '◎',
      requiredCurve: 'ed25519',
      description: 'Native Ed25519 32-byte public key encoded in Base58.',
      networks: ['mainnet', 'devnet', 'testnet'],
    },
    {
      id: 'passkey-p256',
      name: 'WebAuthn / Passkey Account',
      symbol: 'PASSKEY',
      icon: '🔐',
      requiredCurve: 'nist-p256',
      description: 'Hardware-grade NIST P-256 / secp256r1. Native EIP-7212 Passkey Smart Account.',
      networks: ['sepolia', 'arbitrum', 'base', 'optimism'],
    },
  ];

  const handleCreateWallet = async () => {
    if (!compatibility.compatible) {
      setErrorMsg(compatibility.reason || 'Selected chain is incompatible with DKG key curve');
      return;
    }

    if (!currentSession) {
      setErrorMsg('Please select a completed DKG session');
      return;
    }

    setLoading(true);
    setErrorMsg('');

    try {
      const wallet = await apiService.createWallet({
        name: walletName,
        blockchain: selectedChain,
        network: selectedNetwork,
        dkgSessionId: currentSession.sessionId,
      });

      setCreatedWallet(wallet);
      onWalletCreated(wallet);
      setStep(4);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to create wallet');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ maxWidth: '880px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Wizard Header */}
      <div>
        <h2 style={{ fontSize: '20px', fontWeight: 700, margin: '0 0 6px 0', color: '#f8fafc' }}>
          Create Web3 Threshold Wallet
        </h2>
        <p style={{ margin: 0, fontSize: '13px', color: '#94a3b8' }}>
          Derive cryptographically verified blockchain addresses from dealerless DKG key material.
        </p>
      </div>

      {/* Stepper Tabs */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
        {[
          { num: 1, label: 'Blockchain' },
          { num: 2, label: 'DKG Key' },
          { num: 3, label: 'Configuration' },
          { num: 4, label: 'Wallet Created' },
        ].map((s) => {
          const isDone = step > s.num;
          const isCurrent = step === s.num;
          return (
            <div
              key={s.num}
              style={{
                padding: '10px 14px',
                borderRadius: '8px',
                backgroundColor: isCurrent ? '#1e293b' : '#111827',
                border: `1px solid ${isCurrent ? '#38bdf8' : '#1f2937'}`,
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <div style={{
                width: '22px',
                height: '22px',
                borderRadius: '50%',
                backgroundColor: isDone ? '#10b981' : isCurrent ? '#0284c7' : '#334155',
                color: '#ffffff',
                fontSize: '11px',
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}>
                {isDone ? '✓' : s.num}
              </div>
              <span style={{ fontSize: '12px', fontWeight: 600, color: isCurrent ? '#f8fafc' : '#94a3b8' }}>
                {s.label}
              </span>
            </div>
          );
        })}
      </div>

      {/* STEP 1: Select Blockchain */}
      {step === 1 && (
        <div style={{
          backgroundColor: '#111827',
          border: '1px solid #1f2937',
          borderRadius: '10px',
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '20px',
        }}>
          <div>
            <h3 style={{ margin: '0 0 6px 0', fontSize: '16px', fontWeight: 600, color: '#f8fafc' }}>
              Step 1 — Select Target Blockchain
            </h3>
            <p style={{ margin: 0, fontSize: '12px', color: '#94a3b8' }}>
              Select the network where the threshold wallet address will be deployed. Each blockchain strictly requires a matching elliptic curve.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '14px' }}>
            {chains.map((c) => {
              const isSelected = selectedChain === c.id;
              const isCompatibleWithDkg = c.requiredCurve === 'nist-p256';

              return (
                <div
                  key={c.id}
                  onClick={() => {
                    setSelectedChain(c.id);
                    setSelectedNetwork(c.networks[0]);
                  }}
                  style={{
                    padding: '16px',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    backgroundColor: isSelected ? '#1e293b' : '#0c121e',
                    border: `2px solid ${isSelected ? (isCompatibleWithDkg ? '#38bdf8' : '#f59e0b') : '#1e293b'}`,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '10px',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontSize: '20px' }}>{c.icon}</span>
                      <strong style={{ fontSize: '14px', color: '#f8fafc' }}>{c.name}</strong>
                    </div>
                    <span style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: '4px',
                      backgroundColor: isCompatibleWithDkg ? 'rgba(16, 185, 129, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                      color: isCompatibleWithDkg ? '#34d399' : '#fbbf24',
                      border: `1px solid ${isCompatibleWithDkg ? '#059669' : '#d97706'}`,
                    }}>
                      Curve: {c.requiredCurve}
                    </span>
                  </div>

                  <p style={{ margin: 0, fontSize: '11px', color: '#94a3b8', lineHeight: '1.4' }}>
                    {c.description}
                  </p>

                  {!isCompatibleWithDkg && (
                    <div style={{
                      fontSize: '10px',
                      color: '#f59e0b',
                      backgroundColor: 'rgba(245, 158, 11, 0.1)',
                      padding: '4px 8px',
                      borderRadius: '4px',
                      border: '1px solid rgba(245, 158, 11, 0.3)',
                    }}>
                      ⚠️ Current DKG keys are NIST P-256. Native {c.requiredCurve} DKG is required for this chain.
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Compatibility Warning if selecting incompatible chain */}
          {!compatibility.compatible && (
            <div style={{
              padding: '12px 16px',
              borderRadius: '6px',
              backgroundColor: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid #ef4444',
              color: '#fca5a5',
              fontSize: '12px',
              lineHeight: '1.4',
            }}>
              🛑 <strong style={{ color: '#ffffff' }}>Cryptographic Safety Enforcement:</strong> {compatibility.reason}
              <div style={{ marginTop: '4px', color: '#fecaca', fontSize: '11px' }}>
                SARAL adheres to strict cryptographic integrity. We do not construct fake blockchain addresses from incompatible public keys or use centralized fallbacks.
              </div>
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '10px' }}>
            <button
              onClick={() => setStep(2)}
              disabled={!compatibility.compatible}
              style={{
                padding: '10px 24px',
                backgroundColor: compatibility.compatible ? '#2563eb' : '#475569',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                fontWeight: 600,
                fontSize: '13px',
                cursor: compatibility.compatible ? 'pointer' : 'not-allowed',
                opacity: compatibility.compatible ? 1 : 0.6,
              }}
            >
              Continue to Key Selection ➔
            </button>
          </div>
        </div>
      )}

      {/* STEP 2: Select DKG Key */}
      {step === 2 && (
        <div style={{
          backgroundColor: '#111827',
          border: '1px solid #1f2937',
          borderRadius: '10px',
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '20px',
        }}>
          <div>
            <h3 style={{ margin: '0 0 6px 0', fontSize: '16px', fontWeight: 600, color: '#f8fafc' }}>
              Step 2 — Select Verified DKG Key
            </h3>
            <p style={{ margin: 0, fontSize: '12px', color: '#94a3b8' }}>
              Choose the verified Dealerless DKG session whose aggregated public key will back the wallet.
            </p>
          </div>

          {completedSessions.length === 0 ? (
            <div style={{
              padding: '30px',
              textAlign: 'center',
              backgroundColor: '#0c121e',
              borderRadius: '8px',
              border: '1px dashed #334155',
            }}>
              <div style={{ fontSize: '24px', marginBottom: '8px' }}>🔐</div>
              <div style={{ fontWeight: 600, color: '#f8fafc', marginBottom: '4px' }}>No Completed DKG Sessions Found</div>
              <div style={{ fontSize: '12px', color: '#94a3b8', marginBottom: '16px' }}>
                You must run and complete a Dealerless DKG session before creating a Web3 wallet.
              </div>
              <button
                onClick={() => onNavigate('dkg-sessions')}
                style={{
                  padding: '8px 16px',
                  backgroundColor: '#0284c7',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '6px',
                  fontWeight: 600,
                  fontSize: '12px',
                  cursor: 'pointer',
                }}
              >
                Go to DKG Sessions Wizard ➔
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {completedSessions.map((s) => {
                const isSelected = (selectedSessionId || completedSessions[0].sessionId) === s.sessionId;

                return (
                  <div
                    key={s.sessionId}
                    onClick={() => setSelectedSessionId(s.sessionId)}
                    style={{
                      padding: '16px',
                      borderRadius: '8px',
                      cursor: 'pointer',
                      backgroundColor: isSelected ? '#1e293b' : '#0c121e',
                      border: `2px solid ${isSelected ? '#38bdf8' : '#1e293b'}`,
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <span style={{ fontWeight: 700, color: '#38bdf8', fontFamily: 'monospace', fontSize: '13px' }}>
                          {s.sessionId}
                        </span>
                        <span style={{
                          fontSize: '10px',
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: '4px',
                          backgroundColor: 'rgba(16, 185, 129, 0.2)',
                          color: '#34d399',
                        }}>
                          ● {s.state}
                        </span>
                      </div>
                      <div style={{ fontSize: '11px', color: '#94a3b8' }}>
                        Curve: <strong style={{ color: '#cbd5e1' }}>{s.curve}</strong> | Threshold: <strong>k={s.k}, t={s.t}</strong>
                      </div>
                    </div>

                    <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                      Master Public Key Y: {s.masterPublicKey ? s.masterPublicKey.substring(0, 48) + '...' : 'Available'}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '10px' }}>
            <button
              onClick={() => setStep(1)}
              style={{
                padding: '8px 18px',
                backgroundColor: '#1e293b',
                color: '#cbd5e1',
                border: '1px solid #334155',
                borderRadius: '6px',
                fontSize: '12px',
                cursor: 'pointer',
              }}
            >
              ← Back
            </button>
            <button
              onClick={() => setStep(3)}
              disabled={completedSessions.length === 0}
              style={{
                padding: '10px 24px',
                backgroundColor: completedSessions.length > 0 ? '#2563eb' : '#475569',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                fontWeight: 600,
                fontSize: '13px',
                cursor: completedSessions.length > 0 ? 'pointer' : 'not-allowed',
              }}
            >
              Continue to Configuration ➔
            </button>
          </div>
        </div>
      )}

      {/* STEP 3: Configure and Generate */}
      {step === 3 && (
        <div style={{
          backgroundColor: '#111827',
          border: '1px solid #1f2937',
          borderRadius: '10px',
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '20px',
        }}>
          <div>
            <h3 style={{ margin: '0 0 6px 0', fontSize: '16px', fontWeight: 600, color: '#f8fafc' }}>
              Step 3 — Configure Wallet Parameters
            </h3>
            <p style={{ margin: 0, fontSize: '12px', color: '#94a3b8' }}>
              Confirm your wallet metadata and deploy the address record to the coordinator.
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
                Wallet Name
              </label>
              <input
                type="text"
                value={walletName}
                onChange={(e) => setWalletName(e.target.value)}
                style={{
                  width: '100%',
                  padding: '10px 14px',
                  backgroundColor: '#0c121e',
                  border: '1px solid #334155',
                  borderRadius: '6px',
                  color: '#f8fafc',
                  fontSize: '13px',
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
                Target Network
              </label>
              <select
                value={selectedNetwork}
                onChange={(e) => setSelectedNetwork(e.target.value)}
                style={{
                  width: '100%',
                  padding: '10px 14px',
                  backgroundColor: '#0c121e',
                  border: '1px solid #334155',
                  borderRadius: '6px',
                  color: '#f8fafc',
                  fontSize: '13px',
                }}
              >
                {chains.find((c) => c.id === selectedChain)?.networks.map((net) => (
                  <option key={net} value={net}>
                    {net.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>

            {/* Summary Review Card */}
            <div style={{
              padding: '16px',
              borderRadius: '8px',
              backgroundColor: '#0c121e',
              border: '1px solid #1e293b',
              fontSize: '12px',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#94a3b8' }}>Target Blockchain:</span>
                <strong style={{ color: '#38bdf8' }}>{chains.find((c) => c.id === selectedChain)?.name}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#94a3b8' }}>Curve Compliance:</span>
                <span style={{ color: '#34d399', fontWeight: 600 }}>✓ Verified ({activeKeyCurve})</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#94a3b8' }}>DKG Key Reference:</span>
                <span style={{ color: '#e2e8f0', fontFamily: 'monospace' }}>{currentSession?.sessionId}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#94a3b8' }}>Signing Capability:</span>
                <span style={{ color: '#fbbf24' }}>Address Only (Signing scheduled for Phase 4)</span>
              </div>
            </div>

            {errorMsg && (
              <div style={{
                padding: '12px',
                borderRadius: '6px',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid #ef4444',
                color: '#f87171',
                fontSize: '12px',
              }}>
                {errorMsg}
              </div>
            )}
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '10px' }}>
            <button
              onClick={() => setStep(2)}
              disabled={loading}
              style={{
                padding: '8px 18px',
                backgroundColor: '#1e293b',
                color: '#cbd5e1',
                border: '1px solid #334155',
                borderRadius: '6px',
                fontSize: '12px',
                cursor: 'pointer',
              }}
            >
              ← Back
            </button>
            <button
              onClick={handleCreateWallet}
              disabled={loading}
              style={{
                padding: '10px 24px',
                backgroundColor: '#2563eb',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                fontWeight: 600,
                fontSize: '13px',
                cursor: loading ? 'not-allowed' : 'pointer',
                opacity: loading ? 0.7 : 1,
              }}
            >
              {loading ? 'Deriving & Verifying Address...' : '🚀 Generate Real Wallet Address'}
            </button>
          </div>
        </div>
      )}

      {/* STEP 4: Wallet Created Confirmation */}
      {step === 4 && createdWallet && (
        <div style={{
          backgroundColor: '#111827',
          border: '1px solid #10b981',
          borderRadius: '12px',
          padding: '28px',
          display: 'flex',
          flexDirection: 'column',
          gap: '24px',
          boxShadow: '0 8px 30px rgba(16, 185, 129, 0.15)',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '20px' }}>🎉</span>
                <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: '#f8fafc' }}>
                  Web3 Wallet Address Successfully Created
                </h3>
              </div>
              <p style={{ margin: '4px 0 0 28px', fontSize: '12px', color: '#94a3b8' }}>
                Derived from verified Dealerless DKG key material without central private key reconstruction.
              </p>
            </div>
            <span style={{
              fontSize: '11px',
              fontWeight: 700,
              padding: '4px 10px',
              borderRadius: '9999px',
              backgroundColor: 'rgba(16, 185, 129, 0.2)',
              color: '#34d399',
              border: '1px solid #10b981',
            }}>
              ● {createdWallet.status}
            </span>
          </div>

          {/* Large Address Card */}
          <div style={{
            padding: '20px',
            backgroundColor: '#0c121e',
            borderRadius: '10px',
            border: '1px solid #1e293b',
          }}>
            <div style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 700, marginBottom: '8px' }}>
              Verified Blockchain Address ({createdWallet.blockchain.toUpperCase()} • {createdWallet.network.toUpperCase()})
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
                fontSize: '15px',
                color: '#34d399',
                fontWeight: 700,
                wordBreak: 'break-all',
              }}>
                {createdWallet.address}
              </span>
              <button
                onClick={() => copyToClipboard(createdWallet.address)}
                style={{
                  padding: '6px 12px',
                  backgroundColor: '#1e293b',
                  color: copied ? '#34d399' : '#38bdf8',
                  border: '1px solid #334155',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  flexShrink: 0,
                  marginLeft: '12px',
                }}
              >
                {copied ? '✓ Copied' : 'Copy'}
              </button>
            </div>
          </div>

          {/* Details Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            <div style={{
              padding: '14px',
              backgroundColor: '#0c121e',
              borderRadius: '8px',
              border: '1px solid #1e293b',
              fontSize: '12px',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
            }}>
              <div style={{ color: '#94a3b8' }}>Wallet Name:</div>
              <strong style={{ color: '#f8fafc' }}>{createdWallet.name}</strong>
              <div style={{ color: '#94a3b8', marginTop: '6px' }}>Wallet ID:</div>
              <span style={{ fontFamily: 'monospace', color: '#38bdf8' }}>{createdWallet.walletId}</span>
              <div style={{ color: '#94a3b8', marginTop: '6px' }}>DKG Key Reference:</div>
              <span style={{ fontFamily: 'monospace', color: '#cbd5e1' }}>{createdWallet.dkgSessionId}</span>
            </div>

            <div style={{
              padding: '14px',
              backgroundColor: '#0c121e',
              borderRadius: '8px',
              border: '1px solid #1e293b',
              fontSize: '12px',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
            }}>
              <div style={{ color: '#94a3b8' }}>Cryptographic Curve:</div>
              <strong style={{ color: '#a78bfa' }}>{createdWallet.curve}</strong>
              <div style={{ color: '#94a3b8', marginTop: '6px' }}>Committee ID:</div>
              <span style={{ color: '#cbd5e1' }}>{createdWallet.committeeId}</span>
              <div style={{ color: '#94a3b8', marginTop: '6px' }}>Creation Date:</div>
              <span style={{ color: '#94a3b8' }}>{new Date(createdWallet.createdAt).toLocaleString()}</span>
            </div>
          </div>

          {/* Public Key Display */}
          <div style={{
            padding: '12px',
            backgroundColor: '#0c121e',
            borderRadius: '6px',
            border: '1px solid #1e293b',
            fontSize: '11px',
            fontFamily: 'monospace',
          }}>
            <span style={{ color: '#94a3b8' }}>Unblinded Master Signing Public Key (Y = x*G):</span>
            <div style={{ color: '#a78bfa', marginTop: '4px', wordBreak: 'break-all' }}>
              {createdWallet.publicKeyHex}
            </div>
          </div>

          {/* Separation of Powers Security Disclaimer */}
          <div style={{
            padding: '12px 16px',
            backgroundColor: 'rgba(99, 102, 241, 0.1)',
            border: '1px solid #6366f1',
            borderRadius: '6px',
            fontSize: '12px',
            color: '#c7d2fe',
            lineHeight: '1.4',
          }}>
            🛡️ <strong style={{ color: '#ffffff' }}>Zero-Knowledge Distributed Custody:</strong> No master private key was reconstructed or handled by the browser or coordinator. The underlying secret shares remain securely vaulted inside local Go node processes.
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
            <button
              onClick={() => {
                setStep(1);
                setCreatedWallet(null);
              }}
              style={{
                padding: '10px 18px',
                backgroundColor: '#1e293b',
                color: '#cbd5e1',
                border: '1px solid #334155',
                borderRadius: '6px',
                fontSize: '13px',
                cursor: 'pointer',
              }}
            >
              + Create Another Wallet
            </button>
            <button
              onClick={() => onNavigate('wallets')}
              style={{
                padding: '10px 22px',
                backgroundColor: '#2563eb',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                fontWeight: 600,
                fontSize: '13px',
                cursor: 'pointer',
              }}
            >
              View in My Wallets ➔
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
