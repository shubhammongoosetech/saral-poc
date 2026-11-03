import React, { useState, useEffect, useCallback } from 'react';
import { walletApi, WalletData, PolicyCheckResponse } from '../api/endpoints';
import { useLocation } from '../hooks/useLocation';
import { useAuth } from '../hooks/useAuth';

export const Wallet: React.FC = () => {
  const { logout } = useAuth();
  const location = useLocation();

  const [hasWallet, setHasWallet] = useState<boolean | null>(null);
  const [wallet, setWallet] = useState<WalletData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Case A: Generation Settings
  const [showConfig, setShowConfig] = useState(false);
  const [nShares, setNShares] = useState(9);
  const [threshold, setThreshold] = useState(5);
  const [generating, setGenerating] = useState(false);

  // Case B: Access Policy State
  const [policyCheck, setPolicyCheck] = useState<PolicyCheckResponse | null>(null);
  const [checkingPolicy, setCheckingPolicy] = useState(false);
  const [isReadyToSign, setIsReadyToSign] = useState(false);

  // Payment Form
  const [recipient, setRecipient] = useState('');
  const [amount, setAmount] = useState('0.001');
  const [signing, setSigning] = useState(false);
  const [txResult, setTxResult] = useState<{ txHash: string; message: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [transactions, setTransactions] = useState<Array<{
    tx_hash: string;
    to_address: string;
    amount: string;
    created_at: string;
  }>>([]);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Fetch transaction history
  const fetchTransactions = useCallback(async () => {
    try {
      const res = await walletApi.getTransactions();
      setTransactions(res.transactions || []);
    } catch (err) {
      // Non-blocking fail
    }
  }, []);

  // Fetch initial wallet state
  const loadWallet = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await walletApi.getWallet();
      setHasWallet(res.hasWallet);
      setWallet(res.wallet);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to fetch wallet status');
    } finally {
      setLoading(false);
    }
  }, []);

  // Check access policy on load and whenever location updates
  const checkAccess = useCallback(async () => {
    if (location.lat === null || location.lng === null) return;
    try {
      setCheckingPolicy(true);
      const result = await walletApi.checkAccess(location.lat, location.lng);
      setPolicyCheck(result);
    } catch (err: any) {
      setPolicyCheck({
        allowed: false,
        reason: err.response?.data?.error || 'Failed to evaluate access policy',
      });
    } finally {
      setCheckingPolicy(false);
    }
  }, [location.lat, location.lng]);

  const handleManualRefresh = async () => {
    try {
      setRefreshing(true);
      setError(null);
      const res = await walletApi.getWallet();
      setHasWallet(res.hasWallet);
      setWallet(res.wallet);
      if (location.lat !== null && location.lng !== null) {
        const result = await walletApi.checkAccess(location.lat, location.lng);
        setPolicyCheck(result);
      }
      await fetchTransactions();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to refresh wallet status');
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadWallet();
  }, [loadWallet]);

  useEffect(() => {
    if (hasWallet) {
      fetchTransactions();
    }
  }, [hasWallet, fetchTransactions]);

  useEffect(() => {
    if (hasWallet && location.lat !== null && location.lng !== null) {
      checkAccess();
    }
  }, [hasWallet, location.lat, location.lng, checkAccess]);

  // Case A: Generate Wallet
  const handleGenerate = async () => {
    if (threshold > nShares) {
      setError('Threshold cannot be greater than total shares (n)');
      return;
    }
    try {
      setGenerating(true);
      setError(null);
      const res = await walletApi.generateWallet(nShares, threshold);
      setWallet(res.wallet);
      setHasWallet(true);
      setIsReadyToSign(true);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to generate cryptographic wallet');
    } finally {
      setGenerating(false);
    }
  };

  // Case B: Trigger Ready to Sign
  const handleReadyToSign = () => {
    if (policyCheck?.allowed) {
      setIsReadyToSign(true);
    }
  };

  // Payment Form Submit
  const handleSendTransaction = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!recipient.startsWith('0x') || recipient.length !== 42) {
      setError('Please provide a valid Ethereum recipient address (0x...)');
      return;
    }
    if (!amount || parseFloat(amount) <= 0) {
      setError('Please enter a valid positive transfer amount');
      return;
    }

    try {
      setSigning(true);
      setError(null);
      setTxResult(null);

      const res = await walletApi.signTransaction({
        toAddress: recipient.trim(),
        amount: amount.trim(),
        lat: location.lat || undefined,
        lng: location.lng || undefined,
      });

      setTxResult({
        txHash: res.txHash,
        message: res.message,
      });

      // Reload wallet to refresh balance and transaction history
      loadWallet();
      fetchTransactions();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Transaction execution failed');
      // If access policy failed during signing, re-evaluate
      checkAccess();
    } finally {
      setSigning(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const copyTxHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  if (loading) {
    return (
      <div className="card">
        <p style={{ textAlign: 'center', color: 'var(--text-muted)' }}>Loading wallet...</p>
      </div>
    );
  }

  return (
    <div className="card card-wide">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
        <h1 className="page-title" style={{ margin: 0 }}>SARAL Wallet</h1>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            type="button"
            onClick={handleManualRefresh}
            className="btn btn-outline btn-sm"
            disabled={refreshing}
            title="Refresh balance and security status"
          >
            {refreshing ? 'Refreshing...' : '↻ Refresh'}
          </button>
          <button onClick={logout} className="btn btn-outline btn-sm">
            Logout
          </button>
        </div>
      </div>
      <p className="page-subtitle">SARAL Non-Custodial Key Management — 3-Domain Separation of Powers & True Threshold MPC</p>

      {error && <div className="alert alert-danger">{error}</div>}

      {/* CASE A: No Wallet exists yet */}
      {!hasWallet ? (
        <div>
          <div className="policy-block" style={{ marginBottom: '20px' }}>
            <p style={{ fontWeight: 600, marginBottom: '6px' }}>First-Time Setup: 3-Domain MPC Wallet Initialization</p>
            <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
              Your wallet is generated via Distributed Key Generation (DKG) across 3 independent trust domains:
              <strong> FOUNDATION</strong> (Institutional Compliance), <strong>PUBLIC</strong> (Decentralized Staking Nodes), and <strong>PRIVATE</strong> (Sovereign User Devices & Guardians).
              27 distributed nodes are deployed with <strong>Zero Complete Private Key Reconstruction</strong>.
            </p>
          </div>

          <div style={{ marginBottom: '18px' }}>
            <button
              type="button"
              className="copy-btn"
              onClick={() => setShowConfig(!showConfig)}
              style={{ marginBottom: '12px' }}
            >
              {showConfig ? 'Hide Shamir Parameters' : 'Configure Shamir Parameters (Default: 9 shares, threshold 5)'}
            </button>

            {showConfig && (
              <div className="grid-2 policy-block" style={{ marginTop: 0 }}>
                <div className="form-group" style={{ margin: 0 }}>
                  <label className="form-label" htmlFor="totalShares">
                    Total Shares (n) [2-255]
                  </label>
                  <input
                    id="totalShares"
                    type="number"
                    min={2}
                    max={255}
                    className="form-input text-mono"
                    value={nShares}
                    onChange={(e) => setNShares(parseInt(e.target.value, 10))}
                  />
                </div>
                <div className="form-group" style={{ margin: 0 }}>
                  <label className="form-label" htmlFor="thresholdShares">
                    Threshold Shares (k) [2-n]
                  </label>
                  <input
                    id="thresholdShares"
                    type="number"
                    min={2}
                    max={nShares}
                    className="form-input text-mono"
                    value={threshold}
                    onChange={(e) => setThreshold(parseInt(e.target.value, 10))}
                  />
                </div>
              </div>
            )}
          </div>

          <button
            type="button"
            className="btn btn-primary"
            onClick={handleGenerate}
            disabled={generating}
          >
            {generating ? 'Generating Secure Containers...' : 'Generate Wallet'}
          </button>
        </div>
      ) : (
        /* CASE B: User already has a wallet */
        <div>
          {/* Policy Check Status Banner */}
          {checkingPolicy ? (
            <div className="policy-block" style={{ marginBottom: '16px' }}>
              <p style={{ color: 'var(--text-muted)' }}>Verifying location and working hours...</p>
            </div>
          ) : policyCheck && !policyCheck.allowed ? (
            <div className="alert alert-danger">
              <p style={{ fontWeight: 600, marginBottom: '4px' }}>
                Access allowed only during your working time and location
              </p>
              <p style={{ fontSize: '12px' }}>{policyCheck.reason}</p>
            </div>
          ) : (
            <div className="alert alert-success" style={{ marginBottom: '16px' }}>
              Working time and physical location verified. 3-Domain MPC Threshold Signing Quorum Authorized (Zero Private Key Reconstruction).
            </div>
          )}

          {/* Wallet Information Summary */}
          <div className="summary-list">
            <div className="summary-item">
              <span className="summary-label">Public Address</span>
              <span className="summary-value text-mono" style={{ fontSize: '13px' }}>
                {wallet?.address}
              </span>
            </div>

            <div className="summary-item">
              <span className="summary-label">MSTC Balance</span>
              <span className="summary-value text-mono">
                {wallet?.balance} MSTC
              </span>
            </div>

            <div className="summary-item">
              <span className="summary-label">Cryptographic Protocol</span>
              <span className="summary-value" style={{ color: 'var(--success)', fontWeight: 600 }}>
                {wallet?.protocolVersion || 'MPC-secp256k1-v1'} (Gennaro-Goldfeder Threshold ECDSA)
              </span>
            </div>

            <div className="summary-item">
              <span className="summary-label">Separation-of-Powers Scheme</span>
              <span className="summary-value">
                Foundation (1-of-1) ∧ Public ({wallet?.threshold || 5}-of-{wallet?.n || 9}) ∧ Private ({wallet?.threshold || 5}-of-{wallet?.n || 9})
              </span>
            </div>

            <div className="summary-item">
              <span className="summary-label">Node Cluster Distribution</span>
              <span className="summary-value">
                27 Distributed Nodes across 3 Trust Domains
              </span>
            </div>
          </div>

          {/* Ready to Sign Button (if not already opened) */}
          {!isReadyToSign ? (
            <div style={{ textAlign: 'center', marginTop: '16px' }}>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleReadyToSign}
                disabled={!policyCheck?.allowed}
              >
                Ready to Sign
              </button>
              {!policyCheck?.allowed && (
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '8px' }}>
                  Signing is disabled outside your designated working hours and location.
                </p>
              )}
            </div>
          ) : (
            /* Payment Form */
            <div style={{ marginTop: '24px', borderTop: '1px solid var(--border-color)', paddingTop: '20px' }}>
              <h2 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '14px' }}>
                Send Transaction (MST Testnet)
              </h2>

              <form onSubmit={handleSendTransaction}>
                <div className="form-group">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <label className="form-label" htmlFor="recipientInput" style={{ margin: 0 }}>
                      Recipient Address (0x...)
                    </label>
                    <button
                      type="button"
                      className="copy-btn"
                      style={{ fontSize: '11px', padding: '2px 8px' }}
                      onClick={() => setRecipient('0x742d35Cc6634C0532925a3b844Bc454e4438f44e')}
                    >
                      Use Sample Address
                    </button>
                  </div>
                  <input
                    id="recipientInput"
                    type="text"
                    className="form-input text-mono"
                    placeholder="0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
                    value={recipient}
                    onChange={(e) => setRecipient(e.target.value)}
                    disabled={signing}
                    required
                  />
                </div>

                <div className="form-group">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <label className="form-label" htmlFor="amountInput" style={{ margin: 0 }}>
                      Amount (MSTC)
                    </label>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <button
                        type="button"
                        className="copy-btn"
                        style={{ fontSize: '11px', padding: '2px 6px' }}
                        onClick={() => setAmount('0.001')}
                      >
                        0.001
                      </button>
                      <button
                        type="button"
                        className="copy-btn"
                        style={{ fontSize: '11px', padding: '2px 6px' }}
                        onClick={() => setAmount('1')}
                      >
                        1 MSTC
                      </button>
                      <button
                        type="button"
                        className="copy-btn"
                        style={{ fontSize: '11px', padding: '2px 6px', fontWeight: 600 }}
                        onClick={() => {
                          const currentBal = parseFloat(wallet?.balance || '0');
                          const max = Math.max(0, currentBal - 0.0001);
                          setAmount(max > 0 ? max.toFixed(4) : '0');
                        }}
                      >
                        Send Max
                      </button>
                    </div>
                  </div>
                  <input
                    id="amountInput"
                    type="text"
                    className="form-input text-mono"
                    placeholder="0.01"
                    value={amount}
                    onChange={(e) => setAmount(e.target.value)}
                    disabled={signing}
                    required
                  />
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginTop: '4px' }}>
                    Available: {wallet?.balance} MSTC (Note: small gas fee ~0.000021 MSTC is required for network broadcast)
                  </span>
                </div>

                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={signing || !policyCheck?.allowed}
                >
                  {signing ? 'Coordinating 3-Domain MPC Signing...' : 'Sign & Broadcast Transaction via MPC'}
                </button>
              </form>

              {/* Transaction Hash Result Display */}
              {txResult && (
                <div style={{ marginTop: '20px', padding: '14px', background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '4px' }}>
                  <p style={{ fontSize: '13px', fontWeight: 600, color: 'var(--success)', marginBottom: '8px' }}>
                    ✓ {txResult.message}
                  </p>
                  <label className="form-label" style={{ marginBottom: '2px' }}>
                    Transaction Hash:
                  </label>
                  <div className="copy-box" style={{ background: '#ffffff' }}>
                    <span className="text-mono" style={{ fontSize: '12px' }}>{txResult.txHash}</span>
                    <button
                      type="button"
                      className="copy-btn"
                      onClick={() => copyToClipboard(txResult.txHash)}
                    >
                      {copied ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <div style={{ marginTop: '10px' }}>
                    <a
                      href={`https://testnet.mstscan.com/tx/${txResult.txHash}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="btn btn-outline btn-sm"
                      style={{ display: 'inline-flex', width: 'auto', gap: '4px', textDecoration: 'none' }}
                    >
                      View on MSTScan Explorer ↗
                    </a>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Bottom Section: Transaction History & Hashes */}
          <div style={{ marginTop: '28px', borderTop: '1px solid var(--border-color)', paddingTop: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <h3 style={{ fontSize: '15px', fontWeight: 600, margin: 0, color: 'var(--text-main)' }}>
                Recent Transactions (MST Testnet)
              </h3>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                {transactions.length} transaction{transactions.length === 1 ? '' : 's'} recorded
              </span>
            </div>

            {transactions.length === 0 ? (
              <div style={{ padding: '16px', background: '#f9fafb', borderRadius: '4px', textAlign: 'center' }}>
                <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0 }}>
                  No transactions recorded yet. Click <strong>"Use Sample Address"</strong> and <strong>"Sign & Broadcast Transaction"</strong> to generate your first transaction hash!
                </p>
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table className="tx-table">
                  <thead>
                    <tr>
                      <th>Tx Hash</th>
                      <th>Recipient</th>
                      <th>Amount</th>
                      <th>Timestamp</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {transactions.map((tx, idx) => {
                      const hash = tx.tx_hash || (tx as any).txHash || '';
                      const toAddr = tx.to_address || (tx as any).toAddress || '';
                      const createdAt = tx.created_at || (tx as any).createdAt || '';
                      return (
                        <tr key={hash || idx}>
                          <td className="text-mono" style={{ fontSize: '12px' }}>
                            {hash ? (
                              <a
                                href={`https://testnet.mstscan.com/tx/${hash}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                style={{ color: 'var(--accent)', textDecoration: 'none', fontWeight: 500 }}
                                title="View on MSTScan Explorer"
                              >
                                {hash.length > 18 ? `${hash.slice(0, 10)}...${hash.slice(-8)}` : hash} ↗
                              </a>
                            ) : (
                              'Pending'
                            )}
                          </td>
                          <td className="text-mono" style={{ fontSize: '12px' }}>
                            <span title={toAddr}>
                              {toAddr.length > 14 ? `${toAddr.slice(0, 8)}...${toAddr.slice(-6)}` : toAddr}
                            </span>
                          </td>
                          <td style={{ fontWeight: 500, fontSize: '13px' }}>
                            {tx.amount} MSTC
                          </td>
                          <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                            {createdAt ? new Date(createdAt).toLocaleString('en-IN', {
                              dateStyle: 'short',
                              timeStyle: 'short',
                            }) : '-'}
                          </td>
                          <td>
                            <div style={{ display: 'flex', gap: '6px' }}>
                              {hash && (
                                <>
                                  <button
                                    type="button"
                                    className="copy-btn"
                                    onClick={() => copyTxHash(hash)}
                                  >
                                    {copiedHash === hash ? 'Copied' : 'Copy'}
                                  </button>
                                  <a
                                    href={`https://testnet.mstscan.com/tx/${hash}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="copy-btn"
                                    style={{ textDecoration: 'none', color: 'inherit' }}
                                  >
                                    Explorer ↗
                                  </a>
                                </>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
