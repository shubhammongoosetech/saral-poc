import React, { useState, useEffect } from 'react';
import { walletApi } from '../../api/endpoints';
import { getCurrentCoords } from '../../hooks/useLocation';
import { CopyButton } from '../../components/CopyButton';

interface SendFormProps {
  onSent: () => void;
  activeNetwork?: 'mst-testnet' | 'solana-devnet' | 'polygon-amoy';
  onNetworkChange?: (network: 'mst-testnet' | 'solana-devnet' | 'polygon-amoy') => void;
  balance?: string;
  solanaBalance?: string;
  resetTrigger?: number;
}

export const SendForm: React.FC<SendFormProps> = ({
  onSent,
  activeNetwork,
  onNetworkChange,
  balance,
  solanaBalance,
  resetTrigger,
}) => {
  const [internalChain, setInternalChain] = useState<'mst-testnet' | 'solana-devnet' | 'polygon-amoy'>('mst-testnet');
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);
  const [explorerUrl, setExplorerUrl] = useState<string | null>(null);

  const chain = activeNetwork || internalChain;
  const setChain = (nextChain: 'mst-testnet' | 'solana-devnet' | 'polygon-amoy') => {
    setInternalChain(nextChain);
    onNetworkChange?.(nextChain);
  };

  const isSolana = chain === 'solana-devnet';
  const currencySymbol = isSolana ? 'SOL' : chain === 'polygon-amoy' ? 'MATIC' : 'MSTC';

  // Clear error, input fields, and old transaction status on manual Refresh
  useEffect(() => {
    if (resetTrigger && resetTrigger > 0) {
      setTo('');
      setAmount('');
      setError(null);
      setTxHash(null);
      setExplorerUrl(null);
    }
  }, [resetTrigger]);

  // Clear error, input fields, and transaction status when switching network
  useEffect(() => {
    setTo('');
    setAmount('');
    setError(null);
    setTxHash(null);
    setExplorerUrl(null);
  }, [chain]);

  const handleMaxClick = () => {
    const rawBalance = isSolana ? solanaBalance || '0' : balance || '0';
    const numBalance = parseFloat(rawBalance);
    if (isNaN(numBalance) || numBalance <= 0) {
      setAmount('0');
      return;
    }

    // Reserve network gas/fee so transaction does not fail due to insufficient funds:
    // Solana Devnet fee: 5000 lamports (reserve 0.00001 SOL buffer)
    // Polygon Amoy gas fee: ~0.005 MATIC
    // MST Testnet gas fee: ~0.0005 MSTC
    const feeReserve = isSolana ? 0.00001 : chain === 'polygon-amoy' ? 0.005 : 0.0005;

    const maxSendable = Math.max(0, numBalance - feeReserve);
    if (maxSendable <= 0) {
      setAmount('0');
      setError(`Balance is too low to cover network gas fee (~${feeReserve} ${currencySymbol}).`);
      return;
    }

    const formatted = isSolana
      ? maxSendable.toFixed(6).replace(/\.?0+$/, '')
      : maxSendable.toFixed(4).replace(/\.?0+$/, '');

    setAmount(formatted);
    setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (isSolana) {
      const base58Regex = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
      if (!base58Regex.test(to.trim())) {
        setError('Please enter a valid Solana address (Base58, e.g. 4Nd1mBQtr...)');
        return;
      }
    } else {
      if (!to.trim().startsWith('0x') || to.trim().length !== 42) {
        setError('Please enter a valid EVM address (0x...)');
        return;
      }
    }

    if (!amount || parseFloat(amount) <= 0) {
      setError('Please enter a valid amount');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      setTxHash(null);
      setExplorerUrl(null);

      const coords = await getCurrentCoords();
      const res = await walletApi.signTransaction({
        chain,
        toAddress: to.trim(),
        amount: amount.trim(),
        lat: coords.lat,
        lng: coords.lng,
      });

      if (res.broadcasted === false) {
        setError(res.message || 'Transaction broadcast was rejected by the blockchain node.');
        onSent();
        return;
      }

      setTxHash(res.txHash);
      setExplorerUrl(res.explorerUrl || (isSolana ? `https://explorer.solana.com/tx/${res.txHash}?cluster=devnet` : `https://testnet.mstscan.com/tx/${res.txHash}`));
      setTo('');
      setAmount('');
      onSent();
    } catch (err: any) {
      setError(err.response?.data?.error || err.response?.data?.message || 'Transaction failed');
      if (err.response?.data?.txHash) {
        onSent();
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="field">
      <h2 className="section-title">Send</h2>

      {error && <div className="alert alert-error">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div className="field">
          <label className="label" htmlFor="chainSelect">
            Network
          </label>
          <select
            id="chainSelect"
            className="input"
            value={chain}
            onChange={(e) => {
              setChain(e.target.value as any);
              setError(null);
              setTo('');
            }}
            disabled={loading}
          >
            <option value="mst-testnet">MST Testnet (MSTC)</option>
            <option value="solana-devnet">Solana Devnet (SOL)</option>
            <option value="polygon-amoy">Polygon Amoy (MATIC)</option>
          </select>
        </div>

        <div className="field">
          <label className="label" htmlFor="recipientInput">
            {isSolana ? 'To (Solana Base58 Address)' : 'To (EVM Address)'}
          </label>
          <input
            id="recipientInput"
            type="text"
            className="input text-mono"
            placeholder={isSolana ? 'e.g. 4Nd1mBQtrMJVYVfKf2PJy9NZPdde5VUkrMaD4W1U4q69' : '0x...'}
            value={to}
            onChange={(e) => setTo(e.target.value)}
            disabled={loading}
            required
          />
        </div>

        <div className="field">
          <div className="inline-row" style={{ marginBottom: '6px' }}>
            <label className="label" htmlFor="amountInput" style={{ margin: 0 }}>
              Amount ({currencySymbol})
            </label>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="helper-text muted" style={{ fontSize: '12px' }}>
                Bal: {isSolana ? solanaBalance || '0.00' : balance || '0.00'} {currencySymbol}
              </span>
              <button
                type="button"
                className="btn-link helper-text"
                style={{ fontWeight: 600, textTransform: 'uppercase', color: 'var(--accent)', cursor: 'pointer' }}
                onClick={handleMaxClick}
                disabled={loading}
              >
                Max
              </button>
            </div>
          </div>
          <input
            id="amountInput"
            type="text"
            className="input text-mono"
            placeholder="0.00"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            disabled={loading}
            required
          />
          <span className="helper-text muted" style={{ display: 'block', marginTop: '4px', fontSize: '11px' }}>
            {isSolana
              ? 'Estimated network fee (~0.000005 SOL) is automatically deducted'
              : 'Estimated gas fee is automatically deducted from max send'}
          </span>
        </div>

        <button
          type="submit"
          className="btn btn-primary"
          disabled={loading || !to.trim() || !amount.trim()}
        >
          {loading ? 'Signing via 3-Domain MPC...' : `Send ${currencySymbol}`}
        </button>
      </form>

      {txHash && (
        <div className="send-result">
          <div className="inline-row">
            <span>
              <strong>Sent!</strong>{' '}
              <a
                href={explorerUrl || `https://testnet.mstscan.com/tx/${txHash}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                View transaction ↗
              </a>
            </span>
          </div>
          <div className="send-tx-row">
            <span className="muted">Tx Hash:</span>
            <span className="text-mono send-tx-hash" title={txHash}>
              {txHash}
            </span>
            <CopyButton text={txHash} ariaLabel="Copy transaction hash" />
          </div>
        </div>
      )}
    </div>
  );
};

