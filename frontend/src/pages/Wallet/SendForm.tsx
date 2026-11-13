import React, { useState } from 'react';
import { walletApi } from '../../api/endpoints';
import { getCurrentCoords } from '../../hooks/useLocation';
import { CopyButton } from '../../components/CopyButton';

interface SendFormProps {
  onSent: () => void;
}

export const SendForm: React.FC<SendFormProps> = ({ onSent }) => {
  const [chain, setChain] = useState<'mst-testnet' | 'solana-devnet' | 'polygon-amoy'>('mst-testnet');
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);
  const [explorerUrl, setExplorerUrl] = useState<string | null>(null);

  const isSolana = chain === 'solana-devnet';
  const currencySymbol = isSolana ? 'SOL' : chain === 'polygon-amoy' ? 'MATIC' : 'MSTC';

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
          <label className="label" htmlFor="amountInput">
            Amount ({currencySymbol})
          </label>
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

