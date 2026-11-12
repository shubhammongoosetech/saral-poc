import React, { useState } from 'react';
import { walletApi } from '../../api/endpoints';
import { getCurrentCoords } from '../../hooks/useLocation';

interface SendFormProps {
  onSent: () => void;
}

export const SendForm: React.FC<SendFormProps> = ({ onSent }) => {
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);
  const [explorerUrl, setExplorerUrl] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!to.trim().startsWith('0x') || to.trim().length !== 42) {
      setError('Please enter a valid recipient address (0x...)');
      return;
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
        toAddress: to.trim(),
        amount: amount.trim(),
        lat: coords.lat,
        lng: coords.lng,
      });

      if (res.broadcasted === false) {
        setError(res.message || 'Transaction broadcast was rejected by the blockchain node.');
        return;
      }

      setTxHash(res.txHash);
      setExplorerUrl(res.explorerUrl || `https://testnet.mstscan.com/tx/${res.txHash}`);
      setTo('');
      setAmount('');
      onSent();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Transaction failed');
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
          <label className="label" htmlFor="recipientInput">
            To
          </label>
          <input
            id="recipientInput"
            type="text"
            className="input text-mono"
            placeholder="0x..."
            value={to}
            onChange={(e) => setTo(e.target.value)}
            disabled={loading}
            required
          />
        </div>

        <div className="field">
          <label className="label" htmlFor="amountInput">
            Amount
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
          {loading ? 'Sending...' : 'Send'}
        </button>
      </form>

      {txHash && (
        <div className="send-result">
          <span>Sent! </span>
          <a
            href={explorerUrl || `https://testnet.mstscan.com/tx/${txHash}`}
            target="_blank"
            rel="noopener noreferrer"
          >
            View transaction ↗
          </a>
        </div>
      )}
    </div>
  );
};

export default SendForm;

