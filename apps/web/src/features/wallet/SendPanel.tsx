import React, { useState } from 'react';
import { walletApi } from '@/shared/api/endpoints';
import { getExplorerTxUrl, mapApiError } from '@/shared/lib/format';
import { Card } from '@/shared/ui/Card';
import { Button } from '@/shared/ui/Button';
import { Input } from '@/shared/ui/Input';
import { Field } from '@/shared/ui/Field';
import { Select } from '@/shared/ui/Select';
import { Alert } from '@/shared/ui/Alert';
import { CopyButton } from '@/shared/ui/CopyButton';

export type SendChain = 'mst-testnet' | 'solana-devnet' | 'polygon-amoy';

export interface SendPanelProps {
  balance?: string;
  solanaBalance?: string;
  activeNetwork?: SendChain;
  onNetworkChange?: (net: SendChain) => void;
  onSent?: () => void;
  onClose?: () => void;
}

export const SendPanel: React.FC<SendPanelProps> = ({
  balance = '0.0000',
  solanaBalance = '0.0000',
  activeNetwork = 'mst-testnet',
  onNetworkChange,
  onSent,
}) => {
  const [network, setNetwork] = useState<SendChain>(activeNetwork);
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('');
  const [toError, setToError] = useState<string | null>(null);
  const [amountError, setAmountError] = useState<string | null>(null);

  const [isConfirming, setIsConfirming] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);

  const isSolana = network === 'solana-devnet';
  const isPolygon = network === 'polygon-amoy';
  const currencySymbol = isSolana ? 'SOL' : isPolygon ? 'MATIC' : 'MSTC';
  const currentBalance = isSolana ? solanaBalance : balance;
  const estimatedFee = isSolana ? '0.000005 SOL' : isPolygon ? '0.005 MATIC' : '0.0005 MSTC';

  const handleNetworkChange = (val: SendChain) => {
    setNetwork(val);
    onNetworkChange?.(val);
    setTo('');
    setAmount('');
    setToError(null);
    setAmountError(null);
    setError(null);
    setTxHash(null);
    setIsConfirming(false);
  };

  const handleMax = () => {
    const num = parseFloat(currentBalance);
    if (isNaN(num) || num <= 0) {
      setAmount('0');
      return;
    }
    const reserve = isSolana ? 0.00001 : isPolygon ? 0.005 : 0.0005;
    const maxVal = Math.max(0, num - reserve);
    setAmount(isSolana ? maxVal.toFixed(6) : maxVal.toFixed(4));
    setAmountError(null);
  };

  const validate = (): boolean => {
    let valid = true;
    setToError(null);
    setAmountError(null);

    const cleanTo = to.trim();
    if (!cleanTo) {
      setToError('Recipient required');
      valid = false;
    } else if (isSolana) {
      if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(cleanTo)) {
        setToError('Invalid Solana address (Base58, 32-44 characters)');
        valid = false;
      }
    } else {
      if (!/^0x[a-fA-F0-9]{40}$/.test(cleanTo)) {
        setToError('Invalid EVM address (0x format, 42 characters)');
        valid = false;
      }
    }

    const numAmount = parseFloat(amount.trim());
    const numBal = parseFloat(currentBalance);
    if (!amount.trim() || isNaN(numAmount) || numAmount <= 0) {
      setAmountError('Enter a valid amount');
      valid = false;
    } else if (numAmount > numBal) {
      setAmountError(`Exceeds balance (${currentBalance} ${currencySymbol})`);
      valid = false;
    }

    return valid;
  };

  const handleReview = (e: React.FormEvent) => {
    e.preventDefault();
    if (validate()) {
      setIsConfirming(true);
    }
  };

  const handleSend = async () => {
    try {
      setSubmitting(true);
      setError(null);
      const res = await walletApi.signTransaction({
        chain: network,
        toAddress: to.trim(),
        amount: amount.trim(),
      });

      if (!res.broadcasted || !res.txHash) throw new Error('Unable to confirm transaction broadcast.');
      setTxHash(res.txHash);
      onSent?.();
    } catch (err: unknown) {
      setError(mapApiError(err, 'Transaction failed'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleReset = () => {
    setTo('');
    setAmount('');
    setToError(null);
    setAmountError(null);
    setError(null);
    setTxHash(null);
    setIsConfirming(false);
  };

  // Render Post-Broadcast Success State
  if (txHash) {
    const explorerUrl = getExplorerTxUrl(network, txHash);
    return (
      <Card className="flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-text">Transaction sent</h2>
        </div>
        <Alert variant="success">Transaction broadcasted successfully.</Alert>
        <div className="flex flex-col gap-1.5 p-3 rounded-lg bg-surface-2 border border-border text-xs">
          <span className="text-muted font-medium">Transaction hash</span>
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-xs text-text break-all select-all">{txHash}</span>
            <CopyButton text={txHash} />
          </div>
        </div>
        {explorerUrl && (
          <a
            href={explorerUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-accent hover:underline text-center"
          >
            View on explorer
          </a>
        )}
        <Button variant="secondary" onClick={handleReset} fullWidth>
          Send another
        </Button>
      </Card>
    );
  }

  // Render Confirmation Step with Highlighted First/Last Address Characters
  if (isConfirming) {
    const cleanTo = to.trim();
    const startPart = cleanTo.slice(0, 6);
    const middlePart = cleanTo.slice(6, -4);
    const endPart = cleanTo.slice(-4);

    return (
      <Card className="flex flex-col gap-4">
        <h2 className="text-sm font-semibold text-text">Confirm transaction</h2>

        {error && <Alert variant="error">{error}</Alert>}

        <div className="divide-y divide-border rounded-lg border border-border bg-surface-2 p-0 overflow-hidden text-xs">
          <div className="flex justify-between items-center p-3">
            <span className="text-muted font-medium">Network</span>
            <span className="text-text font-medium">
              {network === 'solana-devnet'
                ? 'Solana Devnet'
                : network === 'polygon-amoy'
                ? 'Polygon Amoy'
                : 'MST Testnet'}
            </span>
          </div>

          <div className="flex flex-col gap-1 p-3">
            <span className="text-muted font-medium">To</span>
            <div className="font-mono text-xs break-all bg-surface p-2 rounded border border-border">
              <span className="font-bold text-accent">{startPart}</span>
              <span className="text-muted opacity-80">{middlePart}</span>
              <span className="font-bold text-accent">{endPart}</span>
            </div>
          </div>

          <div className="flex justify-between items-center p-3">
            <span className="text-muted font-medium">Amount</span>
            <span className="text-text font-mono font-semibold">
              {amount} {currencySymbol}
            </span>
          </div>

          <div className="flex justify-between items-center p-3">
            <span className="text-muted font-medium">Estimated fee</span>
            <span className="text-muted font-mono">{estimatedFee}</span>
          </div>
        </div>

        <div className="flex gap-2">
          <Button
            type="button"
            variant="secondary"
            onClick={() => setIsConfirming(false)}
            disabled={submitting}
            className="flex-1"
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="primary"
            onClick={handleSend}
            loading={submitting}
            disabled={submitting}
            className="flex-1"
          >
            Confirm & Send
          </Button>
        </div>
      </Card>
    );
  }

  // Render Input Form Step
  return (
    <Card className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-text">Send</h2>
      </div>

      {error && <Alert variant="error">{error}</Alert>}

      <form onSubmit={handleReview} noValidate className="flex flex-col gap-4">
        <Field label="Network" htmlFor="networkSelect">
          <Select
            id="networkSelect"
            value={network}
            onChange={(e) =>
              handleNetworkChange(e.target.value as SendChain)
            }
            options={[
              { value: 'mst-testnet', label: 'MST Testnet (MSTC)' },
              { value: 'solana-devnet', label: 'Solana Devnet (SOL)' },
              { value: 'polygon-amoy', label: 'Polygon Amoy (MATIC)' },
            ]}
          />
        </Field>

        <Field label="To" htmlFor="toAddress" error={toError || undefined}>
          <Input
            id="toAddress"
            type="text"
            placeholder={isSolana ? 'Solana address' : '0x...'}
            value={to}
            onChange={(e) => {
              setTo(e.target.value);
              if (toError) setToError(null);
            }}
            error={!!toError}
            mono
          />
        </Field>

        <Field
          label="Amount"
          htmlFor="amountInput"
          error={amountError || undefined}
          hint={`Balance: ${currentBalance} ${currencySymbol}`}
        >
          <div className="relative">
            <Input
              id="amountInput"
              type="text"
              inputMode="decimal"
              placeholder="0.00"
              value={amount}
              onChange={(e) => {
                setAmount(e.target.value);
                if (amountError) setAmountError(null);
              }}
              error={!!amountError}
              className="pr-14"
              mono
            />
            <button
              type="button"
              onClick={handleMax}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-xs font-medium text-accent hover:underline px-1.5 py-0.5 rounded"
            >
              Max
            </button>
          </div>
        </Field>

        <Button type="submit" fullWidth disabled={!to.trim() || !amount.trim()}>
          Review
        </Button>
      </form>
    </Card>
  );
};
