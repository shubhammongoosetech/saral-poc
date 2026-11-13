import React, { useState } from 'react';

interface WalletHeaderProps {
  address: string;
  balance: string;
  solanaAddress?: string;
  solanaBalance?: string;
  activeNetwork?: 'mst-testnet' | 'solana-devnet';
  onNetworkChange?: (network: 'mst-testnet' | 'solana-devnet') => void;
  onRefresh: () => void;
  refreshing: boolean;
}

export const WalletHeader: React.FC<WalletHeaderProps> = ({
  address,
  balance,
  solanaAddress,
  solanaBalance,
  activeNetwork,
  onNetworkChange,
  onRefresh,
  refreshing,
}) => {
  const [localNetwork, setLocalNetwork] = useState<'mst-testnet' | 'solana-devnet'>('mst-testnet');
  const [copied, setCopied] = useState(false);

  const network = activeNetwork || localNetwork;
  const isSolana = network === 'solana-devnet';

  const setNetwork = (nextNetwork: 'mst-testnet' | 'solana-devnet') => {
    setLocalNetwork(nextNetwork);
    onNetworkChange?.(nextNetwork);
  };

  const currentAddress = isSolana && solanaAddress ? solanaAddress : address;
  const currentBalance = isSolana ? solanaBalance || '0.0000' : balance;
  const currentSymbol = isSolana ? 'SOL' : 'MSTC';

  const shortAddress =
    currentAddress.length > 14
      ? `${currentAddress.slice(0, 6)}...${currentAddress.slice(-4)}`
      : currentAddress;

  const handleCopy = () => {
    if (currentAddress) {
      navigator.clipboard.writeText(currentAddress);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="wallet-balance-box">
      {/* Network Switcher Tabs */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '14px' }}>
        <button
          type="button"
          className={`btn btn-sm ${!isSolana ? 'btn-primary' : 'btn-outline'}`}
          onClick={() => setNetwork('mst-testnet')}
        >
          MST Testnet (EVM)
        </button>
        <button
          type="button"
          className={`btn btn-sm ${isSolana ? 'btn-primary' : 'btn-outline'}`}
          onClick={() => setNetwork('solana-devnet')}
        >
          Solana Devnet (SOL)
        </button>
      </div>

      <div className="inline-row">
        <div className="wallet-address-row">
          <span className="text-mono muted" title={currentAddress}>
            {shortAddress}
          </span>
          <button type="button" onClick={handleCopy} className="btn-link helper-text">
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          className="btn-link helper-text"
          disabled={refreshing}
        >
          {refreshing ? 'Updating...' : 'Refresh'}
        </button>
      </div>

      <div className="balance-amount">
        {currentBalance} {currentSymbol}
      </div>
    </div>
  );
};
