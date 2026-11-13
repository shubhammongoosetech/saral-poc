import React, { useState } from 'react';

interface WalletHeaderProps {
  address: string;
  balance: string;
  onRefresh: () => void;
  refreshing: boolean;
}

export const WalletHeader: React.FC<WalletHeaderProps> = ({
  address,
  balance,
  onRefresh,
  refreshing,
}) => {
  const [copied, setCopied] = useState(false);

  const shortAddress =
    address.length > 14 ? `${address.slice(0, 6)}...${address.slice(-4)}` : address;

  const handleCopy = () => {
    navigator.clipboard.writeText(address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="wallet-balance-box">
      <div className="inline-row">
        <div className="wallet-address-row">
          <span className="text-mono muted">{shortAddress}</span>
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

      <div className="balance-amount">{balance} MSTC</div>
    </div>
  );
};

