import React, { useState } from 'react';
import { Card } from '@/shared/ui/Card';
import { Tabs } from '@/shared/ui/Tabs';
import { CopyButton } from '@/shared/ui/CopyButton';
import { Badge } from '@/shared/ui/Badge';

export interface ReceivePanelProps {
  address?: string;
  solanaAddress?: string;
  bitcoinAddress?: string;
  onClose?: () => void;
}

export const ReceivePanel: React.FC<ReceivePanelProps> = ({
  address = '',
  solanaAddress = '',
  bitcoinAddress = '',
}) => {
  const [network, setNetwork] = useState<'mst-testnet' | 'solana-devnet' | 'bitcoin-testnet'>('mst-testnet');

  let activeAddress = address;
  if (network === 'solana-devnet') activeAddress = solanaAddress;
  if (network === 'bitcoin-testnet') activeAddress = bitcoinAddress;

  // Simple QR code representation
  const qrUrl = activeAddress
    ? `https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(activeAddress)}`
    : '';

  return (
    <Card className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-text">Receive Funds</h2>
        <Badge variant="testnet">Testnet</Badge>
      </div>

      <Tabs
        tabs={[
          { id: 'mst-testnet', label: 'MST' },
          { id: 'solana-devnet', label: 'Solana' },
          { id: 'bitcoin-testnet', label: 'Bitcoin' },
        ]}
        activeTab={network}
        onChange={(id) => setNetwork(id as any)}
      />

      {/* QR Code Container */}
      {activeAddress && (
        <div className="flex flex-col items-center justify-center p-4 bg-white rounded-xl border border-border mx-auto">
          <img
            src={qrUrl}
            alt="Address QR Code"
            className="w-40 h-40 object-contain"
            loading="lazy"
          />
          <span className="text-[11px] text-muted mt-2">Scan to send to this address</span>
        </div>
      )}

      <div className="flex flex-col gap-1.5">
        <span className="text-[13px] font-medium text-muted">Receive Address</span>
        <div className="flex items-center justify-between gap-2 p-3 rounded-lg bg-surface-2 border border-border">
          <span className="font-mono text-xs text-text break-all select-all">
            {activeAddress || 'Loading address...'}
          </span>
          <CopyButton text={activeAddress} variant="button" label="Copy" copiedLabel="Copied" />
        </div>
      </div>
    </Card>
  );
};
