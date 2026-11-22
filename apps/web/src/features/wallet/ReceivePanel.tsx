import React, { useState } from 'react';
import { Card } from '@/shared/ui/Card';
import { Tabs } from '@/shared/ui/Tabs';
import { CopyButton } from '@/shared/ui/CopyButton';
import { Badge } from '@/shared/ui/Badge';
import { QrCode } from '@/shared/ui/QrCode';

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
        <QrCode value={activeAddress} label="Receive address QR code" size={180} />
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
