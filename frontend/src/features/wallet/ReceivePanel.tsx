import React, { useState } from 'react';
import { Card } from '@/shared/ui/Card';
import { Tabs } from '@/shared/ui/Tabs';
import { CopyButton } from '@/shared/ui/CopyButton';
import { Badge } from '@/shared/ui/Badge';

export interface ReceivePanelProps {
  address?: string;
  solanaAddress?: string;
  onClose?: () => void;
}

export const ReceivePanel: React.FC<ReceivePanelProps> = ({
  address = '',
  solanaAddress = '',
}) => {
  const [network, setNetwork] = useState<'mst-testnet' | 'solana-devnet'>('mst-testnet');

  const activeAddress = network === 'solana-devnet' ? solanaAddress : address;

  return (
    <Card className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-text">Receive</h2>
        <Badge variant="testnet">Testnet</Badge>
      </div>

      <Tabs
        tabs={[
          { id: 'mst-testnet', label: 'MST Testnet' },
          { id: 'solana-devnet', label: 'Solana Devnet' },
        ]}
        activeTab={network}
        onChange={(id) => setNetwork(id as 'mst-testnet' | 'solana-devnet')}
      />

      <div className="flex flex-col gap-1.5">
        <span className="text-[13px] font-medium text-muted">Address</span>
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
