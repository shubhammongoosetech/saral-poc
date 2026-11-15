import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { walletApi } from '@/shared/api/endpoints';
import { useWalletQuery, useTransactionsQuery, usePostSendPolling } from './useWalletQueries';
import { useBreakpoint } from '@/shared/hooks/useBreakpoint';
import { SendPanel, type SendChain } from './SendPanel';
import { ReceivePanel } from './ReceivePanel';
import { Card } from '@/shared/ui/Card';
import { Button } from '@/shared/ui/Button';
import { Badge } from '@/shared/ui/Badge';
import { Skeleton } from '@/shared/ui/Skeleton';
import { Alert } from '@/shared/ui/Alert';
import { EmptyState } from '@/shared/ui/EmptyState';
import { Sheet, SheetContent } from '@/shared/ui/Sheet';
import { Dialog, DialogContent } from '@/shared/ui/Dialog';
import { Amount } from '@/shared/ui/Amount';
import { AddressText } from '@/shared/ui/AddressText';
import { formatRelativeTime } from '@/shared/lib/format';
import { IconSend, IconReceive, IconRefresh } from '@/shared/ui/icons';

export const Wallet: React.FC = () => {
  const { isDesktop } = useBreakpoint();
  const { data: walletData, isLoading, refetch, isRefetching } = useWalletQuery();
  const { data: txData, refetch: refetchTxs } = useTransactionsQuery();
  const { triggerPostSendPolling } = usePostSendPolling();

  const [activeNetwork, setActiveNetwork] = useState<SendChain>('mst-testnet');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Mobile modal state
  const [showSendModal, setShowSendModal] = useState(false);
  const [showReceiveModal, setShowReceiveModal] = useState(false);

  const wallet = walletData?.wallet;
  const hasWallet = walletData?.hasWallet;
  const transactions = txData?.transactions || [];

  const handleRefreshAll = async () => {
    await Promise.all([refetch(), refetchTxs()]);
  };

  const handleCreateWallet = async () => {
    try {
      setCreating(true);
      setError(null);
      await walletApi.generateWallet();
      await handleRefreshAll();
    } catch {
      setError('Failed to create wallet');
    } finally {
      setCreating(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex flex-col gap-6 w-full max-w-4xl mx-auto">
        <Skeleton className="h-40 w-full rounded-2xl" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Skeleton className="h-64 rounded-xl" />
          <Skeleton className="h-64 rounded-xl" />
        </div>
      </div>
    );
  }

  if (!hasWallet) {
    return (
      <div className="w-full max-w-sm mx-auto py-16 flex flex-col items-center gap-4">
        {error && <Alert variant="error">{error}</Alert>}
        <Button onClick={handleCreateWallet} loading={creating}>
          Create wallet
        </Button>
      </div>
    );
  }

  const mstcBalance = wallet?.balance || '0.0000';
  const solBalance = wallet?.solanaBalance || '0.0000';
  const evmAddress = wallet?.address || '';
  const solAddress = wallet?.solanaAddress || '';

  return (
    <div className="flex flex-col gap-6 w-full max-w-5xl mx-auto">
      {error && <Alert variant="error">{error}</Alert>}

      {/* Hero Balance Card */}
      <Card className="flex flex-col gap-5 p-6 bg-surface border-border">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">
              Balance
            </span>
            <Badge variant="testnet">Testnet</Badge>
          </div>
          <button
            type="button"
            onClick={handleRefreshAll}
            disabled={isRefetching}
            className="p-1.5 rounded-lg text-muted hover:text-text hover:bg-surface-2 transition-colors"
            title="Refresh balance"
            aria-label="Refresh balance"
          >
            <IconRefresh className={isRefetching ? 'animate-spin' : ''} size={16} />
          </button>
        </div>

        {/* Primary and Secondary Balances */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="flex flex-col gap-1 p-4 rounded-xl bg-surface-2 border border-border">
            <span className="text-xs text-muted font-medium">MST Testnet</span>
            <Amount value={mstcBalance} symbol="MSTC" className="text-2xl" />
            <AddressText address={evmAddress} copyable className="mt-1 text-muted" />
          </div>

          <div className="flex flex-col gap-1 p-4 rounded-xl bg-surface-2 border border-border">
            <span className="text-xs text-muted font-medium">Solana Devnet</span>
            <Amount value={solBalance} symbol="SOL" className="text-2xl" />
            <AddressText address={solAddress} copyable className="mt-1 text-muted" />
          </div>
        </div>

        {/* Quick Actions (Send & Receive) */}
        <div className="flex gap-3">
          <Button
            variant="primary"
            className="flex-1 gap-2"
            onClick={() => setShowSendModal(true)}
          >
            <IconSend size={16} />
            <span>Send</span>
          </Button>
          <Button
            variant="secondary"
            className="flex-1 gap-2"
            onClick={() => setShowReceiveModal(true)}
          >
            <IconReceive size={16} />
            <span>Receive</span>
          </Button>
        </div>
      </Card>

      {/* Main Content Grid: Desktop 2-column or Mobile stacked */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Recent Activity (Desktop 7 cols, Mobile 12 cols) */}
        <div className="lg:col-span-7 flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-text">Recent activity</h2>
            <Link to="/activity" className="text-xs text-accent hover:underline">
              View all
            </Link>
          </div>

          {transactions.length === 0 ? (
            <EmptyState title="No transactions yet" />
          ) : (
            <Card className="divide-y divide-border p-0 overflow-hidden">
              {transactions.slice(0, 5).map((tx) => (
                <div key={tx.tx_hash} className="flex items-center justify-between p-3.5 text-xs">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-7 h-7 rounded-full bg-surface-2 flex items-center justify-center text-muted">
                      {tx.direction === 'received' ? <IconReceive size={14} /> : <IconSend size={14} />}
                    </div>
                    <div className="flex flex-col min-w-0">
                      <span className="font-medium text-text truncate">
                        {tx.direction === 'received' ? 'Received' : 'Sent'}
                      </span>
                      <span className="text-[11px] text-muted font-mono truncate">
                        {tx.to_address ? `${tx.to_address.slice(0, 6)}...${tx.to_address.slice(-4)}` : ''}
                      </span>
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-0.5">
                    <span className="font-mono font-medium text-text">
                      {tx.amount} {tx.chain === 'solana-devnet' ? 'SOL' : 'MSTC'}
                    </span>
                    <span className="text-[10px] text-muted">{formatRelativeTime(tx.created_at)}</span>
                  </div>
                </div>
              ))}
            </Card>
          )}
        </div>

        {/* Right Column: Inline Send (Desktop 5 cols) */}
        {isDesktop && (
          <div className="lg:col-span-5 flex flex-col gap-4">
            <SendPanel
              balance={mstcBalance}
              solanaBalance={solBalance}
              activeNetwork={activeNetwork}
              onNetworkChange={setActiveNetwork}
              onSent={triggerPostSendPolling}
            />
          </div>
        )}
      </div>

      {/* Mobile/Tablet Send Modal */}
      {!isDesktop && (
        <Sheet open={showSendModal} onOpenChange={setShowSendModal}>
          <SheetContent side="bottom">
            <SendPanel
              balance={mstcBalance}
              solanaBalance={solBalance}
              activeNetwork={activeNetwork}
              onNetworkChange={setActiveNetwork}
              onSent={() => {
                triggerPostSendPolling();
                setShowSendModal(false);
              }}
              onClose={() => setShowSendModal(false)}
            />
          </SheetContent>
        </Sheet>
      )}

      {/* Receive Modal (Desktop & Mobile) */}
      {isDesktop ? (
        <Dialog open={showReceiveModal} onOpenChange={setShowReceiveModal}>
          <DialogContent>
            <ReceivePanel
              address={evmAddress}
              solanaAddress={solAddress}
              onClose={() => setShowReceiveModal(false)}
            />
          </DialogContent>
        </Dialog>
      ) : (
        <Sheet open={showReceiveModal} onOpenChange={setShowReceiveModal}>
          <SheetContent side="bottom">
            <ReceivePanel
              address={evmAddress}
              solanaAddress={solAddress}
              onClose={() => setShowReceiveModal(false)}
            />
          </SheetContent>
        </Sheet>
      )}
    </div>
  );
};

export default Wallet;
