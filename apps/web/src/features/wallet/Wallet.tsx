import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { walletApi } from '@/shared/api/endpoints';
import { useWalletQuery, useTransactionsQuery } from './useWalletQueries';
import { useBreakpoint } from '@/shared/hooks/useBreakpoint';
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
import { formatRelativeTime, truncateAddress, getExplorerTxUrl } from '@/shared/lib/format';
import { IconReceive, IconRefresh, IconExternal } from '@/shared/ui/icons';

const DKG_STEPS = [
  'Node Quorum Reached (15/15 Active)',
  'Kate-Huang-Goldberg AVSS Started',
  'Pedersen Bivariate Commitments Verified',
  'Randomized ABBA Consensus Reached',
  'Threshold Public Keys Derived (Y = xG)',
  'Multi-Chain Address Derivation (MST, SOL, BTC)',
  'Local Node Vault Persistence (AES-256-GCM)',
  'Wallet Identity Cryptographically Bound',
];

export const Wallet: React.FC = () => {
  const { isDesktop } = useBreakpoint();
  const { data: walletData, isLoading, refetch, isRefetching } = useWalletQuery();
  const { data: txData, refetch: refetchTxs } = useTransactionsQuery();

  const [creating, setCreating] = useState(false);
  const [currentDkgStep, setCurrentDkgStep] = useState(0);
  const [error, setError] = useState<string | null>(null);

  // Receive modal state
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
      setCurrentDkgStep(0);

      // Multi-step progress animation while DKG runs
      const stepInterval = setInterval(() => {
        setCurrentDkgStep((prev) => (prev < DKG_STEPS.length - 1 ? prev + 1 : prev));
      }, 350);

      await walletApi.generateWallet();
      clearInterval(stepInterval);
      setCurrentDkgStep(DKG_STEPS.length);
      await handleRefreshAll();
    } catch (err: any) {
      setError(err?.message || 'Failed to create distributed wallet');
    } finally {
      setCreating(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex flex-col gap-6 w-full max-w-4xl mx-auto">
        <Skeleton className="h-40 w-full rounded-2xl" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Skeleton className="h-44 rounded-xl" />
          <Skeleton className="h-44 rounded-xl" />
          <Skeleton className="h-44 rounded-xl" />
        </div>
      </div>
    );
  }

  // Before Wallet Creation: Clean Centered Card
  if (!hasWallet) {
    return (
      <div className="w-full max-w-md mx-auto py-12 flex flex-col items-center gap-6">
        <div className="w-16 h-16 rounded-2xl bg-accent/10 text-accent flex items-center justify-center font-bold text-2xl select-none">
          S
        </div>

        <div className="text-center">
          <h1 className="text-xl font-bold text-text tracking-tight mb-2">
            SARAL Key Infrastructure
          </h1>
          <p className="text-xs text-muted max-w-sm mx-auto leading-relaxed">
            Your cryptographic keys will be generated collaboratively across 15 independent nodes using Dealerless Kate-Huang-Goldberg DKG. No single party ever holds your private keys.
          </p>
        </div>

        {error && <Alert variant="error">{error}</Alert>}

        {creating ? (
          <Card className="w-full flex flex-col gap-3 p-5 bg-surface border-border">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <span className="text-xs font-semibold text-text">Dealerless DKG in Progress</span>
              <span className="text-[11px] font-mono text-accent animate-pulse">Running...</span>
            </div>
            <div className="flex flex-col gap-2 py-1">
              {DKG_STEPS.map((step, idx) => (
                <div key={step} className="flex items-center gap-2.5 text-xs">
                  <div
                    className={`w-3.5 h-3.5 rounded-full flex items-center justify-center text-[9px] shrink-0 ${
                      idx <= currentDkgStep
                        ? 'bg-accent text-accent-contrast'
                        : 'bg-surface-2 text-muted border border-border'
                    }`}
                  >
                    {idx <= currentDkgStep ? '✓' : idx + 1}
                  </div>
                  <span
                    className={
                      idx <= currentDkgStep ? 'text-text font-medium' : 'text-muted'
                    }
                  >
                    {step}
                  </span>
                </div>
              ))}
            </div>
          </Card>
        ) : (
          <Button onClick={handleCreateWallet} loading={creating} size="lg" className="w-full max-w-xs">
            Create Wallet
          </Button>
        )}
      </div>
    );
  }

  const mstcBalance = wallet?.balance || '0.0000';
  const solBalance = wallet?.solanaBalance || '0.0000';
  const btcBalance = wallet?.bitcoinBalance || '0.00000000';

  const evmAddress = wallet?.address || wallet?.addresses?.mst || '';
  const solAddress = wallet?.solanaAddress || wallet?.addresses?.solana || '';
  const btcAddress = wallet?.bitcoinAddress || wallet?.addresses?.bitcoin || '';

  return (
    <div className="flex flex-col gap-6 w-full max-w-5xl mx-auto">
      {error && <Alert variant="error">{error}</Alert>}

      {/* Top Hero Balance Header */}
      <Card className="flex flex-col gap-5 p-6 bg-surface border-border">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">
              SARAL Multi-Chain Wallet
            </span>
            <Badge variant="testnet">Testnet Live</Badge>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowReceiveModal(true)}
              className="gap-1.5 text-xs"
            >
              <IconReceive size={14} />
              <span>Receive / QR</span>
            </Button>
            <button
              type="button"
              onClick={handleRefreshAll}
              disabled={isRefetching}
              className="p-1.5 rounded-lg text-muted hover:text-text hover:bg-surface-2 transition-colors"
              title="Refresh balances"
              aria-label="Refresh balances"
            >
              <IconRefresh className={isRefetching ? 'animate-spin' : ''} size={16} />
            </button>
          </div>
        </div>

        {/* The Three Required Address Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Card 1: MST Testnet */}
          <div className="flex flex-col justify-between p-4 rounded-xl bg-surface-2 border border-border">
            <div className="flex flex-col gap-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-text">MST Testnet</span>
                <span className="text-[10px] font-mono text-muted bg-surface px-1.5 py-0.5 rounded border border-border">
                  EVM
                </span>
              </div>
              <Amount value={mstcBalance} symbol="MSTC" className="text-2xl mt-1" />
            </div>
            <div className="mt-3 pt-2 border-t border-border/60">
              <span className="text-[10px] uppercase font-semibold text-muted block mb-0.5">Receive Address</span>
              <AddressText address={evmAddress} copyable className="text-muted text-[11px]" />
            </div>
          </div>

          {/* Card 2: Solana Devnet */}
          <div className="flex flex-col justify-between p-4 rounded-xl bg-surface-2 border border-border">
            <div className="flex flex-col gap-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-text">Solana Devnet</span>
                <span className="text-[10px] font-mono text-muted bg-surface px-1.5 py-0.5 rounded border border-border">
                  Ed25519
                </span>
              </div>
              <Amount value={solBalance} symbol="SOL" className="text-2xl mt-1" />
            </div>
            <div className="mt-3 pt-2 border-t border-border/60">
              <span className="text-[10px] uppercase font-semibold text-muted block mb-0.5">Receive Address</span>
              <AddressText address={solAddress} copyable className="text-muted text-[11px]" />
            </div>
          </div>

          {/* Card 3: Bitcoin Testnet */}
          <div className="flex flex-col justify-between p-4 rounded-xl bg-surface-2 border border-border">
            <div className="flex flex-col gap-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-text">Bitcoin Testnet</span>
                <span className="text-[10px] font-mono text-muted bg-surface px-1.5 py-0.5 rounded border border-border">
                  Taproot
                </span>
              </div>
              <Amount value={btcBalance} symbol="BTC" className="text-2xl mt-1" />
            </div>
            <div className="mt-3 pt-2 border-t border-border/60">
              <span className="text-[10px] uppercase font-semibold text-muted block mb-0.5">Receive Address</span>
              <AddressText address={btcAddress} copyable className="text-muted text-[11px]" />
            </div>
          </div>
        </div>
      </Card>

      {/* Recent Activity List */}
      <div className="flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-text">Recent Activity (Incoming)</h2>
          <Link to="/activity" className="text-xs text-accent hover:underline">
            View all
          </Link>
        </div>

        {transactions.length === 0 ? (
          <EmptyState title="No transactions detected on testnets yet" description="Send MSTC, SOL or Testnet BTC to your receive addresses above to see live incoming balances." />
        ) : (
          <Card className="divide-y divide-border p-0 overflow-hidden">
            {transactions.slice(0, 6).map((tx) => {
              const hash = tx.tx_hash || tx.txHash || '';
              const explorerUrl =
                (tx as any).explorerUrl || getExplorerTxUrl(tx.chain, hash);
              const symbol =
                tx.chain === 'solana-devnet'
                  ? 'SOL'
                  : tx.chain === 'bitcoin-testnet'
                  ? 'BTC'
                  : 'MSTC';

              return (
                <div key={hash || tx.created_at} className="flex items-center justify-between p-3.5 text-xs">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-7 h-7 rounded-full bg-accent/10 text-accent flex items-center justify-center shrink-0">
                      <IconReceive size={14} />
                    </div>
                    <div className="flex flex-col min-w-0">
                      <span className="font-medium text-text truncate">
                        Received {symbol}
                      </span>
                      <div className="flex items-center gap-2 text-[11px] text-muted font-mono flex-wrap">
                        {hash && (
                          <a
                            href={explorerUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-accent hover:underline flex items-center gap-0.5"
                            title="Verify on explorer"
                          >
                            <span>Tx: {truncateAddress(hash, 6, 6)}</span>
                            <IconExternal size={11} />
                          </a>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-0.5 shrink-0 ml-2">
                    <span className="font-mono font-medium text-text">
                      +{tx.amount} {symbol}
                    </span>
                    <span className="text-[10px] text-muted">{formatRelativeTime(tx.created_at)}</span>
                  </div>
                </div>
              );
            })}
          </Card>
        )}
      </div>

      {/* Receive Modal (Desktop & Mobile) */}
      {isDesktop ? (
        <Dialog open={showReceiveModal} onOpenChange={setShowReceiveModal}>
          <DialogContent>
            <ReceivePanel
              address={evmAddress}
              solanaAddress={solAddress}
              bitcoinAddress={btcAddress}
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
              bitcoinAddress={btcAddress}
              onClose={() => setShowReceiveModal(false)}
            />
          </SheetContent>
        </Sheet>
      )}
    </div>
  );
};

export default Wallet;
