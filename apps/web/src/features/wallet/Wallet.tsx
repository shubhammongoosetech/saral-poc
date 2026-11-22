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
import { formatRelativeTime, truncateAddress, getExplorerTxUrl, mapApiError } from '@/shared/lib/format';
import { IconReceive, IconRefresh, IconExternal } from '@/shared/ui/icons';

export const Wallet: React.FC = () => {
  const { isDesktop } = useBreakpoint();
  const { data: walletData, error: walletError, isLoading, isError, refetch, isRefetching } = useWalletQuery();
  const wallet = walletData?.wallet;
  const walletReady = !isError && walletData?.hasWallet === true && wallet?.status === 'READY';
  const { data: txData, error: txError, refetch: refetchTxs } = useTransactionsQuery(walletReady);

  const [creating, setCreating] = useState(false);
  const [creationError, setCreationError] = useState<string | null>(null);

  // Receive modal state
  const [showReceiveModal, setShowReceiveModal] = useState(false);

  const transactions = txData?.transactions || [];

  const handleRefreshAll = async () => {
    await Promise.all([refetch(), refetchTxs()]);
  };

  const handleCreateWallet = async () => {
    setCreating(true);
    setCreationError(null);
    try {
      await walletApi.generateWallet();
    } catch (error: unknown) {
      const message = error instanceof DOMException && error.name === 'AbortError'
        ? 'Wallet setup is taking longer than expected. Check its status before trying again.'
        : mapApiError(error, 'Unable to complete wallet setup.');
      setCreationError(message);
    } finally {
      await refetch();
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

  const walletMissing = walletData?.hasWallet === false && walletData.wallet === null;
  const setupInProgress = wallet?.status === 'DKG_IN_PROGRESS';
  const setupCanResume = wallet?.status === 'KEY_READY';
  const setupFailed = wallet?.status === 'ERROR';

  if (!isError && wallet?.status === 'UNAVAILABLE') {
    return (
      <Card className="w-full max-w-md mx-auto flex flex-col gap-4 p-6">
        <h1 className="text-lg font-semibold text-text">Wallet unavailable</h1>
        <Alert variant="error">{wallet.error || 'This wallet needs migration before it can be used.'}</Alert>
      </Card>
    );
  }

  if (!creating && (isError || !(walletMissing || walletReady || setupInProgress || setupCanResume || setupFailed))) {
    return (
      <Card className="w-full max-w-md mx-auto flex flex-col gap-4 p-6">
        <h1 className="text-lg font-semibold text-text">Unable to load wallet</h1>
        <Alert variant="error">{mapApiError(walletError, 'Check your access or try again.')}</Alert>
        <Button variant="secondary" onClick={() => refetch()} loading={isRefetching}>
          Reload Wallet
        </Button>
      </Card>
    );
  }

  if (creating || !walletReady) {
    return (
      <Card className="w-full max-w-md mx-auto flex flex-col gap-4 p-6">
        <h1 className="text-lg font-semibold text-text">Wallet setup</h1>
        {(creationError || wallet?.error) && (
          <Alert variant="error">{creationError || wallet?.error}</Alert>
        )}
        {creating || setupInProgress ? (
          <>
            <p role="status" className="text-sm text-muted">Wallet setup is in progress.</p>
            {!creating && (
              <div className="flex flex-wrap gap-2">
                <Button onClick={handleCreateWallet}>Resume Wallet Setup</Button>
                <Button variant="secondary" onClick={() => refetch()} loading={isRefetching}>
                  Check Status
                </Button>
              </div>
            )}
          </>
        ) : (
          <>
            <p className="text-sm text-muted">
              {walletMissing ? 'Create a wallet for MST, Solana, and Bitcoin test networks.' : 'Finish setting up your wallet.'}
            </p>
            <Button onClick={handleCreateWallet} disabled={isRefetching}>
              {walletMissing ? 'Create Wallet' : setupCanResume ? 'Finish Wallet Setup' : 'Retry Wallet Setup'}
            </Button>
          </>
        )}
      </Card>
    );
  }

  const mstcBalance = wallet?.chains?.mst?.balance ?? wallet?.balance ?? null;
  const solBalance = wallet?.chains?.solana?.balance ?? wallet?.solanaBalance ?? null;
  const btcBalance = wallet?.chains?.bitcoin?.balance ?? wallet?.bitcoinBalance ?? null;

  const evmAddress = wallet?.chains?.mst?.address || wallet?.address || wallet?.addresses?.mst || '';
  const solAddress = wallet?.chains?.solana?.address || wallet?.solanaAddress || wallet?.addresses?.solana || '';
  const btcAddress = wallet?.chains?.bitcoin?.address || wallet?.bitcoinAddress || wallet?.addresses?.bitcoin || '';
  const canReceive = Boolean(evmAddress && solAddress && btcAddress);

  return (
    <div className="flex flex-col gap-6 w-full max-w-5xl mx-auto">
      {!canReceive && (
        <Alert variant="error" className="w-full">
          <div className="flex items-center justify-between">
            <span>Unable to load all receive addresses.</span>
            <Button size="sm" variant="secondary" onClick={handleRefreshAll} loading={isRefetching}>
              Retry Derivation
            </Button>
          </div>
        </Alert>
      )}

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
              disabled={!canReceive}
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
              <Amount value={mstcBalance} symbol="MSTC" decimals={18} className="text-2xl mt-1" />
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
              <Amount value={solBalance} symbol="SOL" decimals={9} className="text-2xl mt-1" />
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
              <Amount value={btcBalance} symbol="BTC" decimals={8} className="text-2xl mt-1" />
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

        {txError ? (
          <Alert variant="error">{mapApiError(txError, 'Unable to load recent activity.')}</Alert>
        ) : transactions.length === 0 ? (
          <EmptyState title="No transactions detected on testnets yet" description="Send MSTC, SOL or Testnet BTC to your receive addresses above to see live incoming balances." />
        ) : (
          <Card className="divide-y divide-border p-0 overflow-hidden">
            {transactions.slice(0, 6).map((tx) => {
              const hash = tx.tx_hash || tx.txHash || '';
              const explorerUrl = getExplorerTxUrl(tx.chain, hash);
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
