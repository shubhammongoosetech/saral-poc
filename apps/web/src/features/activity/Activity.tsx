import React, { useState, useMemo } from 'react';
import { useTransactionsQuery } from '@/features/wallet/useWalletQueries';
import { Card } from '@/shared/ui/Card';
import { Alert } from '@/shared/ui/Alert';
import { Button } from '@/shared/ui/Button';
import { Badge } from '@/shared/ui/Badge';
import { Skeleton } from '@/shared/ui/Skeleton';
import { EmptyState } from '@/shared/ui/EmptyState';
import { CopyButton } from '@/shared/ui/CopyButton';
import { formatRelativeTime, truncateAddress, getExplorerTxUrl, mapApiError } from '@/shared/lib/format';
import { IconSend, IconReceive, IconExternal } from '@/shared/ui/icons';

export const Activity: React.FC = () => {
  const { data, error, isLoading, isRefetching, refetch } = useTransactionsQuery();
  const [filter, setFilter] = useState<'all' | 'sent' | 'received'>('all');

  const filtered = useMemo(() => {
    const transactions = data?.transactions || [];
    if (filter === 'all') return transactions;
    if (filter === 'sent') return transactions.filter((t) => t.direction !== 'received');
    if (filter === 'received') return transactions.filter((t) => t.direction === 'received');
    return transactions;
  }, [data?.transactions, filter]);

  if (isLoading) {
    return (
      <div className="flex flex-col gap-4 w-full max-w-4xl mx-auto">
        <Skeleton className="h-8 w-32" />
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-72 w-full" />
      </div>
    );
  }

  if (error) {
    return (
      <Card className="w-full max-w-md mx-auto flex flex-col gap-4 p-6">
        <h1 className="text-lg font-semibold text-text">Unable to load activity</h1>
        <Alert variant="error">{mapApiError(error, 'Check your access or try again.')}</Alert>
        <Button variant="secondary" onClick={() => refetch()} loading={isRefetching}>Reload Activity</Button>
      </Card>
    );
  }

  return (
    <div className="flex flex-col gap-6 w-full max-w-4xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <h1 className="text-xl font-semibold text-text">Activity</h1>

        {/* Filter Chips */}
        <div className="inline-flex p-1 rounded-lg bg-surface-2 border border-border">
          {(['all', 'sent', 'received'] as const).map((key) => {
            const labels = { all: 'All', sent: 'Sent', received: 'Received' };
            const isActive = filter === key;
            return (
              <button
                key={key}
                type="button"
                onClick={() => setFilter(key)}
                className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                  isActive
                    ? 'bg-surface text-text shadow-xs font-semibold'
                    : 'text-muted hover:text-text'
                }`}
              >
                {labels[key]}
              </button>
            );
          })}
        </div>
      </div>

      {filtered.length === 0 ? (
        <EmptyState title="No transactions yet" />
      ) : (
        <Card className="p-0 overflow-hidden">
          {/* Desktop Data Table (hidden on small screens) */}
          <div className="hidden md:block overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-border bg-surface-2/50 text-muted">
                  <th className="py-3 px-4 font-medium">Type</th>
                  <th className="py-3 px-4 font-medium">Tx Hash</th>
                  <th className="py-3 px-4 font-medium">To / From</th>
                  <th className="py-3 px-4 font-medium">Amount</th>
                  <th className="py-3 px-4 font-medium">Status</th>
                  <th className="py-3 px-4 font-medium text-right">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filtered.map((tx) => {
                  const hash = tx.tx_hash || tx.txHash || '';
                  const explorerUrl = getExplorerTxUrl(tx.chain, hash);
                  const isRecv = tx.direction === 'received';
                  const isPending = !tx.status || tx.status.toLowerCase() === 'pending';
                  const isFailed = tx.status?.toLowerCase().includes('fail');
                  const badgeVariant = isFailed ? 'failed' : isPending ? 'pending' : 'confirmed';
                  const badgeLabel = isFailed ? 'Failed' : isPending ? 'Pending' : 'Confirmed';

                  return (
                    <tr key={hash || tx.created_at} className="hover:bg-surface-2/40 transition-colors">
                      <td className="py-3.5 px-4 font-medium text-text">
                        <div className="flex items-center gap-2">
                          <div className="w-6 h-6 rounded-full bg-surface-2 flex items-center justify-center text-muted">
                            {isRecv ? <IconReceive size={13} /> : <IconSend size={13} />}
                          </div>
                          <span>{isRecv ? 'Received' : 'Sent'}</span>
                        </div>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-muted">
                        {hash ? (
                          <div className="flex items-center gap-1.5">
                            <a
                              href={explorerUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-accent hover:underline flex items-center gap-1 group font-mono"
                              title="Verify on explorer"
                            >
                              <span>{truncateAddress(hash, 6, 4)}</span>
                              <IconExternal size={13} className="opacity-70 group-hover:opacity-100 transition-opacity" />
                            </a>
                            <CopyButton text={hash} />
                          </div>
                        ) : (
                          <span className="text-muted">—</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-muted">
                        <div className="flex items-center gap-1.5">
                          <span>{truncateAddress(tx.to_address || tx.toAddress || '', 6, 4)}</span>
                          {(tx.to_address || tx.toAddress) && <CopyButton text={tx.to_address || tx.toAddress || ''} />}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 font-mono font-medium text-text">
                        {tx.amount} {tx.chain === 'solana-devnet' ? 'SOL' : 'MSTC'}
                      </td>
                      <td className="py-3.5 px-4">
                        <Badge variant={badgeVariant} dot={isPending}>
                          {badgeLabel}
                        </Badge>
                      </td>
                      <td className="py-3.5 px-4 text-right text-muted">
                        {formatRelativeTime(tx.created_at || tx.createdAt || '')}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Mobile List View (visible on small screens) */}
          <div className="block md:hidden divide-y divide-border">
            {filtered.map((tx) => {
              const hash = tx.tx_hash || tx.txHash || '';
              const explorerUrl = getExplorerTxUrl(tx.chain, hash);
              const isRecv = tx.direction === 'received';
              const isPending = !tx.status || tx.status.toLowerCase() === 'pending';
              const isFailed = tx.status?.toLowerCase().includes('fail');
              const badgeVariant = isFailed ? 'failed' : isPending ? 'pending' : 'confirmed';
              const badgeLabel = isFailed ? 'Failed' : isPending ? 'Pending' : 'Confirmed';

              return (
                <div key={hash || tx.created_at} className="flex items-center justify-between p-3.5 text-xs">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-7 h-7 rounded-full bg-surface-2 flex items-center justify-center text-muted shrink-0">
                      {isRecv ? <IconReceive size={14} /> : <IconSend size={14} />}
                    </div>
                    <div className="flex flex-col min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="font-medium text-text">
                          {isRecv ? 'Received' : 'Sent'}
                        </span>
                        <Badge variant={badgeVariant} size="sm" dot={isPending}>
                          {badgeLabel}
                        </Badge>
                      </div>
                      <span className="text-[11px] text-muted font-mono truncate">
                        {isRecv ? 'From: ' : 'To: '}{truncateAddress(tx.to_address || tx.toAddress || '', 4, 4)}
                      </span>
                      {hash && (
                        <div className="flex items-center gap-1 mt-0.5">
                          <a
                            href={explorerUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[11px] font-mono text-accent hover:underline flex items-center gap-1"
                            title="Verify on explorer"
                          >
                            <span>Tx: {truncateAddress(hash, 4, 4)}</span>
                            <IconExternal size={11} />
                          </a>
                          <CopyButton text={hash} />
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-0.5 shrink-0 ml-2">
                    <span className="font-mono font-medium text-text">
                      {tx.amount} {tx.chain === 'solana-devnet' ? 'SOL' : 'MSTC'}
                    </span>
                    <span className="text-[10px] text-muted">{formatRelativeTime(tx.created_at || tx.createdAt || '')}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      )}
    </div>
  );
};

export default Activity;
