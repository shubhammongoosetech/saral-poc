import React from 'react';
import { CopyButton } from '../../components/CopyButton';

export interface TransactionItem {
  tx_hash: string;
  to_address: string;
  amount: string;
  created_at: string;
  status?: string;
  chain?: string;
}

interface TransactionListProps {
  transactions: TransactionItem[];
}

export const TransactionList: React.FC<TransactionListProps> = ({ transactions }) => {
  return (
    <div>
      <h2 className="section-title">Recent transactions</h2>

      {transactions.length === 0 ? (
        <p className="muted text-center">No transactions yet.</p>
      ) : (
        <div className="table-wrapper">
          <table className="table">
            <thead>
              <tr>
                <th>Date</th>
                <th>To</th>
                <th>Amount</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {transactions.map((tx, idx) => {
                const hash = tx.tx_hash || '';
                const toAddr = tx.to_address || '';
                const shortTo =
                  toAddr.length > 12 ? `${toAddr.slice(0, 6)}...${toAddr.slice(-4)}` : toAddr;
                const formattedDate = tx.created_at
                  ? new Date(tx.created_at).toLocaleDateString()
                  : '-';

                const isSolana =
                  tx.chain === 'solana-devnet' ||
                  (!toAddr.startsWith('0x') && toAddr.length >= 32);
                const isPolygon = tx.chain === 'polygon-amoy';
                const currency = isSolana ? 'SOL' : isPolygon ? 'MATIC' : 'MSTC';

                const explorerUrl = isSolana
                  ? `https://explorer.solana.com/tx/${hash}?cluster=devnet`
                  : isPolygon
                  ? `https://amoy.polygonscan.com/tx/${hash}`
                  : `https://testnet.mstscan.com/tx/${hash}`;

                const rowKey = hash || String(idx);

                return (
                  <tr key={rowKey}>
                    <td className="muted">{formattedDate}</td>
                    <td title={toAddr}>
                      <div className="tx-address-cell">
                        <span className="text-mono">{shortTo}</span>
                        {toAddr && <CopyButton text={toAddr} ariaLabel="Copy recipient address" />}
                      </div>
                    </td>
                    <td>
                      {tx.amount} {currency}
                    </td>
                    <td>
                      {tx.status === 'BROADCASTED' && hash ? (
                        <a href={explorerUrl} target="_blank" rel="noopener noreferrer">
                          Confirmed ↗
                        </a>
                      ) : tx.status && tx.status.toUpperCase().includes('FAILED') ? (
                        <span className="status-failed">Failed</span>
                      ) : !tx.status && hash ? (
                        <a href={explorerUrl} target="_blank" rel="noopener noreferrer">
                          Confirmed ↗
                        </a>
                      ) : (
                        <span className="muted">{tx.status || 'Pending'}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
