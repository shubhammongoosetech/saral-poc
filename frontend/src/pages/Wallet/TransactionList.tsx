import React from 'react';

export interface TransactionItem {
  tx_hash: string;
  to_address: string;
  amount: string;
  created_at: string;
  status?: string;
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

                return (
                  <tr key={hash || idx}>
                    <td className="muted">{formattedDate}</td>
                    <td className="text-mono" title={toAddr}>
                      {shortTo}
                    </td>
                    <td>{tx.amount} MSTC</td>
                    <td>
                      {tx.status === 'BROADCASTED' && hash ? (
                        <a
                          href={`https://testnet.mstscan.com/tx/${hash}`}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Confirmed ↗
                        </a>
                      ) : tx.status && tx.status.toUpperCase().includes('FAILED') ? (
                        <span className="status-failed">Failed</span>
                      ) : !tx.status && hash ? (
                        <a
                          href={`https://testnet.mstscan.com/tx/${hash}`}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
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

export default TransactionList;
