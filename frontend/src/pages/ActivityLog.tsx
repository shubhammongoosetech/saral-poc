import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { apiClient as api } from '../api/client';

interface UnifiedActivity {
  id: string;
  timestamp: string;
  whatHappened: string;
  result: string;
}

const PAGE_SIZE_OPTIONS = [10, 20, 50];

/**
 * Computes compact page numbers with ellipsis markers ('...') for pagination UI.
 */
function buildPageNumbers(currentPage: number, totalPages: number): (number | string)[] {
  if (totalPages <= 7) {
    return Array.from({ length: totalPages }, (_, i) => i + 1);
  }
  const pages: (number | string)[] = [1];
  const start = Math.max(2, currentPage - 1);
  const end = Math.min(totalPages - 1, currentPage + 1);

  if (start > 2) pages.push('…-start');
  for (let p = start; p <= end; p++) pages.push(p);
  if (end < totalPages - 1) pages.push('…-end');
  pages.push(totalPages);
  return pages;
}

function humanizeEvent(eventType: string, details?: string): string {
  if (details && (details.includes('Sent') || details.includes('Transfer'))) {
    return details;
  }
  switch (eventType) {
    case 'LOGIN':
    case 'AUTH_LOGIN':
      return 'Signed in';
    case 'LOGOUT':
    case 'AUTH_LOGOUT':
      return 'Signed out';
    case 'WALLET_GENERATED':
    case 'WALLET_CREATED':
      return 'Created wallet';
    case 'TRANSACTION_SIGNED':
    case 'TRANSFER':
      return 'Sent transaction';
    case 'POLICY_UPDATED':
      return 'Updated working hours';
    default:
      return eventType.toLowerCase().replace(/_/g, ' ');
  }
}

function mapAccessEntry(entry: any): UnifiedActivity {
  return {
    id: entry.id,
    timestamp: entry.attemptedAt || entry.timestamp,
    whatHappened: 'Access check',
    result: entry.allowed
      ? 'Allowed'
      : entry.reason
      ? `Blocked: ${entry.reason}`
      : 'Blocked: outside working hours',
  };
}

function mapSecurityEntry(entry: any): UnifiedActivity {
  return {
    id: entry.id,
    timestamp: entry.createdAt || entry.timestamp,
    whatHappened: humanizeEvent(entry.eventType, entry.details),
    result: entry.severity === 'CRITICAL' ? 'Blocked' : 'Success',
  };
}

export const ActivityLog: React.FC = () => {
  const [items, setItems] = useState<UnifiedActivity[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [totalItems, setTotalItems] = useState(0);
  const [totalPages, setTotalPages] = useState(1);

  const fetchLogs = useCallback(async (targetPage: number, targetLimit: number) => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.get('/activity', {
        params: { page: targetPage, limit: targetLimit },
      });

      const serverItems: UnifiedActivity[] = Array.isArray(res.data.items)
        ? res.data.items.map((entry: any) =>
            entry.kind === 'access' ? mapAccessEntry(entry) : mapSecurityEntry(entry)
          )
        : [
            ...(res.data.accessLogs || []).map(mapAccessEntry),
            ...(res.data.securityLogs || []).map(mapSecurityEntry),
          ].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

      const pg = res.data.pagination;
      setItems(serverItems);
      if (pg) {
        setTotalItems(pg.total);
        setTotalPages(Math.max(1, pg.totalPages));
        if (pg.page !== targetPage) {
          setPage(pg.page);
        }
      } else {
        setTotalItems(serverItems.length);
        setTotalPages(1);
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to load activity');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs(page, pageSize);
  }, [fetchLogs, page, pageSize]);

  const currentPage = Math.min(page, totalPages);
  const startIdx = (currentPage - 1) * pageSize;
  const pageNumbers = useMemo(
    () => buildPageNumbers(currentPage, totalPages),
    [currentPage, totalPages]
  );

  return (
    <div className="card card-wide">
      <div className="inline-row" style={{ marginBottom: 16 }}>
        <h1 className="page-title" style={{ marginBottom: 0 }}>Activity</h1>
        <button
          type="button"
          className="btn-link helper-text"
          onClick={() => fetchLogs(currentPage, pageSize)}
          disabled={loading}
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {loading ? (
        <p className="muted text-center">Loading activity...</p>
      ) : totalItems === 0 ? (
        <p className="muted text-center">No activity yet.</p>
      ) : (
        <>
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>What happened</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id}>
                    <td className="muted">
                      {new Date(item.timestamp).toLocaleString(undefined, {
                        dateStyle: 'short',
                        timeStyle: 'short',
                      })}
                    </td>
                    <td>{item.whatHappened}</td>
                    <td>{item.result}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pagination-bar">
            <div className="pagination-info">
              <span>
                Showing {startIdx + 1}–{Math.min(startIdx + pageSize, totalItems)} of {totalItems}
              </span>
              <select
                aria-label="Rows per page"
                className="pagination-select"
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(1);
                }}
              >
                {PAGE_SIZE_OPTIONS.map((size) => (
                  <option key={size} value={size}>
                    {size} / page
                  </option>
                ))}
              </select>
            </div>

            {totalPages > 1 && (
              <div className="pagination-controls">
                <button
                  type="button"
                  className="btn-page"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                >
                  Prev
                </button>
                {pageNumbers.map((p) =>
                  typeof p === 'string' ? (
                    <span key={p} className="muted pagination-ellipsis">
                      …
                    </span>
                  ) : (
                    <button
                      key={p}
                      type="button"
                      className={`btn-page${p === currentPage ? ' active' : ''}`}
                      onClick={() => setPage(p)}
                    >
                      {p}
                    </button>
                  )
                )}
                <button
                  type="button"
                  className="btn-page"
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                >
                  Next
                </button>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};
