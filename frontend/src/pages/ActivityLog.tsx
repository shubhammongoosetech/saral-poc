import React, { useState, useEffect } from 'react';
import { apiClient as api } from '../api/client';

interface UnifiedActivity {
  id: string;
  timestamp: string;
  whatHappened: string;
  result: string;
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
    case 'DEVICE_ENROLLED':
      return 'Added device';
    case 'GUARDIAN_ENROLLED':
      return 'Added guardian';
    case 'RECOVERY_REQUESTED':
      return 'Requested recovery';
    case 'RECOVERY_CANCELLED':
      return 'Cancelled recovery';
    default:
      return eventType.toLowerCase().replace(/_/g, ' ');
  }
}

export const ActivityLog: React.FC = () => {
  const [items, setItems] = useState<UnifiedActivity[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        setLoading(true);
        setError(null);
        const res = await api.get('/activity');

        const access: UnifiedActivity[] = (res.data.accessLogs || []).map((l: any) => ({
          id: l.id,
          timestamp: l.attemptedAt,
          whatHappened: 'Access check',
          result: l.allowed
            ? 'Allowed'
            : l.reason
            ? `Blocked: ${l.reason}`
            : 'Blocked: outside working hours',
        }));

        const security: UnifiedActivity[] = (res.data.securityLogs || []).map((s: any) => ({
          id: s.id,
          timestamp: s.createdAt,
          whatHappened: humanizeEvent(s.eventType, s.details),
          result: s.severity === 'CRITICAL' ? 'Blocked' : 'Success',
        }));

        const combined = [...access, ...security].sort(
          (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
        );

        setItems(combined);
      } catch (err: any) {
        setError(err.response?.data?.error || 'Failed to load activity');
      } finally {
        setLoading(false);
      }
    };

    fetchLogs();
  }, []);

  return (
    <div className="card card-wide">
      <h1 className="page-title">Activity</h1>

      {error && <div className="alert alert-error">{error}</div>}

      {loading ? (
        <p className="muted text-center">Loading activity...</p>
      ) : items.length === 0 ? (
        <p className="muted text-center">No activity yet.</p>
      ) : (
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
      )}
    </div>
  );
};

export default ActivityLog;
