import React, { useState, useEffect } from 'react';
import { apiClient as api } from '../../api/client';

interface ActiveRecovery {
  requestId: string;
  state: string;
  timelockExpiresAt: string;
  reason: string;
}

export const RecoverySection: React.FC = () => {
  const [activeRequest, setActiveRequest] = useState<ActiveRecovery | null>(null);
  const [remainingSeconds, setRemainingSeconds] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [reason, setReason] = useState('Lost primary device');
  const [hours, setHours] = useState(48);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const fetchRecovery = async () => {
    try {
      setLoading(true);
      const res = await api.get('/wallet/recovery/logs');
      const logs = res.data.logs || [];
      const req = [...logs].reverse().find((l: any) => l.eventType === 'RECOVERY_REQUESTED');
      const cancel = [...logs].reverse().find((l: any) => l.eventType === 'RECOVERY_CANCELLED_BY_USER');
      const exec = [...logs].reverse().find((l: any) => l.eventType === 'RECOVERY_MPC_EXECUTED');

      if (req) {
        const id = req.details.requestId;
        const isCancelled = cancel && cancel.details.requestId === id;
        const isExecuted = exec && exec.details.requestId === id;
        if (!isCancelled && !isExecuted) {
          setActiveRequest({
            requestId: id,
            state: 'PENDING_TIMELOCK',
            timelockExpiresAt: req.details.timelockExpiresAt,
            reason: req.details.reason || 'Emergency recovery',
          });
        } else {
          setActiveRequest(null);
        }
      } else {
        setActiveRequest(null);
      }
    } catch {
      // Non-blocking fetch
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRecovery();
  }, []);

  useEffect(() => {
    if (!activeRequest || activeRequest.state !== 'PENDING_TIMELOCK') {
      setRemainingSeconds(null);
      return;
    }
    const update = () => {
      const now = Date.now();
      const expiry = new Date(activeRequest.timelockExpiresAt).getTime();
      setRemainingSeconds(Math.max(0, Math.floor((expiry - now) / 1000)));
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, [activeRequest]);

  const handleStart = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSubmitting(true);
      setError(null);
      await api.post('/wallet/recovery/initiate', { reason, timelockHours: hours });
      setMessage('Recovery started. Timelock protection is active.');
      setShowForm(false);
      await fetchRecovery();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to start recovery');
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancel = async () => {
    if (!activeRequest) return;
    try {
      setSubmitting(true);
      setError(null);
      await api.post('/wallet/recovery/cancel', { requestId: activeRequest.requestId, reason: 'Cancelled by user' });
      setMessage('Recovery request cancelled.');
      await fetchRecovery();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to cancel recovery');
    } finally {
      setSubmitting(false);
    }
  };

  const formatRemaining = (sec: number | null) => {
    if (sec === null) return '';
    return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m ${sec % 60}s`;
  };

  return (
    <div>
      <h2 className="section-title">Recovery</h2>

      {error && <div className="alert alert-error">{error}</div>}
      {message && <div className="alert alert-success">{message}</div>}

      {loading ? (
        <p className="muted text-center">Checking recovery status...</p>
      ) : activeRequest ? (
        <div className="field">
          <div className="two-column-list">
            <div className="two-column-item">
              <span className="label-col">Status</span>
              <span className="value-col">Timelock waiting period</span>
            </div>
            <div className="two-column-item">
              <span className="label-col">Time remaining</span>
              <span className="value-col text-mono">{formatRemaining(remainingSeconds)}</span>
            </div>
            <div className="two-column-item">
              <span className="label-col">Reason</span>
              <span className="value-col">{activeRequest.reason}</span>
            </div>
          </div>

          <button
            type="button"
            onClick={handleCancel}
            className="btn btn-outline btn-danger"
            disabled={submitting}
          >
            {submitting ? 'Cancelling...' : 'Cancel recovery'}
          </button>
        </div>
      ) : showForm ? (
        <form onSubmit={handleStart} className="field">
          <div className="field">
            <label className="label" htmlFor="recoveryReason">Reason</label>
            <input
              id="recoveryReason"
              type="text"
              className="input"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              required
            />
          </div>

          <div className="field">
            <label className="label" htmlFor="recoveryHours">Waiting period (hours)</label>
            <input
              id="recoveryHours"
              type="number"
              min={1}
              max={168}
              className="input text-mono"
              value={hours}
              onChange={(e) => setHours(parseInt(e.target.value, 10) || 48)}
              required
            />
          </div>

          <div className="actions-row">
            <button type="button" className="btn btn-outline" onClick={() => setShowForm(false)}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? 'Starting...' : 'Start recovery'}
            </button>
          </div>
        </form>
      ) : (
        <div className="inline-row">
          <span className="muted">No active recovery request.</span>
          <button type="button" onClick={() => setShowForm(true)} className="btn btn-outline btn-sm">
            Start recovery
          </button>
        </div>
      )}
    </div>
  );
};

export default RecoverySection;
