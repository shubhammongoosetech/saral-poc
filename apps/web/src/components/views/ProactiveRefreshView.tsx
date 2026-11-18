import React, { useState } from 'react';
import { apiService } from '../../services/api';

export const ProactiveRefreshView: React.FC = () => {
  const [epoch, setEpoch] = useState<number>(1);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [notice, setNotice] = useState<string>('');

  const handleRefresh = async () => {
    setRefreshing(true);
    setNotice('');
    try {
      await apiService.requestProactiveRefresh({
        committeeId: 'saral-global-15',
        k: 5,
        t: 4,
      });
      setEpoch((prev) => prev + 1);
      setNotice(`Proactive refresh completed! Transitioned to Epoch τ=${epoch + 1}. Previous epoch shares were cryptographically erased.`);
    } catch (err: any) {
      setNotice(`Refresh failed: ${err.message}`);
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <div style={{ maxWidth: '800px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div>
        <h2 style={{ fontSize: '20px', fontWeight: 700, margin: '0 0 4px 0', color: '#f8fafc' }}>
          Asynchronous Proactive Share Refresh
        </h2>
        <p style={{ margin: 0, fontSize: '13px', color: '#94a3b8' }}>
          Cachin et al. (ACM CCS 2002) — Periodic share rotation with secret invariance and forward secrecy.
        </p>
      </div>

      <div style={{
        backgroundColor: '#111827',
        border: '1px solid #1f2937',
        borderRadius: '10px',
        padding: '24px',
        display: 'flex',
        flexDirection: 'column',
        gap: '20px',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '12px', color: '#94a3b8' }}>Current Epoch</div>
            <div style={{ fontSize: '32px', fontWeight: 800, color: '#fbbf24' }}>
              τ = {epoch}
            </div>
          </div>
          <span style={{
            fontSize: '11px',
            fontWeight: 700,
            padding: '4px 12px',
            borderRadius: '9999px',
            backgroundColor: 'rgba(16, 185, 129, 0.2)',
            color: '#34d399',
            border: '1px solid #10b981',
          }}>
            ● ACTIVE & SYNCHRONIZED
          </span>
        </div>

        <div style={{
          padding: '16px',
          backgroundColor: '#0c121e',
          borderRadius: '8px',
          border: '1px solid #1e293b',
          fontSize: '12px',
          color: '#cbd5e1',
          lineHeight: '1.5',
        }}>
          💡 <strong style={{ color: '#ffffff' }}>How Proactive Refresh Protects Wallets:</strong> Each node shares a random zero-sum polynomial. Honest nodes aggregate refreshed shares x_j(τ+1). Even if an adversary compromises up to t nodes across different time epochs, old and new shares cannot be combined, maintaining perpetual forward secrecy without changing the master public key or wallet addresses.
        </div>

        {notice && (
          <div style={{
            padding: '12px',
            borderRadius: '6px',
            backgroundColor: notice.includes('failed') ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)',
            border: `1px solid ${notice.includes('failed') ? '#ef4444' : '#10b981'}`,
            color: notice.includes('failed') ? '#f87171' : '#34d399',
            fontSize: '12px',
          }}>
            {notice}
          </div>
        )}

        <button
          onClick={handleRefresh}
          disabled={refreshing}
          style={{
            padding: '12px 24px',
            backgroundColor: '#7c3aed',
            color: '#ffffff',
            border: 'none',
            borderRadius: '6px',
            fontWeight: 600,
            fontSize: '13px',
            cursor: refreshing ? 'not-allowed' : 'pointer',
            opacity: refreshing ? 0.7 : 1,
            alignSelf: 'flex-start',
          }}
        >
          {refreshing ? 'Executing Subprotocol AVSS & Agreement...' : '⚡ Trigger Asynchronous Proactive Refresh'}
        </button>
      </div>
    </div>
  );
};
