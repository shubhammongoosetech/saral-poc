import React from 'react';
import { ProtocolEvent } from '../../types';

interface AuditLogsViewProps {
  events: ProtocolEvent[];
  onClear?: () => void;
}

export const AuditLogsView: React.FC<AuditLogsViewProps> = ({ events, onClear }) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 700, margin: '0 0 4px 0', color: '#f8fafc' }}>
            Security Audit Trail & Protocol Telemetry
          </h2>
          <p style={{ margin: 0, fontSize: '13px', color: '#94a3b8' }}>
            Immutable event log tracking P2P probes, DKG executions, and wallet creations.
          </p>
        </div>
        {onClear && (
          <button
            onClick={onClear}
            style={{
              padding: '6px 12px',
              backgroundColor: '#1e293b',
              color: '#94a3b8',
              border: '1px solid #334155',
              borderRadius: '6px',
              fontSize: '12px',
              cursor: 'pointer',
            }}
          >
            Clear Log
          </button>
        )}
      </div>

      <div style={{
        backgroundColor: '#111827',
        border: '1px solid #1f2937',
        borderRadius: '10px',
        overflow: 'hidden',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
          <thead>
            <tr style={{ backgroundColor: '#0c121e', borderBottom: '1px solid #1e293b', color: '#94a3b8' }}>
              <th style={{ padding: '12px 16px', width: '120px' }}>Time</th>
              <th style={{ padding: '12px 16px', width: '100px' }}>Type</th>
              <th style={{ padding: '12px 16px' }}>Event Details</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr>
                <td colSpan={3} style={{ padding: '36px', textAlign: 'center', color: '#64748b' }}>
                  No security audit events recorded.
                </td>
              </tr>
            ) : (
              events.map((ev) => (
                <tr key={ev.id} style={{ borderBottom: '1px solid #1e293b' }}>
                  <td style={{ padding: '12px 16px', fontFamily: 'monospace', color: '#64748b' }}>
                    {ev.time}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: '4px',
                      backgroundColor: ev.type === 'ERROR' ? 'rgba(239, 68, 68, 0.2)' : ev.type === 'WALLET' ? 'rgba(139, 92, 246, 0.2)' : 'rgba(56, 189, 248, 0.2)',
                      color: ev.type === 'ERROR' ? '#f87171' : ev.type === 'WALLET' ? '#a78bfa' : '#38bdf8',
                    }}>
                      {ev.type}
                    </span>
                  </td>
                  <td style={{ padding: '12px 16px', color: '#cbd5e1' }}>
                    {ev.message}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
