import React, { useState } from 'react';
import { apiService } from '../../services/api';

interface SettingsViewProps {
  coordUrl: string;
  authUrl: string;
  onUpdateCoordUrl: (url: string) => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  coordUrl,
  authUrl,
  onUpdateCoordUrl,
}) => {
  const [currentCoord, setCurrentCoord] = useState<string>(coordUrl);
  const [tokenMsg, setTokenMsg] = useState<string>('');
  const [tokenLoading, setTokenLoading] = useState<boolean>(false);

  const handleSave = () => {
    onUpdateCoordUrl(currentCoord);
    apiService.setCoordinatorUrl(currentCoord);
    alert('Coordinator endpoint updated successfully');
  };

  const handleIssueToken = async () => {
    setTokenLoading(true);
    setTokenMsg('');
    try {
      const token = await apiService.authenticate('dev-operator', 'admin');
      setTokenMsg(`Successfully obtained RS256 JWT (${token.substring(0, 32)}...)`);
    } catch (err: any) {
      setTokenMsg(`Failed to issue token: ${err.message}`);
    } finally {
      setTokenLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: '700px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div>
        <h2 style={{ fontSize: '20px', fontWeight: 700, margin: '0 0 4px 0', color: '#f8fafc' }}>
          Environment & System Settings
        </h2>
        <p style={{ margin: 0, fontSize: '13px', color: '#94a3b8' }}>
          Configure cluster coordinator endpoints, authentication credentials, and verifier tokens.
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
        <div>
          <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
            Active Coordinator JSON-RPC Endpoint
          </label>
          <div style={{ display: 'flex', gap: '10px' }}>
            <input
              type="text"
              value={currentCoord}
              onChange={(e) => setCurrentCoord(e.target.value)}
              style={{
                flex: 1,
                padding: '10px 14px',
                backgroundColor: '#0c121e',
                border: '1px solid #334155',
                borderRadius: '6px',
                color: '#f8fafc',
                fontSize: '13px',
                fontFamily: 'monospace',
              }}
            />
            <button
              onClick={handleSave}
              style={{
                padding: '10px 18px',
                backgroundColor: '#2563eb',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                fontSize: '13px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Save
            </button>
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '6px' }}>
            Default Foundation: http://localhost:9001, Public: http://localhost:9002, Private: http://localhost:9003
          </div>
        </div>

        <div style={{ borderTop: '1px solid #1f2937', paddingTop: '16px' }}>
          <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
            Auth Server Endpoint (RS256 JWT Issuer)
          </label>
          <input
            type="text"
            readOnly
            value={authUrl}
            style={{
              width: '100%',
              padding: '10px 14px',
              backgroundColor: '#0c121e',
              border: '1px solid #334155',
              borderRadius: '6px',
              color: '#94a3b8',
              fontSize: '13px',
              fontFamily: 'monospace',
            }}
          />
        </div>

        <div>
          <button
            onClick={handleIssueToken}
            disabled={tokenLoading}
            style={{
              padding: '10px 18px',
              backgroundColor: '#1e293b',
              color: '#38bdf8',
              border: '1px solid #0284c7',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: tokenLoading ? 'not-allowed' : 'pointer',
            }}
          >
            {tokenLoading ? 'Authenticating...' : '🔑 Fetch Fresh Operator Bearer Token'}
          </button>
          {tokenMsg && (
            <div style={{
              marginTop: '10px',
              padding: '10px',
              borderRadius: '4px',
              backgroundColor: '#0c121e',
              fontSize: '11px',
              fontFamily: 'monospace',
              color: tokenMsg.includes('Failed') ? '#f87171' : '#34d399',
            }}>
              {tokenMsg}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
