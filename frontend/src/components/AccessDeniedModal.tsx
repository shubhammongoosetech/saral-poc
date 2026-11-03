import React from 'react';

interface AccessDeniedModalProps {
  isOpen: boolean;
  reason: string;
  details?: {
    currentTime?: string;
    allowedWindow?: string;
    currentDistanceKm?: number;
    maxRadiusKm?: number;
  };
  onRetry: () => void;
  onLogout: () => void;
  retrying?: boolean;
}

export const AccessDeniedModal: React.FC<AccessDeniedModalProps> = ({
  isOpen,
  reason,
  details,
  onRetry,
  onLogout,
  retrying = false,
}) => {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true">
      <div className="modal-content">
        <div className="modal-badge-danger">
          ⚠️
        </div>

        <h2 className="modal-title">Access Denied: Outside Working Policy</h2>
        <p className="modal-subtitle">
          Your session was authenticated, but access is blocked because you are outside your registered working hours or location perimeter.
        </p>

        <div className="alert alert-danger" style={{ marginBottom: '16px' }}>
          <p style={{ fontWeight: 600, marginBottom: '4px' }}>Policy Gate Violation</p>
          <p style={{ fontSize: '13px' }}>{reason || 'Access outside permitted working hours or geographic boundaries.'}</p>

          {(details?.allowedWindow || details?.maxRadiusKm !== undefined) && (
            <div className="modal-details-grid">
              {details.currentTime && details.allowedWindow && (
                <div className="modal-detail-box">
                  <span className="label">Current Time / Window</span>
                  <span className="value">{details.currentTime} ({details.allowedWindow})</span>
                </div>
              )}
              {details.currentDistanceKm !== undefined && details.maxRadiusKm !== undefined && (
                <div className="modal-detail-box">
                  <span className="label">Distance / Allowed Radius</span>
                  <span className="value">{details.currentDistanceKm} km / {details.maxRadiusKm} km</span>
                </div>
              )}
            </div>
          )}
        </div>

        <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '20px' }}>
          SARAL non-custodial protection blocks wallet operations and access outside your designated work schedule and physical radius.
        </p>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            type="button"
            className="btn btn-outline"
            onClick={onLogout}
            disabled={retrying}
          >
            Logout
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={onRetry}
            disabled={retrying}
          >
            {retrying ? 'Checking Policy...' : 'Retry Verification'}
          </button>
        </div>
      </div>
    </div>
  );
};

