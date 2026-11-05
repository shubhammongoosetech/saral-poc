import React, { useState, useEffect } from 'react';
import { apiClient as api } from '../../api/client';

interface DeviceItem {
  id: string;
  name: string;
  deviceType: string;
  status: string;
  guardianEmail?: string;
}

export const DevicesSection: React.FC = () => {
  const [devices, setDevices] = useState<DeviceItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [isGuardian, setIsGuardian] = useState(false);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [deviceType, setDeviceType] = useState('MOBILE');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchDevices = async () => {
    try {
      setLoading(true);
      const res = await api.get('/devices');
      setDevices(res.data.devices || []);
    } catch {
      // Non-blocking fetch
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDevices();
  }, []);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    try {
      setSubmitting(true);
      setError(null);
      if (isGuardian) {
        if (!email.trim()) {
          setError('Please provide a guardian email');
          return;
        }
        await api.post('/devices/guardian', { name: name.trim(), guardianEmail: email.trim() });
      } else {
        await api.post('/devices/enroll', { name: name.trim(), deviceType });
      }
      setName('');
      setEmail('');
      setShowAdd(false);
      await fetchDevices();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to add');
    } finally {
      setSubmitting(false);
    }
  };

  const handleRevoke = async (id: string, deviceName: string) => {
    if (!window.confirm(`Revoke ${deviceName}?`)) return;
    try {
      await api.delete(`/devices/${id}`);
      await fetchDevices();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to revoke');
    }
  };

  return (
    <div>
      <div className="inline-row section-title">
        <span>Devices and guardians</span>
        <button
          type="button"
          onClick={() => { setShowAdd(!showAdd); setError(null); }}
          className="btn-link helper-text"
        >
          {showAdd ? 'Cancel' : '+ Add'}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {showAdd && (
        <form onSubmit={handleAdd} className="field">
          <div className="grid-2">
            <div className="field">
              <label className="label" htmlFor="holderType">Type</label>
              <select
                id="holderType"
                className="input"
                value={isGuardian ? 'GUARDIAN' : deviceType}
                onChange={(e) => {
                  const val = e.target.value;
                  setIsGuardian(val === 'GUARDIAN');
                  if (val !== 'GUARDIAN') setDeviceType(val);
                }}
              >
                <option value="MOBILE">Mobile phone</option>
                <option value="DESKTOP">Computer</option>
                <option value="HARDWARE_KEY">Hardware key</option>
                <option value="GUARDIAN">Guardian</option>
              </select>
            </div>

            <div className="field">
              <label className="label" htmlFor="holderName">Name</label>
              <input
                id="holderName"
                type="text"
                className="input"
                placeholder="e.g. My Phone"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </div>
          </div>

          {isGuardian && (
            <div className="field">
              <label className="label" htmlFor="guardianEmail">Guardian email</label>
              <input
                id="guardianEmail"
                type="email"
                className="input"
                placeholder="alice@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
          )}

          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'Adding...' : 'Add'}
          </button>
        </form>
      )}

      {loading ? (
        <p className="muted text-center">Loading...</p>
      ) : devices.length === 0 ? (
        <p className="muted text-center">No devices or guardians enrolled.</p>
      ) : (
        <div className="table-wrapper">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.id}>
                  <td>
                    {d.name}
                    {d.guardianEmail && <div className="muted helper-text">{d.guardianEmail}</div>}
                  </td>
                  <td className="muted">{d.deviceType.toLowerCase().replace(/_/g, ' ')}</td>
                  <td>{d.status === 'ACTIVE' ? 'Active' : d.status}</td>
                  <td>
                    {d.status === 'ACTIVE' && (
                      <button
                        type="button"
                        onClick={() => handleRevoke(d.id, d.name)}
                        className="btn-link helper-text"
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default DevicesSection;
