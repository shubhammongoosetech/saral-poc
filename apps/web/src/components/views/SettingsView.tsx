import React, { useState } from 'react';
import { useSession } from '../../context/SessionContext';
import { authApi } from '../../services/authApi';
import { AppLayout } from '../layout/AppLayout';

const WEEKDAYS = [
  { id: 'MON', label: 'Mon' },
  { id: 'TUE', label: 'Tue' },
  { id: 'WED', label: 'Wed' },
  { id: 'THU', label: 'Thu' },
  { id: 'FRI', label: 'Fri' },
  { id: 'SAT', label: 'Sat' },
  { id: 'SUN', label: 'Sun' },
];

export const SettingsView: React.FC<{ onNavigateToWallet: () => void }> = ({
  onNavigateToWallet,
}) => {
  const { user, policy, savePolicy, refreshSession } = useSession();

  const [timeEnabled, setTimeEnabled] = useState(policy?.timeRestrictionEnabled ?? true);
  const [startTime, setStartTime] = useState(policy?.startTime || '09:00');
  const [endTime, setEndTime] = useState(policy?.endTime || '18:00');
  const [days, setDays] = useState<string[]>(policy?.days || ['MON', 'TUE', 'WED', 'THU', 'FRI']);

  const [locationEnabled, setLocationEnabled] = useState(policy?.locationRestrictionEnabled ?? false);
  const [allowedRegion, setAllowedRegion] = useState(policy?.allowedRegion || 'Headquarters');
  const [lat, setLat] = useState<number | undefined>(policy?.lat);
  const [lng, setLng] = useState<number | undefined>(policy?.lng);
  const [radiusKm, setRadiusKm] = useState(Math.round((policy?.radiusMeters || 25000) / 1000));

  const [linkInput, setLinkInput] = useState('');
  const [linkingMethod, setLinkingMethod] = useState<'google' | 'mobile'>('mobile');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const toggleDay = (dayId: string) => {
    if (days.includes(dayId)) {
      if (days.length === 1) return;
      setDays(days.filter((d) => d !== dayId));
    } else {
      setDays([...days, dayId]);
    }
  };

  const handleDetectLocation = () => {
    if (!navigator.geolocation) {
      setError('Geolocation not supported');
      return;
    }
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setLat(pos.coords.latitude);
        setLng(pos.coords.longitude);
        setLocationEnabled(true);
      },
      (err) => setError(err.message),
      { enableHighAccuracy: true }
    );
  };

  const handleSavePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSaving(true);
      setError(null);
      setMsg(null);
      await savePolicy({
        timeRestrictionEnabled: timeEnabled,
        startTime,
        endTime,
        days,
        timezone: policy?.timezone || 'Asia/Kolkata',
        locationRestrictionEnabled: locationEnabled,
        allowedRegion,
        geofenceEnabled: locationEnabled,
        lat,
        lng,
        radiusMeters: radiusKm * 1000,
      });
      setMsg('Working policy updated successfully');
    } catch (err: any) {
      setError(err.message || 'Failed to update policy');
    } finally {
      setSaving(false);
    }
  };

  const handleLinkAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!linkInput.trim()) return;

    try {
      setSaving(true);
      setError(null);
      setMsg(null);
      await authApi.linkAccount(linkingMethod, linkInput.trim());
      setMsg(`Successfully linked ${linkingMethod === 'google' ? 'Google account' : 'phone number'}`);
      setLinkInput('');
      await refreshSession();
    } catch (err: any) {
      setError(err.message || 'Account linking failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <AppLayout activeTab="settings" onTabChange={(t) => t === 'wallet' && onNavigateToWallet()}>
      <div className="flex flex-col gap-6 max-w-2xl mx-auto">
        <div className="flex items-center justify-between">
          <div className="flex flex-col">
            <h1 className="text-xl font-bold text-text tracking-tight">
              Security & Working Policy Settings
            </h1>
            <p className="text-xs text-muted">
              Configure contextual access restrictions and linked identity credentials.
            </p>
          </div>
          <button
            type="button"
            onClick={onNavigateToWallet}
            className="text-xs font-semibold text-accent hover:underline cursor-pointer"
          >
            ➔ Back to Wallet
          </button>
        </div>

        {error && (
          <div className="p-3 rounded-xl bg-danger/10 border border-danger/20 text-xs text-danger font-medium">
            {error}
          </div>
        )}
        {msg && (
          <div className="p-3 rounded-xl bg-success/10 border border-success/20 text-xs text-success font-medium">
            {msg}
          </div>
        )}

        {/* Form: Policy Settings */}
        <form onSubmit={handleSavePolicy} className="p-5 rounded-2xl bg-surface border border-border shadow-xs flex flex-col gap-5">
          <h2 className="text-sm font-bold text-text">Access Restriction Policy</h2>

          {/* Time Restrictions */}
          <div className="flex flex-col gap-3 p-4 rounded-xl bg-surface-2 border border-border">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-text">Time Restrictions</span>
              <input
                type="checkbox"
                checked={timeEnabled}
                onChange={(e) => setTimeEnabled(e.target.checked)}
                className="w-4 h-4 accent-accent rounded"
              />
            </div>

            {timeEnabled && (
              <div className="flex flex-col gap-3 pt-2 border-t border-border/60">
                <div className="grid grid-cols-2 gap-3">
                  <div className="flex flex-col gap-1">
                    <label className="text-[11px] font-semibold text-muted">Start Time</label>
                    <input
                      type="time"
                      value={startTime}
                      onChange={(e) => setStartTime(e.target.value)}
                      className="h-9 px-3 bg-surface border border-border rounded-lg text-sm text-text font-mono"
                    />
                  </div>
                  <div className="flex flex-col gap-1">
                    <label className="text-[11px] font-semibold text-muted">End Time</label>
                    <input
                      type="time"
                      value={endTime}
                      onChange={(e) => setEndTime(e.target.value)}
                      className="h-9 px-3 bg-surface border border-border rounded-lg text-sm text-text font-mono"
                    />
                  </div>
                </div>

                <div className="flex flex-col gap-1">
                  <label className="text-[11px] font-semibold text-muted">Permitted Days</label>
                  <div className="flex gap-1">
                    {WEEKDAYS.map((w) => (
                      <button
                        key={w.id}
                        type="button"
                        onClick={() => toggleDay(w.id)}
                        className={`flex-1 h-8 rounded-lg text-xs font-semibold cursor-pointer ${
                          days.includes(w.id)
                            ? 'bg-accent text-accent-contrast'
                            : 'bg-surface border border-border text-muted hover:text-text'
                        }`}
                      >
                        {w.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Location Geofence */}
          <div className="flex flex-col gap-3 p-4 rounded-xl bg-surface-2 border border-border">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-text">Location Geofence</span>
              <input
                type="checkbox"
                checked={locationEnabled}
                onChange={(e) => setLocationEnabled(e.target.checked)}
                className="w-4 h-4 accent-accent rounded"
              />
            </div>

            {locationEnabled && (
              <div className="flex flex-col gap-3 pt-2 border-t border-border/60">
                <div className="flex flex-col gap-1">
                  <label className="text-[11px] font-semibold text-muted">Area Name</label>
                  <input
                    type="text"
                    value={allowedRegion}
                    onChange={(e) => setAllowedRegion(e.target.value)}
                    className="h-9 px-3 bg-surface border border-border rounded-lg text-sm text-text"
                  />
                </div>

                <button
                  type="button"
                  onClick={handleDetectLocation}
                  className="h-9 bg-surface border border-border rounded-lg text-xs font-semibold text-text hover:bg-surface-2"
                >
                  📍 Update with Current GPS Location
                </button>

                {lat !== undefined && lng !== undefined && (
                  <span className="text-[11px] font-mono text-muted">
                    Geofence Center: {lat.toFixed(4)}, {lng.toFixed(4)}
                  </span>
                )}

                <div className="flex flex-col gap-1">
                  <div className="flex justify-between text-[11px]">
                    <span className="text-muted">Radius</span>
                    <span className="font-bold text-accent">{radiusKm} km</span>
                  </div>
                  <input
                    type="range"
                    min={1}
                    max={100}
                    value={radiusKm}
                    onChange={(e) => setRadiusKm(Number(e.target.value))}
                    className="accent-accent"
                  />
                </div>
              </div>
            )}
          </div>

          <button
            type="submit"
            disabled={saving}
            className="w-full h-10 bg-accent text-accent-contrast rounded-xl text-xs font-semibold hover:bg-accent-hover transition-colors cursor-pointer"
          >
            {saving ? 'Saving...' : 'Save Policy Changes'}
          </button>
        </form>

        {/* Linked Accounts */}
        <div className="p-5 rounded-2xl bg-surface border border-border shadow-xs flex flex-col gap-4">
          <h2 className="text-sm font-bold text-text">Linked Authentication Credentials</h2>
          <div className="flex flex-col gap-2 text-xs">
            <div className="p-3 rounded-xl bg-surface-2 border border-border flex items-center justify-between">
              <span className="font-semibold text-muted">Primary Login Method:</span>
              <span className="font-mono text-text font-bold uppercase">{user?.loginMethod}</span>
            </div>
            {user?.email && (
              <div className="p-3 rounded-xl bg-surface-2 border border-border flex items-center justify-between">
                <span className="font-semibold text-muted">Google Email:</span>
                <span className="font-mono text-text">{user.email}</span>
              </div>
            )}
            {user?.mobile && (
              <div className="p-3 rounded-xl bg-surface-2 border border-border flex items-center justify-between">
                <span className="font-semibold text-muted">Phone Number:</span>
                <span className="font-mono text-text">{user.mobile}</span>
              </div>
            )}
          </div>

          {/* Link Additional Method */}
          <form onSubmit={handleLinkAccount} className="flex flex-col gap-3 pt-3 border-t border-border">
            <span className="text-xs font-bold text-text">Link Additional Login Method</span>
            <div className="flex gap-2">
              <select
                value={linkingMethod}
                onChange={(e) => setLinkingMethod(e.target.value as any)}
                className="h-10 px-3 bg-surface-2 border border-border rounded-xl text-xs font-semibold text-text"
              >
                <option value="mobile">Phone Number</option>
                <option value="google">Google ID</option>
              </select>
              <input
                type="text"
                placeholder={linkingMethod === 'mobile' ? '9876543210' : 'Google Account ID or Email'}
                value={linkInput}
                onChange={(e) => setLinkInput(e.target.value)}
                className="flex-1 h-10 px-3 bg-surface border border-border rounded-xl text-xs text-text font-mono"
              />
              <button
                type="submit"
                disabled={saving || !linkInput.trim()}
                className="px-4 h-10 bg-accent text-accent-contrast rounded-xl text-xs font-semibold hover:bg-accent-hover transition-colors disabled:opacity-50 cursor-pointer"
              >
                Link
              </button>
            </div>
          </form>
        </div>
      </div>
    </AppLayout>
  );
};
