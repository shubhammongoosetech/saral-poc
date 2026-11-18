import React, { useState } from 'react';
import { useSession } from '../../context/SessionContext';
import { AuthLayout } from '../layout/AuthLayout';

const WEEKDAYS = [
  { id: 'MON', label: 'Mon' },
  { id: 'TUE', label: 'Tue' },
  { id: 'WED', label: 'Wed' },
  { id: 'THU', label: 'Thu' },
  { id: 'FRI', label: 'Fri' },
  { id: 'SAT', label: 'Sat' },
  { id: 'SUN', label: 'Sun' },
];

export const WorkingPolicyView: React.FC = () => {
  const { policy, savePolicy, logout } = useSession();

  const [timeEnabled, setTimeEnabled] = useState(policy?.timeRestrictionEnabled ?? true);
  const [startTime, setStartTime] = useState(policy?.startTime || '09:00');
  const [endTime, setEndTime] = useState(policy?.endTime || '18:00');
  const [days, setDays] = useState<string[]>(policy?.days || ['MON', 'TUE', 'WED', 'THU', 'FRI']);
  const [timezone] = useState(() => {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || 'Asia/Kolkata';
    } catch {
      return 'Asia/Kolkata';
    }
  });

  const [locationEnabled, setLocationEnabled] = useState(policy?.locationRestrictionEnabled ?? false);
  const [allowedRegion, setAllowedRegion] = useState(policy?.allowedRegion || 'Primary Office');
  const [lat, setLat] = useState<number | undefined>(policy?.lat);
  const [lng, setLng] = useState<number | undefined>(policy?.lng);
  const [radiusKm, setRadiusKm] = useState(Math.round((policy?.radiusMeters || 25000) / 1000));

  const [locating, setLocating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggleDay = (dayId: string) => {
    if (days.includes(dayId)) {
      if (days.length === 1) return; // Keep at least one day
      setDays(days.filter((d) => d !== dayId));
    } else {
      setDays([...days, dayId]);
    }
  };

  const handleDetectLocation = () => {
    if (!navigator.geolocation) {
      setError('Geolocation not supported by your browser');
      return;
    }
    setLocating(true);
    setError(null);
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setLat(pos.coords.latitude);
        setLng(pos.coords.longitude);
        setLocationEnabled(true);
        setLocating(false);
      },
      (err) => {
        setError(`Failed to retrieve GPS location: ${err.message}`);
        setLocating(false);
      },
      { timeout: 7000, enableHighAccuracy: true }
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (timeEnabled && (!startTime || !endTime)) {
      setError('Start time and end time are required');
      return;
    }
    if (locationEnabled && (lat === undefined || lng === undefined)) {
      setError('Please click "Detect Current Location" or enter valid coordinates for geofence');
      return;
    }

    try {
      setSaving(true);
      setError(null);
      await savePolicy({
        timeRestrictionEnabled: timeEnabled,
        startTime,
        endTime,
        days,
        timezone,
        locationRestrictionEnabled: locationEnabled,
        allowedRegion,
        geofenceEnabled: locationEnabled,
        lat,
        lng,
        radiusMeters: radiusKm * 1000,
      });
    } catch (err: any) {
      setError(err.message || 'Failed to save working policy');
    } finally {
      setSaving(false);
    }
  };

  return (
    <AuthLayout subtitle="Configure contextual access policies governing when and where your SARAL Wallet can be accessed">
      <div className="flex flex-col gap-5">
        <h1 className="text-xl font-bold text-text text-center tracking-tight">
          Working Policy Setup
        </h1>

        {error && (
          <div className="p-3 rounded-xl bg-danger/10 border border-danger/20 text-xs text-danger font-medium">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="flex flex-col gap-5">
          {/* Section 1: Time Restriction */}
          <div className="p-4 rounded-xl bg-surface-2 border border-border flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <div className="flex flex-col">
                <span className="text-xs font-bold text-text">Time-Based Access</span>
                <span className="text-[11px] text-muted">Restrict wallet access to business hours</span>
              </div>
              <input
                type="checkbox"
                checked={timeEnabled}
                onChange={(e) => setTimeEnabled(e.target.checked)}
                className="w-4 h-4 accent-accent rounded cursor-pointer"
              />
            </div>

            {timeEnabled && (
              <div className="flex flex-col gap-3 pt-2 border-t border-border/60">
                {/* Quick Presets */}
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-semibold text-muted">Presets:</span>
                  <button
                    type="button"
                    onClick={() => {
                      setStartTime('00:00');
                      setEndTime('23:59');
                      setDays(['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN']);
                    }}
                    className="text-[10px] px-2 py-0.5 rounded bg-surface border border-border text-accent font-semibold hover:bg-surface-2 transition-colors cursor-pointer"
                  >
                    24/7 Access (Testing)
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setStartTime('09:00');
                      setEndTime('18:00');
                      setDays(['MON', 'TUE', 'WED', 'THU', 'FRI']);
                    }}
                    className="text-[10px] px-2 py-0.5 rounded bg-surface border border-border text-muted font-medium hover:text-text transition-colors cursor-pointer"
                  >
                    Standard Office
                  </button>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="flex flex-col gap-1">
                    <label className="text-[11px] font-semibold text-muted">Start Time</label>
                    <input
                      type="time"
                      value={startTime}
                      onChange={(e) => setStartTime(e.target.value)}
                      className="h-10 px-3 bg-surface border border-border rounded-lg text-sm text-text font-mono"
                    />
                  </div>
                  <div className="flex flex-col gap-1">
                    <label className="text-[11px] font-semibold text-muted">End Time</label>
                    <input
                      type="time"
                      value={endTime}
                      onChange={(e) => setEndTime(e.target.value)}
                      className="h-10 px-3 bg-surface border border-border rounded-lg text-sm text-text font-mono"
                    />
                  </div>
                </div>

                <div className="flex flex-col gap-1.5">
                  <label className="text-[11px] font-semibold text-muted">Allowed Days</label>
                  <div className="flex items-center justify-between gap-1">
                    {WEEKDAYS.map((w) => (
                      <button
                        key={w.id}
                        type="button"
                        onClick={() => toggleDay(w.id)}
                        className={`flex-1 h-8 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                          days.includes(w.id)
                            ? 'bg-accent text-accent-contrast shadow-xs'
                            : 'bg-surface border border-border text-muted hover:text-text'
                        }`}
                      >
                        {w.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="flex items-center justify-between text-[11px] text-muted font-mono pt-1">
                  <span>Timezone:</span>
                  <span className="text-text font-semibold">{timezone}</span>
                </div>
              </div>
            )}
          </div>

          {/* Section 2: Location Geofence */}
          <div className="p-4 rounded-xl bg-surface-2 border border-border flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <div className="flex flex-col">
                <span className="text-xs font-bold text-text">Location Geofence</span>
                <span className="text-[11px] text-muted">Restrict access within approved geographic radius</span>
              </div>
              <input
                type="checkbox"
                checked={locationEnabled}
                onChange={(e) => setLocationEnabled(e.target.checked)}
                className="w-4 h-4 accent-accent rounded cursor-pointer"
              />
            </div>

            {locationEnabled && (
              <div className="flex flex-col gap-3 pt-2 border-t border-border/60">
                <div className="flex flex-col gap-1">
                  <label className="text-[11px] font-semibold text-muted">Area / Workspace Name</label>
                  <input
                    type="text"
                    value={allowedRegion}
                    onChange={(e) => setAllowedRegion(e.target.value)}
                    placeholder="e.g. Headquarters"
                    className="h-10 px-3 bg-surface border border-border rounded-lg text-sm text-text"
                  />
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleDetectLocation}
                    disabled={locating}
                    className="flex-1 h-9 bg-surface border border-border rounded-lg text-xs font-semibold text-text hover:bg-surface-2 transition-colors cursor-pointer flex items-center justify-center gap-1.5"
                  >
                    {locating ? 'Detecting GPS...' : '📍 Detect Current Location'}
                  </button>
                </div>

                {lat !== undefined && lng !== undefined && (
                  <div className="p-2 rounded-lg bg-surface border border-border font-mono text-[11px] text-muted flex items-center justify-between">
                    <span>GPS Coords:</span>
                    <span className="text-text font-semibold">
                      {lat.toFixed(4)}, {lng.toFixed(4)}
                    </span>
                  </div>
                )}

                <div className="flex flex-col gap-1">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="font-semibold text-muted">Allowed Radius</span>
                    <span className="font-mono text-accent font-bold">{radiusKm} km</span>
                  </div>
                  <input
                    type="range"
                    min={1}
                    max={100}
                    value={radiusKm}
                    onChange={(e) => setRadiusKm(Number(e.target.value))}
                    className="w-full accent-accent cursor-pointer"
                  />
                </div>
              </div>
            )}
          </div>

          {/* Warning Banner */}
          <div className="p-3 rounded-xl bg-warning/10 border border-warning/20 text-[11px] text-warning flex items-start gap-2">
            <span className="text-base leading-none">⚠️</span>
            <p>
              <strong>Access Guardrail:</strong> Your SARAL Wallet will be strictly locked outside of these configured working hours and approved geographic zones.
            </p>
          </div>

          <button
            type="submit"
            disabled={saving}
            className="w-full h-11 bg-accent text-accent-contrast rounded-xl text-sm font-semibold hover:bg-accent-hover transition-colors disabled:opacity-50 shadow-xs cursor-pointer flex items-center justify-center gap-2"
          >
            {saving ? (
              <span className="w-4 h-4 border-2 border-accent-contrast border-t-transparent rounded-full animate-spin" />
            ) : (
              <span>Save Policy & Continue ➔</span>
            )}
          </button>
        </form>

        <div className="flex justify-center text-xs pt-1 border-t border-border">
          <button
            type="button"
            onClick={logout}
            className="text-muted hover:text-text transition-colors cursor-pointer"
          >
            Log out
          </button>
        </div>
      </div>
    </AuthLayout>
  );
};
