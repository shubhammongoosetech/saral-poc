import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { profileApi } from '@/shared/api/endpoints';
import { useSession } from '@/features/auth/useSession';
import { getCurrentCoords } from '@/shared/hooks/useLocation';
import { mapApiError } from '@/shared/lib/format';
import { AuthLayout } from '@/app/layouts/AuthLayout';
import { Button } from '@/shared/ui/Button';
import { Input } from '@/shared/ui/Input';
import { Field } from '@/shared/ui/Field';
import { Alert } from '@/shared/ui/Alert';

export const WorkingPolicy: React.FC = () => {
  const navigate = useNavigate();
  const { logout, refreshProfile, markPolicyConfigured } = useSession();

  const [startTime, setStartTime] = useState('09:00');
  const [endTime, setEndTime] = useState('18:00');
  const [city, setCity] = useState('');
  const [lat, setLat] = useState<number>(22.7196);
  const [lng, setLng] = useState<number>(75.8577);
  const [radiusKm, setRadiusKm] = useState<number>(25);

  const [timezone] = useState(() => {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || 'Asia/Kolkata';
    } catch {
      return 'Asia/Kolkata';
    }
  });

  const [locating, setLocating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // If user already had a policy, populate existing values
  useEffect(() => {
    let active = true;
    profileApi
      .getProfile()
      .then((data) => {
        if (!active || !data.policy) return;
        const p = data.policy;
        if (p.startTime || p.start_time) setStartTime(p.startTime || p.start_time || '09:00');
        if (p.endTime || p.end_time) setEndTime(p.endTime || p.end_time || '18:00');
        if (p.city) setCity(p.city);
        if (p.lat != null) setLat(p.lat);
        if (p.lng != null) setLng(p.lng);
        if (p.radiusKm) setRadiusKm(p.radiusKm);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, []);

  const handleDetectLocation = async () => {
    try {
      setLocating(true);
      setError(null);
      const coords = await getCurrentCoords();
      if (!coords) {
        setError('Allow location access to detect your working location.');
        return;
      }
      setLat(coords.lat);
      setLng(coords.lng);
      try {
        const res = await fetch(
          `https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${coords.lat}&lon=${coords.lng}`,
          { referrerPolicy: 'origin' }
        );
        if (res.ok) {
          const data = await res.json();
          const detectedCity =
            data.address?.city ||
            data.address?.town ||
            data.address?.village ||
            data.address?.state_district ||
            data.address?.state ||
            '';
          if (detectedCity) setCity(detectedCity);
        }
      } catch {}
    } catch (err: unknown) {
      setError(mapApiError(err, 'Failed to detect location'));
    } finally {
      setLocating(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!startTime || !endTime) {
      setError('Start and end times required');
      return;
    }
    if (!city.trim()) {
      setError('City required');
      return;
    }

    try {
      setSaving(true);
      setError(null);
      await profileApi.savePolicy({
        startTime,
        endTime,
        timezone,
        city: city.trim(),
        lat,
        lng,
        radiusKm,
      });

      markPolicyConfigured();
      await refreshProfile();
      navigate('/review');
    } catch (err: unknown) {
      setError(mapApiError(err, 'Failed to save policy'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <AuthLayout>
      <div className="w-full flex flex-col gap-5">
        <h1 className="text-xl font-semibold text-text text-center tracking-tight">Working policy</h1>

        {error && <Alert variant="error">{error}</Alert>}

        <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-4">
          <div className="grid grid-cols-2 gap-3">
            <Field label="Start" htmlFor="startTime">
              <Input
                id="startTime"
                type="time"
                value={startTime}
                onChange={(e) => setStartTime(e.target.value)}
                disabled={saving}
                required
              />
            </Field>

            <Field label="End" htmlFor="endTime">
              <Input
                id="endTime"
                type="time"
                value={endTime}
                onChange={(e) => setEndTime(e.target.value)}
                disabled={saving}
                required
              />
            </Field>
          </div>

          <Field label="Timezone" htmlFor="timezone">
            <Input id="timezone" type="text" value={timezone} disabled />
          </Field>

          <Field label="City" htmlFor="city">
            <div className="flex gap-2">
              <Input
                id="city"
                type="text"
                placeholder="City"
                value={city}
                onChange={(e) => setCity(e.target.value)}
                disabled={saving}
                required
              />
              <Button
                type="button"
                variant="secondary"
                size="md"
                onClick={handleDetectLocation}
                loading={locating}
                disabled={saving}
              >
                Use location
              </Button>
            </div>
          </Field>

          <Field label="Radius (km)" htmlFor="radiusKm">
            <Input
              id="radiusKm"
              type="number"
              min={1}
              max={500}
              value={radiusKm}
              onChange={(e) => setRadiusKm(Number(e.target.value) || 25)}
              disabled={saving}
              required
            />
          </Field>

          <Button
            type="submit"
            loading={saving}
            disabled={!startTime || !endTime || !city.trim()}
            fullWidth
          >
            Save
          </Button>

          <div className="flex justify-center text-xs pt-1">
            <button
              type="button"
              className="text-muted hover:text-text transition-colors"
              onClick={() => logout()}
            >
              Log out
            </button>
          </div>
        </form>
      </div>
    </AuthLayout>
  );
};

export default WorkingPolicy;
