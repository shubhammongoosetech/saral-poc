import React, { useState, useEffect } from 'react';
import { profileApi } from '../../api/endpoints';

interface WorkingHoursSectionProps {
  initialPolicy?: {
    startTime: string;
    endTime: string;
    city: string;
    radiusKm?: number;
    timezone?: string;
  } | null;
}

export const WorkingHoursSection: React.FC<WorkingHoursSectionProps> = ({ initialPolicy }) => {
  const [startTime, setStartTime] = useState(initialPolicy?.startTime || '09:00');
  const [endTime, setEndTime] = useState(initialPolicy?.endTime || '18:00');
  const [city, setCity] = useState(initialPolicy?.city || '');
  const [loading, setLoading] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initialPolicy) {
      if (initialPolicy.startTime) setStartTime(initialPolicy.startTime);
      if (initialPolicy.endTime) setEndTime(initialPolicy.endTime);
      if (initialPolicy.city) setCity(initialPolicy.city);
    }
  }, [initialPolicy]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      setError(null);
      setSaved(false);

      const timezone =
        initialPolicy?.timezone ||
        Intl.DateTimeFormat().resolvedOptions().timeZone ||
        'Asia/Kolkata';

      await profileApi.savePolicy({
        startTime,
        endTime,
        timezone,
        city: city.trim(),
        lat: 22.7196,
        lng: 75.8577,
        radiusKm: initialPolicy?.radiusKm || 25,
      });

      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to update working hours');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2 className="section-title">Working hours and location</h2>

      {error && <div className="alert alert-error">{error}</div>}
      {saved && <div className="alert alert-success">Working hours updated successfully.</div>}

      <form onSubmit={handleSubmit}>
        <div className="grid-2">
          <div className="field">
            <label className="label" htmlFor="setStartTime">
              From time
            </label>
            <input
              id="setStartTime"
              type="time"
              className="input"
              value={startTime}
              onChange={(e) => setStartTime(e.target.value)}
              required
            />
          </div>

          <div className="field">
            <label className="label" htmlFor="setEndTime">
              To time
            </label>
            <input
              id="setEndTime"
              type="time"
              className="input"
              value={endTime}
              onChange={(e) => setEndTime(e.target.value)}
              required
            />
          </div>
        </div>

        <div className="field">
          <label className="label" htmlFor="setCity">
            City
          </label>
          <input
            id="setCity"
            type="text"
            className="input"
            value={city}
            onChange={(e) => setCity(e.target.value)}
            placeholder="e.g. Indore"
            required
          />
        </div>

        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? 'Saving...' : 'Save changes'}
        </button>
      </form>
    </div>
  );
};

export default WorkingHoursSection;

