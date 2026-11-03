import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { profileApi } from '../api/endpoints';
import { useLocation } from '../hooks/useLocation';

export const WorkingPolicy: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();

  const [startTime, setStartTime] = useState('10:00');
  const [endTime, setEndTime] = useState('18:00');
  const [timezone, setTimezone] = useState(() => {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || 'Asia/Kolkata';
    } catch {
      return 'Asia/Kolkata';
    }
  });
  const [city, setCity] = useState('');
  const [lat, setLat] = useState<number>(22.7196);
  const [lng, setLng] = useState<number>(75.8577);
  const [radiusKm, setRadiusKm] = useState<number>(25);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Sync with geolocation
  useEffect(() => {
    if (location.lat !== null && location.lng !== null) {
      setLat(location.lat);
      setLng(location.lng);
    }
    if (location.city && !city) {
      setCity(location.city);
    }
  }, [location, city]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!startTime || !endTime) {
      setError('Please provide valid start and end times');
      return;
    }
    if (!city.trim()) {
      setError('Please enter your working city name');
      return;
    }

    try {
      setLoading(true);
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

      navigate('/review');
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to save working policy');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h1 className="page-title">Working Policy</h1>
      <p className="page-subtitle">Configure permitted execution hours and physical location</p>

      {error && <div className="alert alert-danger">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div className="grid-2">
          <div className="form-group">
            <label className="form-label" htmlFor="startTime">
              Start Time (24h)
            </label>
            <input
              id="startTime"
              type="time"
              className="form-input"
              value={startTime}
              onChange={(e) => setStartTime(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="endTime">
              End Time (24h)
            </label>
            <input
              id="endTime"
              type="time"
              className="form-input"
              value={endTime}
              onChange={(e) => setEndTime(e.target.value)}
              required
            />
          </div>
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor="timezone">
            Timezone
          </label>
          <input
            id="timezone"
            type="text"
            className="form-input"
            value={timezone}
            onChange={(e) => setTimezone(e.target.value)}
            required
          />
        </div>

        <div className="form-group">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <label className="form-label" htmlFor="city">
              Working Location (City)
            </label>
            <button
              type="button"
              className="copy-btn"
              onClick={location.refreshLocation}
              disabled={location.loading}
            >
              {location.loading ? 'Detecting...' : 'Detect GPS'}
            </button>
          </div>
          <input
            id="city"
            type="text"
            className="form-input"
            placeholder="e.g. Indore"
            value={city}
            onChange={(e) => setCity(e.target.value)}
            required
          />
        </div>

        <div className="grid-2">
          <div className="form-group">
            <label className="form-label" htmlFor="lat">
              Latitude
            </label>
            <input
              id="lat"
              type="number"
              step="any"
              className="form-input text-mono"
              value={lat}
              onChange={(e) => setLat(parseFloat(e.target.value))}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="lng">
              Longitude
            </label>
            <input
              id="lng"
              type="number"
              step="any"
              className="form-input text-mono"
              value={lng}
              onChange={(e) => setLng(parseFloat(e.target.value))}
              required
            />
          </div>
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor="radiusKm">
            Permitted Radius (km)
          </label>
          <input
            id="radiusKm"
            type="number"
            min={1}
            max={500}
            className="form-input text-mono"
            value={radiusKm}
            onChange={(e) => setRadiusKm(parseInt(e.target.value, 10))}
            required
          />
        </div>

        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? 'Saving Policy...' : 'Save Policy & Continue'}
        </button>
      </form>
    </div>
  );
};
