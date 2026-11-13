import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { profileApi } from '../api/endpoints';
import { useLocation } from '../hooks/useLocation';

export const WorkingPolicy: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();

  const [startTime, setStartTime] = useState('09:00');
  const [endTime, setEndTime] = useState('18:00');
  const [city, setCity] = useState('');
  const [lat, setLat] = useState<number>(22.7196);
  const [lng, setLng] = useState<number>(75.8577);
  const [radiusKm] = useState<number>(25);

  const [timezone] = useState(() => {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || 'Asia/Kolkata';
    } catch {
      return 'Asia/Kolkata';
    }
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
      setError('Please provide start and end times');
      return;
    }
    if (!city.trim()) {
      setError('Please enter a city');
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
      setError(err.response?.data?.error || 'Failed to save working hours');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h1 className="page-title">Working hours</h1>

      {error && <div className="alert alert-error">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div className="grid-2">
          <div className="field">
            <label className="label" htmlFor="startTime">
              From time
            </label>
            <input
              id="startTime"
              type="time"
              className="input"
              value={startTime}
              onChange={(e) => setStartTime(e.target.value)}
              required
            />
          </div>

          <div className="field">
            <label className="label" htmlFor="endTime">
              To time
            </label>
            <input
              id="endTime"
              type="time"
              className="input"
              value={endTime}
              onChange={(e) => setEndTime(e.target.value)}
              required
            />
          </div>
        </div>

        <div className="field">
          <label className="label" htmlFor="city">
            City
          </label>
          <input
            id="city"
            type="text"
            className="input"
            placeholder="e.g. Indore"
            value={city}
            onChange={(e) => setCity(e.target.value)}
            required
          />
        </div>

        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? 'Saving...' : 'Save'}
        </button>
      </form>
    </div>
  );
};
