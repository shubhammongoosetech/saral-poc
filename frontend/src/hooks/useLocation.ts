import { useState, useEffect, useCallback } from 'react';

const DEFAULT_FALLBACK_COORDS = { lat: 22.7196, lng: 75.8577 };

export interface LocationState {
  lat: number | null;
  lng: number | null;
  city: string;
  loading: boolean;
  error: string | null;
}

/**
 * Resolves the browser's current geographic coordinates, falling back to
 * DEFAULT_FALLBACK_COORDS when geolocation is unavailable, denied, or times out.
 */
export function getCurrentCoords(): Promise<{ lat: number; lng: number }> {
  return new Promise((resolve) => {
    if (!navigator.geolocation) {
      resolve(DEFAULT_FALLBACK_COORDS);
      return;
    }
    navigator.geolocation.getCurrentPosition(
      (pos) => resolve({ lat: pos.coords.latitude, lng: pos.coords.longitude }),
      () => resolve(DEFAULT_FALLBACK_COORDS),
      { timeout: 5000, enableHighAccuracy: true, maximumAge: 60000 }
    );
  });
}

export function useLocation() {
  const [state, setState] = useState<LocationState>({
    lat: null,
    lng: null,
    city: '',
    loading: true,
    error: null,
  });

  const fetchCityName = async (lat: number, lng: number): Promise<string> => {
    try {
      const res = await fetch(
        `https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${lat}&lon=${lng}`
      );
      if (res.ok) {
        const data = await res.json();
        return (
          data.address?.city ||
          data.address?.town ||
          data.address?.village ||
          data.address?.state_district ||
          data.address?.state ||
          'Current Location'
        );
      }
    } catch (e) {
      // Nominatim reverse geocode fallback
    }
    return 'Current Location';
  };

  const getLocation = useCallback(() => {
    setState((prev) => ({ ...prev, loading: true, error: null }));

    if (!navigator.geolocation) {
      setState({
        lat: DEFAULT_FALLBACK_COORDS.lat,
        lng: DEFAULT_FALLBACK_COORDS.lng,
        city: 'Indore',
        loading: false,
        error: 'Geolocation is not supported by your browser. Defaulting to Indore.',
      });
      return;
    }

    navigator.geolocation.getCurrentPosition(
      async (position) => {
        const lat = position.coords.latitude;
        const lng = position.coords.longitude;
        const city = await fetchCityName(lat, lng);

        setState({
          lat,
          lng,
          city,
          loading: false,
          error: null,
        });
      },
      (err) => {
        // Geolocation denied or unavailable -> fallback to Indore as specified in example
        setState({
          lat: DEFAULT_FALLBACK_COORDS.lat,
          lng: DEFAULT_FALLBACK_COORDS.lng,
          city: 'Indore',
          loading: false,
          error: 'Location access denied or unavailable. Fallback set to Indore.',
        });
      },
      { enableHighAccuracy: true, timeout: 10000, maximumAge: 60000 }
    );
  }, []);

  useEffect(() => {
    getLocation();
  }, [getLocation]);

  return { ...state, refreshLocation: getLocation };
}
