import { useState, useEffect, useCallback } from 'react';

export type Coordinates = {
  lat: number;
  lng: number;
};

let pendingLocation: Promise<Coordinates | undefined> | undefined;

export interface LocationState {
  lat: number | null;
  lng: number | null;
  city: string;
  loading: boolean;
  error: string | null;
}

export function getCurrentCoords(): Promise<Coordinates | undefined> {
  if (typeof navigator === 'undefined' || !navigator.geolocation) {
    return Promise.resolve(undefined);
  }

  pendingLocation ??= new Promise<Coordinates | undefined>((resolve) => {
    navigator.geolocation.getCurrentPosition(
      ({ coords }) => resolve({ lat: coords.latitude, lng: coords.longitude }),
      () => resolve(undefined),
      { timeout: 5000, enableHighAccuracy: true, maximumAge: 60000 }
    );
  }).finally(() => {
    pendingLocation = undefined;
  });

  return pendingLocation;
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
        `https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${lat}&lon=${lng}`,
        { referrerPolicy: 'origin' }
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
    } catch {
      // Nominatim reverse geocode fallback
    }
    return 'Current Location';
  };

  const getLocation = useCallback(async () => {
    setState((prev) => ({ ...prev, loading: true, error: null }));

    const coords = await getCurrentCoords();
    if (!coords) {
      setState({
        lat: null,
        lng: null,
        city: '',
        loading: false,
        error: 'Location access denied or unavailable.',
      });
      return;
    }

    const city = await fetchCityName(coords.lat, coords.lng);
    setState({ ...coords, city, loading: false, error: null });
  }, []);

  useEffect(() => {
    getLocation();
  }, [getLocation]);

  return { ...state, refreshLocation: getLocation };
}
