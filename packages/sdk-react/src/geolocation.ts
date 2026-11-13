import { AccessLocation, SaralError } from '@saral/sdk-core';

/**
 * Browser geolocation helper that acquires current GPS coordinates.
 * Throws LOCATION_PERMISSION_DENIED if user refuses permission.
 */
export async function getCurrentBrowserLocation(options?: PositionOptions): Promise<AccessLocation> {
  if (typeof window === 'undefined' || !navigator.geolocation) {
    throw new SaralError(
      'LOCATION_REQUIRED',
      'Browser geolocation API is not available in this environment.'
    );
  }

  return new Promise<AccessLocation>((resolve, reject) => {
    navigator.geolocation.getCurrentPosition(
      (position) => {
        resolve({
          lat: position.coords.latitude,
          lng: position.coords.longitude,
        });
      },
      (error) => {
        if (error.code === error.PERMISSION_DENIED) {
          reject(
            new SaralError(
              'LOCATION_PERMISSION_DENIED',
              'Geolocation permission was denied by the user. Zero-Trust access policy requires location verification.',
              { code: error.code }
            )
          );
        } else {
          reject(
            new SaralError(
              'LOCATION_REQUIRED',
              `Failed to acquire browser location: ${error.message}`,
              { code: error.code }
            )
          );
        }
      },
      {
        enableHighAccuracy: true,
        timeout: 10_000,
        maximumAge: 60_000,
        ...options,
      }
    );
  });
}

