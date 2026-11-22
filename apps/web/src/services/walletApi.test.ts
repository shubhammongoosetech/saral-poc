import { afterEach, describe, expect, it, vi } from 'vitest';
import { HttpError, httpClient } from './httpClient';
import { walletApi } from './walletApi';

const missingLocation = new HttpError(403, 'Forbidden', { code: 'LOCATION_REQUIRED' });

describe('wallet location requirements', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('retries a location-required request with browser coordinates', async () => {
    const getPosition = vi.fn((resolve) => resolve({ coords: { latitude: 0, longitude: 0 } }));
    vi.stubGlobal('navigator', { geolocation: { getCurrentPosition: getPosition } });
    const get = vi.spyOn(httpClient, 'get')
      .mockRejectedValueOnce(missingLocation)
      .mockResolvedValueOnce({ hasWallet: false, wallet: null });

    await expect(walletApi.getWallet()).resolves.toEqual({ hasWallet: false, wallet: null });
    expect(getPosition).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenLastCalledWith('/wallet', expect.objectContaining({ params: { lat: 0, lng: 0 } }));
  });

  it('submits no coordinates if the browser denies location permission', async () => {
    vi.stubGlobal('navigator', { geolocation: { getCurrentPosition: (_resolve: unknown, deny: () => void) => deny() } });
    const get = vi.spyOn(httpClient, 'get').mockRejectedValue(missingLocation);

    await expect(walletApi.getWallet()).rejects.toBe(missingLocation);
    expect(get).toHaveBeenCalledTimes(1);
  });

  it('does not request geolocation for a successful access check', async () => {
    const getPosition = vi.fn();
    vi.stubGlobal('navigator', { geolocation: { getCurrentPosition: getPosition } });
    vi.spyOn(httpClient, 'post').mockResolvedValue({ allowed: true });

    await expect(walletApi.checkAccess()).resolves.toEqual({ allowed: true });
    expect(getPosition).not.toHaveBeenCalled();
  });
});
