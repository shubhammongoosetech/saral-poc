import React from 'react';
import ReactDOMServer from 'react-dom/server';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { SaralClient } from '@saral/sdk-node';
import { SaralProvider, useSaral, getCurrentBrowserLocation } from '../src';
import { SaralError } from '@saral/sdk-core';

describe('SaralProvider & Geolocation Tests', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('throws SaralError if useSaral is called outside of SaralProvider', () => {
    function Consumer() {
      useSaral();
      return null;
    }

    expect(() => ReactDOMServer.renderToString(<Consumer />)).toThrowError(SaralError);
  });

  it('renders children correctly when SaralProvider is supplied', () => {
    const client = new SaralClient({ baseUrl: 'http://localhost:3001' });

    function Consumer() {
      const c = useSaral();
      return <div>Base: {c.baseUrl}</div>;
    }

    const html = ReactDOMServer.renderToString(
      <SaralProvider client={client}>
        <Consumer />
      </SaralProvider>
    );

    expect(html).toContain('http://localhost:3001');
  });

  it('throws LOCATION_PERMISSION_DENIED when browser user denies geolocation', async () => {
    const mockGeolocation = {
      getCurrentPosition: vi.fn((_success, error) => {
        error({
          code: 1, // PERMISSION_DENIED
          message: 'User denied Geolocation',
          PERMISSION_DENIED: 1,
          POSITION_UNAVAILABLE: 2,
          TIMEOUT: 3,
        });
      }),
    };

    (globalThis as any).window = globalThis;
    Object.defineProperty(globalThis, 'navigator', {
      value: { geolocation: mockGeolocation },
      configurable: true,
      writable: true,
    });

    await expect(getCurrentBrowserLocation()).rejects.toThrowError(SaralError);

    try {
      await getCurrentBrowserLocation();
    } catch (err: any) {
      expect(err.code).toBe('LOCATION_PERMISSION_DENIED');
      expect(err.message).toContain('denied by the user');
    }
  });

  it('acquires location coordinates successfully when user permits', async () => {
    const mockGeolocation = {
      getCurrentPosition: vi.fn((success) => {
        success({
          coords: {
            latitude: 12.9716,
            longitude: 77.5946,
          },
        });
      }),
    };

    (globalThis as any).window = globalThis;
    Object.defineProperty(globalThis, 'navigator', {
      value: { geolocation: mockGeolocation },
      configurable: true,
      writable: true,
    });

    const loc = await getCurrentBrowserLocation();
    expect(loc.lat).toBe(12.9716);
    expect(loc.lng).toBe(77.5946);
  });
});
