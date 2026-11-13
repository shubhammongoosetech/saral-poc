import { describe, it, expect } from 'vitest';
import { SaralClient } from '../src';
import { EvmAdapter, MST_TESTNET } from '@saral/sdk-core';

describe('MST Testnet Integration Test', () => {
  const isEnabled = Boolean(process.env.SARAL_INTEGRATION_TEST);

  it.runIf(isEnabled)('connects to MST Testnet and retrieves live balance', async () => {
    const adapter = new EvmAdapter(MST_TESTNET);
    // Well known or funded test address
    const testAddress = process.env.SARAL_TEST_ADDRESS || '0x0000000000000000000000000000000000000000';
    const balance = await adapter.getBalance(testAddress);
    expect(typeof balance).toBe('bigint');
  });

  it.skipIf(isEnabled)('skips live MST Testnet broadcast test when SARAL_INTEGRATION_TEST is not set', () => {
    expect(true).toBe(true);
  });
});

