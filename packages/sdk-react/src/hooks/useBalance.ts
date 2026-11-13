import { useState, useEffect, useCallback } from 'react';
import { ethers } from 'ethers';
import { SaralError } from '@saral/sdk-core';
import { useSaral } from '../context';

export function useBalance(chainId: string = 'mst-testnet', address?: string) {
  const saral = useSaral();
  const [balance, setBalance] = useState<bigint | null>(null);
  const [formatted, setFormatted] = useState<string>('0.0000');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<SaralError | null>(null);

  const fetchBalance = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rawBalance = await saral.getBalance(chainId, address);
      setBalance(rawBalance);

      const chain = saral.registry.getChain(chainId);
      if (chain.type === 'evm') {
        setFormatted(ethers.formatEther(rawBalance));
      } else {
        setFormatted((Number(rawBalance) / 1e9).toFixed(4));
      }
    } catch (err: unknown) {
      const saralErr =
        err instanceof SaralError
          ? err
          : new SaralError('RPC_ERROR', err instanceof Error ? err.message : String(err));
      setError(saralErr);
    } finally {
      setLoading(false);
    }
  }, [saral, chainId, address]);

  useEffect(() => {
    fetchBalance();
  }, [fetchBalance]);

  return {
    balance,
    formatted,
    loading,
    error,
    refresh: fetchBalance,
  };
}

