import { useState, useCallback, useMemo } from 'react';
import { ChainConfig } from '@saral/sdk-core';
import { useSaral } from '../context';

export function useChain(defaultChainId: string = 'mst-testnet') {
  const saral = useSaral();
  const [currentChainId, setCurrentChainId] = useState<string>(defaultChainId);

  const chain = useMemo(() => {
    return saral.registry.getChain(currentChainId);
  }, [saral, currentChainId]);

  const chains = useMemo(() => {
    return saral.registry.getAllChains();
  }, [saral]);

  const setChain = useCallback(
    (id: string) => {
      // Validate chain exists
      saral.registry.getChain(id);
      setCurrentChainId(id);
    },
    [saral]
  );

  const isValidAddress = useCallback(
    (address: string) => {
      return saral.validateAddress(currentChainId, address);
    },
    [saral, currentChainId]
  );

  return {
    chain,
    chains,
    setChain,
    isValidAddress,
  };
}

