import React, { createContext, useContext, useMemo } from 'react';
import { SaralClient } from '@saral/sdk-node';
import { SaralError } from '@saral/sdk-core';

export interface SaralContextValue {
  client: SaralClient;
}

const SaralContext = createContext<SaralContextValue | null>(null);

export interface SaralProviderProps {
  client: SaralClient;
  children: React.ReactNode;
}

/**
 * Root context provider for SARAL React hooks and components.
 */
export const SaralProvider: React.FC<SaralProviderProps> = ({ client, children }) => {
  const value = useMemo(() => ({ client }), [client]);

  return <SaralContext.Provider value={value}>{children}</SaralContext.Provider>;
};

/**
 * Internal hook to retrieve the current SaralClient instance.
 */
export function useSaral(): SaralClient {
  const context = useContext(SaralContext);
  if (!context) {
    throw new SaralError(
      'INVALID_CONFIG',
      'useSaral must be used within a <SaralProvider client={...}> component tree.'
    );
  }
  return context.client;
}

