import { useState, useCallback } from 'react';
import {
  TransactionPreview,
  SignAndSendOptions,
  SignAndSendResult,
  DomainName,
  SaralError,
} from '@saral/sdk-core';
import { useSaral } from '../context';
import { getCurrentBrowserLocation } from '../geolocation';

export type SignFlowState =
  | 'idle'
  | 'preparing'
  | 'awaiting-confirmation'
  | 'signing'
  | 'broadcasting'
  | 'confirmed'
  | 'failed';

export function useSignAndSend() {
  const saral = useSaral();
  const [state, setState] = useState<SignFlowState>('idle');
  const [signingDomain, setSigningDomain] = useState<DomainName | null>(null);
  const [result, setResult] = useState<SignAndSendResult | null>(null);
  const [error, setError] = useState<SaralError | null>(null);

  const execute = useCallback(
    async (
      preview: TransactionPreview,
      opts?: SignAndSendOptions & { autoAcquireLocation?: boolean; waitForConfirm?: boolean }
    ): Promise<SignAndSendResult> => {
      setError(null);
      setResult(null);

      try {
        // Step 1: Location acquisition (if requested or missing)
        let location = opts?.location;
        if (!location && opts?.autoAcquireLocation !== false && typeof window !== 'undefined') {
          try {
            location = await getCurrentBrowserLocation();
          } catch (locErr: unknown) {
            // Re-throw if permission denied so UI can show permission prompt
            if (locErr instanceof SaralError && locErr.code === 'LOCATION_PERMISSION_DENIED') {
              throw locErr;
            }
          }
        }

        // Step 2: Transition through 3-Domain Signing states
        setState('signing');
        setSigningDomain('foundation');

        // Progress simulation for responsive UX across domains
        const domainTimer1 = setTimeout(() => setSigningDomain('public'), 400);
        const domainTimer2 = setTimeout(() => setSigningDomain('private'), 800);

        let sendResult: SignAndSendResult;
        try {
          sendResult = await saral.signAndSend(preview, {
            location,
            idempotencyKey: opts?.idempotencyKey,
          });
        } finally {
          clearTimeout(domainTimer1);
          clearTimeout(domainTimer2);
        }

        setState('broadcasting');
        setSigningDomain(null);
        setResult(sendResult);

        // Step 3: Optional block confirmation polling
        if (opts?.waitForConfirm) {
          const adapter = saral.getAdapter(preview.chain);
          const confirmRes = await adapter.waitForConfirmation(sendResult.txHash, { timeoutMs: 30_000 });
          if (confirmRes.confirmed) {
            setState('confirmed');
            sendResult.status = 'CONFIRMED';
            sendResult.blockNumber = confirmRes.blockNumber;
          } else {
            setState('confirmed'); // Broadcasted successfully even if confirmation receipt delayed
          }
        } else {
          setState('confirmed');
        }

        return sendResult;
      } catch (err: unknown) {
        setState('failed');
        setSigningDomain(null);
        const saralErr =
          err instanceof SaralError
            ? err
            : new SaralError('RPC_ERROR', err instanceof Error ? err.message : String(err));
        setError(saralErr);
        throw saralErr;
      }
    },
    [saral]
  );

  const reset = useCallback(() => {
    setState('idle');
    setSigningDomain(null);
    setResult(null);
    setError(null);
  }, []);

  return {
    state,
    signingDomain,
    result,
    error,
    execute,
    reset,
  };
}

