import { useState, useCallback } from 'react';
import { PrepareTransactionRequest, TransactionPreview, SaralError } from '@saral/sdk-core';
import { useSaral } from '../context';

export function usePrepareTransaction() {
  const saral = useSaral();
  const [preview, setPreview] = useState<TransactionPreview | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<SaralError | null>(null);

  const prepare = useCallback(
    async (req: PrepareTransactionRequest): Promise<TransactionPreview> => {
      setLoading(true);
      setError(null);
      try {
        const result = await saral.prepareTransaction(req);
        setPreview(result);
        return result;
      } catch (err: unknown) {
        const saralErr =
          err instanceof SaralError
            ? err
            : new SaralError('INVALID_CONFIG', err instanceof Error ? err.message : String(err));
        setError(saralErr);
        throw saralErr;
      } finally {
        setLoading(false);
      }
    },
    [saral]
  );

  const reset = useCallback(() => {
    setPreview(null);
    setError(null);
    setLoading(false);
  }, []);

  return {
    prepare,
    preview,
    loading,
    error,
    reset,
  };
}

