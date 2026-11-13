import { useState, useEffect, useCallback } from 'react';
import { TransactionRecord, SaralError } from '@saral/sdk-core';
import { useSaral } from '../context';

export function useTransactions(opts?: { chain?: string; page?: number }) {
  const saral = useSaral();
  const [transactions, setTransactions] = useState<TransactionRecord[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<SaralError | null>(null);

  const fetchTransactions = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await saral.getTransactions(opts);
      setTransactions(res.transactions);
      setTotal(res.total);
    } catch (err: unknown) {
      const saralErr =
        err instanceof SaralError
          ? err
          : new SaralError('RPC_ERROR', err instanceof Error ? err.message : String(err));
      setError(saralErr);
    } finally {
      setLoading(false);
    }
  }, [saral, opts?.chain, opts?.page]);

  useEffect(() => {
    fetchTransactions();
  }, [fetchTransactions]);

  return {
    transactions,
    total,
    loading,
    error,
    refresh: fetchTransactions,
  };
}

