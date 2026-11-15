import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useRef, useEffect } from 'react';
import { walletApi } from '@/shared/api/endpoints';

export const WALLET_QUERY_KEY = ['wallet'];
export const TRANSACTIONS_QUERY_KEY = ['transactions'];

export function useWalletQuery(enabled = true) {
  return useQuery({
    queryKey: WALLET_QUERY_KEY,
    queryFn: () => walletApi.getWallet(),
    enabled,
    staleTime: 10_000,
  });
}

export function useTransactionsQuery(enabled = true) {
  return useQuery({
    queryKey: TRANSACTIONS_QUERY_KEY,
    queryFn: () => walletApi.getTransactions(),
    enabled,
    staleTime: 10_000,
  });
}

export function usePostSendPolling() {
  const queryClient = useQueryClient();
  const timersRef = useRef<number[]>([]);

  const clearTimers = useCallback(() => {
    timersRef.current.forEach((id) => window.clearTimeout(id));
    timersRef.current = [];
  }, []);

  useEffect(() => clearTimers, [clearTimers]);

  const triggerPostSendPolling = useCallback(() => {
    clearTimers();
    // Immediate refetch
    queryClient.invalidateQueries({ queryKey: WALLET_QUERY_KEY });
    queryClient.invalidateQueries({ queryKey: TRANSACTIONS_QUERY_KEY });

    // Multi-interval refresh: 1.5s, 3s, 5s, 8s, 12s
    const intervals = [1500, 3000, 5000, 8000, 12000];
    intervals.forEach((delay) => {
      const id = window.setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: WALLET_QUERY_KEY });
        queryClient.invalidateQueries({ queryKey: TRANSACTIONS_QUERY_KEY });
      }, delay);
      timersRef.current.push(id);
    });
  }, [clearTimers, queryClient]);

  return { triggerPostSendPolling, clearTimers };
}
