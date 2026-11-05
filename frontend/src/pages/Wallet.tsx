import React, { useState, useEffect, useCallback } from 'react';
import { walletApi, WalletData } from '../api/endpoints';
import { WalletHeader } from './Wallet/WalletHeader';
import { SendForm } from './Wallet/SendForm';
import { TransactionList, TransactionItem } from './Wallet/TransactionList';

export const Wallet: React.FC = () => {
  const [hasWallet, setHasWallet] = useState<boolean | null>(null);
  const [wallet, setWallet] = useState<WalletData | null>(null);
  const [transactions, setTransactions] = useState<TransactionItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchTransactions = useCallback(async () => {
    try {
      const res = await walletApi.getTransactions();
      setTransactions(res.transactions || []);
    } catch {
      // Non-blocking history fetch
    }
  }, []);

  const loadWallet = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await walletApi.getWallet();
      setHasWallet(res.hasWallet);
      setWallet(res.wallet);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to load wallet');
    } finally {
      setLoading(false);
    }
  }, []);

  const handleRefresh = async () => {
    try {
      setRefreshing(true);
      setError(null);
      const res = await walletApi.getWallet();
      setHasWallet(res.hasWallet);
      setWallet(res.wallet);
      await fetchTransactions();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to refresh balance');
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadWallet();
  }, [loadWallet]);

  useEffect(() => {
    if (hasWallet) {
      fetchTransactions();
    }
  }, [hasWallet, fetchTransactions]);

  const handleCreateWallet = async () => {
    try {
      setCreating(true);
      setError(null);
      const res = await walletApi.generateWallet(19, 13);
      setWallet(res.wallet);
      setHasWallet(true);
      await fetchTransactions();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to create wallet');
    } finally {
      setCreating(false);
    }
  };

  if (loading) {
    return (
      <div className="card">
        <p className="muted text-center">Loading wallet...</p>
      </div>
    );
  }

  return (
    <div className="card card-wide">
      {error && <div className="alert alert-error">{error}</div>}

      {!hasWallet ? (
        <div>
          <h1 className="page-title">Wallet</h1>
          <button
            type="button"
            className="btn btn-primary"
            onClick={handleCreateWallet}
            disabled={creating}
          >
            {creating ? 'Creating wallet...' : 'Create wallet'}
          </button>
        </div>
      ) : (
        <div>
          <WalletHeader
            address={wallet?.address || ''}
            balance={wallet?.balance || '0.00'}
            onRefresh={handleRefresh}
            refreshing={refreshing}
          />

          <SendForm onSent={handleRefresh} />

          <TransactionList transactions={transactions} />
        </div>
      )}
    </div>
  );
};

export default Wallet;
