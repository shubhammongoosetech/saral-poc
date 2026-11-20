import { httpClient } from './httpClient';
import { TransactionsResponse } from '../shared/api/types';

export const activityApi = {
  getTransactions: async (lat?: number, lng?: number): Promise<TransactionsResponse> => {
    const params = lat !== undefined && lng !== undefined ? { lat, lng } : undefined;
    return httpClient.get<TransactionsResponse>('/wallet/transactions', { params });
  },

  getActivity: async (lat?: number, lng?: number): Promise<TransactionsResponse> => {
    const params = lat !== undefined && lng !== undefined ? { lat, lng } : undefined;
    return httpClient.get<TransactionsResponse>('/wallet/activity', { params });
  },
};

export default activityApi;

