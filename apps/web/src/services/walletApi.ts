import { httpClient } from './httpClient';
import {
  WalletResponse,
  AccessCheckResponse,
  SignResponse,
  TransactionsResponse,
} from '../shared/api/types';

export interface SignTransactionPayload {
  chain?: string;
  toAddress: string;
  amount: string;
  lat?: number;
  lng?: number;
}

export const walletApi = {
  getWallet: async (lat?: number, lng?: number): Promise<WalletResponse> => {
    const params = lat !== undefined && lng !== undefined ? { lat, lng } : undefined;
    return httpClient.get<WalletResponse>('/wallet', { params });
  },

  generateWallet: async (lat?: number, lng?: number): Promise<WalletResponse> => {
    return httpClient.post<WalletResponse>('/wallet/generate', { lat, lng });
  },

  createWallet: async (lat?: number, lng?: number): Promise<WalletResponse> => {
    return httpClient.post<WalletResponse>('/wallet/create', { lat, lng });
  },

  checkAccess: async (lat?: number, lng?: number): Promise<AccessCheckResponse> => {
    return httpClient.post<AccessCheckResponse>('/wallet/check-access', { lat, lng });
  },

  signTransaction: async (data: SignTransactionPayload): Promise<SignResponse> => {
    return httpClient.post<SignResponse>('/wallet/sign', data);
  },

  getTransactions: async (lat?: number, lng?: number): Promise<TransactionsResponse> => {
    const params = lat !== undefined && lng !== undefined ? { lat, lng } : undefined;
    return httpClient.get<TransactionsResponse>('/wallet/transactions', { params });
  },

  getAddresses: async (lat?: number, lng?: number): Promise<any> => {
    const params = lat !== undefined && lng !== undefined ? { lat, lng } : undefined;
    return httpClient.get('/wallet/addresses', { params });
  },
};

export default walletApi;

