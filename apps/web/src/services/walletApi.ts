import { HttpError, httpClient } from './httpClient';
import { Coordinates, getCurrentCoords } from '../shared/hooks/useLocation';
import { SESSION_STORE } from '../shared/lib/storage';
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

const WALLET_CREATION_TIMEOUT_MS = 120_000;
const WALLET_READ_TIMEOUT_MS = 45_000;

async function withPolicyLocation<T>(request: (coords?: Coordinates) => Promise<T>): Promise<T> {
  const token = SESSION_STORE.getToken();
  try {
    return await request();
  } catch (error) {
    if (!(error instanceof HttpError) || error.code !== 'LOCATION_REQUIRED') throw error;
    const coords = await getCurrentCoords();
    if (!coords || SESSION_STORE.getToken() !== token) throw error;
    return request(coords);
  }
}

export const walletApi = {
  getWallet: (signal?: AbortSignal): Promise<WalletResponse> =>
    withPolicyLocation((params) =>
      httpClient.get<WalletResponse>('/wallet', { params, signal, timeoutMs: WALLET_READ_TIMEOUT_MS })
    ),

  generateWallet: (): Promise<WalletResponse> =>
    withPolicyLocation((coords) =>
      httpClient.post<WalletResponse>('/wallet/generate', coords, { timeoutMs: WALLET_CREATION_TIMEOUT_MS })
    ),

  createWallet: (): Promise<WalletResponse> =>
    withPolicyLocation((coords) =>
      httpClient.post<WalletResponse>('/wallet/create', coords, { timeoutMs: WALLET_CREATION_TIMEOUT_MS })
    ),

  checkAccess: async (): Promise<AccessCheckResponse> => {
    const token = SESSION_STORE.getToken();
    const check = await httpClient.post<AccessCheckResponse>('/wallet/check-access');
    if (check.allowed || check.code !== 'LOCATION_REQUIRED') return check;

    const coords = await getCurrentCoords();
    if (!coords || SESSION_STORE.getToken() !== token) return check;
    return httpClient.post<AccessCheckResponse>('/wallet/check-access', coords);
  },

  signTransaction: (data: SignTransactionPayload): Promise<SignResponse> =>
    withPolicyLocation((coords) => httpClient.post<SignResponse>('/wallet/sign', { ...data, ...coords })),

  getTransactions: (signal?: AbortSignal): Promise<TransactionsResponse> =>
    withPolicyLocation((params) =>
      httpClient.get<TransactionsResponse>('/wallet/transactions', { params, signal, timeoutMs: WALLET_READ_TIMEOUT_MS })
    ),

  getAddresses: async (lat?: number, lng?: number): Promise<any> => {
    const params = lat !== undefined && lng !== undefined ? { lat, lng } : undefined;
    return httpClient.get('/wallet/addresses', { params });
  },
};

export default walletApi;

