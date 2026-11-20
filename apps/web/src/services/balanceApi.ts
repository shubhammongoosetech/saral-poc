import { httpClient } from './httpClient';

export interface ChainBalances {
  mst: string;
  solana: string;
  bitcoin: string;
  timestamp?: string;
}

export interface BalancesResponse {
  success: boolean;
  balances: ChainBalances;
}

export const balanceApi = {
  getBalances: async (lat?: number, lng?: number): Promise<BalancesResponse> => {
    const params = lat !== undefined && lng !== undefined ? { lat, lng } : undefined;
    return httpClient.get<BalancesResponse>('/wallet/balances', { params });
  },
};

export default balanceApi;

