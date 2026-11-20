import { httpClient } from './httpClient';
import { Policy, ProfileResponse, AccessCheckResponse } from '../shared/api/types';

export interface SavePolicyPayload {
  startTime: string;
  endTime: string;
  timezone: string;
  city: string;
  lat: number;
  lng: number;
  radiusKm: number;
  days?: string[];
  timeRestrictionEnabled?: boolean;
  locationRestrictionEnabled?: boolean;
  geofenceEnabled?: boolean;
}

export const policyApi = {
  getProfile: async (): Promise<ProfileResponse> => {
    return httpClient.get<ProfileResponse>('/profile');
  },

  getPolicy: async (): Promise<{ success: boolean; policy: Policy | null }> => {
    return httpClient.get<{ success: boolean; policy: Policy | null }>('/wallet/policy');
  },

  savePolicy: async (policyData: SavePolicyPayload): Promise<{ message: string; policy: Policy }> => {
    return httpClient.post<{ message: string; policy: Policy }>('/profile/policy', policyData);
  },

  evaluatePolicy: async (lat?: number, lng?: number): Promise<AccessCheckResponse> => {
    return httpClient.post<AccessCheckResponse>('/wallet/policy/evaluate', { lat, lng });
  },
};

export const profileApi = policyApi;
export default policyApi;

