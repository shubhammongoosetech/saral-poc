import { httpClient } from './httpClient';
import { AuthResponse } from '../shared/api/types';

export interface RequestOtpResponse {
  success: boolean;
  devOtp?: string;
  message?: string;
}

export const authApi = {
  loginWithGoogle: async (credential: string): Promise<AuthResponse> => {
    return httpClient.post<AuthResponse>('/auth/google', { credential });
  },

  requestOtp: async (mobile: string): Promise<RequestOtpResponse> => {
    return httpClient.post<RequestOtpResponse>('/auth/otp/request', { mobile });
  },

  verifyOtp: async (mobile: string, code: string): Promise<AuthResponse> => {
    return httpClient.post<AuthResponse>('/auth/otp/verify', {
      mobile,
      otp: code,
      code,
    });
  },

  logout: async (): Promise<void> => {
    try {
      await httpClient.post('/auth/logout');
    } catch {
      // Backend uses stateless JWT session
    }
  },
};

export default authApi;

