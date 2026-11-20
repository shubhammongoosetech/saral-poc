import { httpClient } from './httpClient';
import {
  MfaStatusResponse,
  MfaEnrollResponse,
  MfaOtpResponse,
  MfaVerifyResponse,
} from '../shared/api/types';

export const mfaApi = {
  getStatus: async (): Promise<MfaStatusResponse> => {
    return httpClient.get<MfaStatusResponse>('/mfa/status');
  },

  enroll: async (): Promise<MfaEnrollResponse> => {
    return httpClient.post<MfaEnrollResponse>('/mfa/enroll');
  },

  sendMfaOtp: async (): Promise<MfaOtpResponse> => {
    return httpClient.post<MfaOtpResponse>('/mfa/send');
  },

  verifyMfaOtp: async (otp: string): Promise<MfaVerifyResponse> => {
    return httpClient.post<MfaVerifyResponse>('/mfa/verify', { otp });
  },
};

export default mfaApi;

