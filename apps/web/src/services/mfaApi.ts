import { httpClient } from './httpClient';
import { SESSION_STORE } from '../shared/lib/storage';
import {
  MfaStatusResponse,
  MfaEnrollResponse,
  MfaOtpResponse,
  MfaVerifyResponse,
} from '../shared/api/types';

let enrollment: { token: string | null; request: Promise<MfaEnrollResponse> } | undefined;

export const mfaApi = {
  getStatus: async (): Promise<MfaStatusResponse> => {
    return httpClient.get<MfaStatusResponse>('/mfa/status');
  },

  enroll: async (): Promise<MfaEnrollResponse> => {
    const token = SESSION_STORE.getToken();
    if (enrollment && enrollment.token === token) return enrollment.request;

    const request = httpClient.post<MfaEnrollResponse>('/mfa/enroll').finally(() => {
      if (enrollment?.request === request) enrollment = undefined;
    });
    enrollment = { token, request };
    return request;
  },

  sendMfaOtp: async (): Promise<MfaOtpResponse> => {
    return httpClient.post<MfaOtpResponse>('/mfa/send');
  },

  verifyMfaOtp: async (otp: string): Promise<MfaVerifyResponse> => {
    return httpClient.post<MfaVerifyResponse>('/mfa/verify', { otp });
  },
};

export default mfaApi;

