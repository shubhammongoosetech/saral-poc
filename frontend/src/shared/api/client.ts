import axios from 'axios';
import { SESSION_STORE } from '../lib/storage';

type AuthErrorHandler = {
  onUnauthorized?: () => void;
  onMfaRequired?: () => void;
};

let authErrorHandler: AuthErrorHandler = {};

export function setAuthErrorHandler(handler: AuthErrorHandler) {
  authErrorHandler = handler;
}

export const apiClient = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use((config) => {
  const token = SESSION_STORE.getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    const code = error.response?.data?.code;

    if (status === 401) {
      if (authErrorHandler.onUnauthorized) {
        authErrorHandler.onUnauthorized();
      }
    } else if (status === 403 && code === 'MFA_REQUIRED') {
      if (authErrorHandler.onMfaRequired) {
        authErrorHandler.onMfaRequired();
      }
    }

    return Promise.reject(error);
  }
);
