import { SESSION_STORE } from '../shared/lib/storage';

export interface RequestOptions extends Omit<RequestInit, 'body'> {
  params?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  timeoutMs?: number;
}

export interface AuthErrorHandler {
  onUnauthorized?: () => void;
  onMfaRequired?: () => void;
}

export class HttpError extends Error {
  public status: number;
  public statusText: string;
  public data: any;
  public code?: string;

  constructor(status: number, statusText: string, data: any) {
    const message = data?.error || data?.message || `HTTP ${status}: ${statusText}`;
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.statusText = statusText;
    this.data = data;
    this.code = data?.code;
  }
}

let authErrorHandler: AuthErrorHandler = {};

export function setAuthErrorHandler(handler: AuthErrorHandler): void {
  authErrorHandler = handler;
}

export class HttpClient {
  private baseUrl: string;
  private defaultTimeoutMs: number;

  constructor(baseUrl: string = '/api', defaultTimeoutMs: number = 15000) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.defaultTimeoutMs = defaultTimeoutMs;
  }

  public async request<T = any>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const {
      params,
      body,
      headers: customHeaders = {},
      timeoutMs = this.defaultTimeoutMs,
      signal: callerSignal,
      credentials = 'include',
      ...rest
    } = options;

    let url = endpoint.startsWith('http')
      ? endpoint
      : `${this.baseUrl}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;

    if (params) {
      const searchParams = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) {
        if (v !== undefined) {
          searchParams.append(k, String(v));
        }
      }
      const qs = searchParams.toString();
      if (qs) {
        url += (url.includes('?') ? '&' : '?') + qs;
      }
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let abortListener: (() => void) | undefined;
    if (callerSignal) {
      if (callerSignal.aborted) {
        clearTimeout(timer);
        throw new DOMException('Aborted', 'AbortError');
      }
      abortListener = () => controller.abort();
      callerSignal.addEventListener('abort', abortListener);
    }

    const headers = new Headers(customHeaders as HeadersInit);
    if (!headers.has('Content-Type') && body !== undefined && !(body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }
    headers.set('X-Requested-With', 'XMLHttpRequest');

    const token = SESSION_STORE.getToken();
    if (token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    try {
      const response = await fetch(url, {
        ...rest,
        headers,
        credentials,
        signal: controller.signal,
        body: body !== undefined ? (body instanceof FormData ? body : JSON.stringify(body)) : undefined,
      });

      const contentType = response.headers.get('content-type') || '';
      let data: any;
      if (contentType.includes('application/json')) {
        data = await response.json();
      } else {
        data = await response.text();
      }

      if (!response.ok) {
        const error = new HttpError(response.status, response.statusText, data);
        if (response.status === 401) {
          authErrorHandler.onUnauthorized?.();
        } else if (response.status === 403 && data?.code === 'MFA_REQUIRED') {
          authErrorHandler.onMfaRequired?.();
        }
        throw error;
      }

      return data as T;
    } finally {
      clearTimeout(timer);
      if (callerSignal && abortListener) {
        callerSignal.removeEventListener('abort', abortListener);
      }
    }
  }

  public get<T = any>(endpoint: string, options: Omit<RequestOptions, 'body'> = {}): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'GET' });
  }

  public post<T = any>(
    endpoint: string,
    body?: unknown,
    options: Omit<RequestOptions, 'body'> = {}
  ): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'POST', body });
  }

  public put<T = any>(
    endpoint: string,
    body?: unknown,
    options: Omit<RequestOptions, 'body'> = {}
  ): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'PUT', body });
  }

  public delete<T = any>(endpoint: string, options: Omit<RequestOptions, 'body'> = {}): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'DELETE' });
  }
}

export const httpClient = new HttpClient('/api');
export default httpClient;

