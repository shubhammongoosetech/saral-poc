/**
 * SARAL Protocol V3 — Global Session Context & Gatekeeper
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authApi } from '../services/authApi';
import {
  UserProfile,
  WorkingPolicy,
  MultiChainAddresses,
  GateStatus,
} from '../types/auth';

interface SessionContextType {
  gate: GateStatus;
  user: UserProfile | null;
  mfaEnrolled: boolean;
  mfaVerified: boolean;
  hasPolicy: boolean;
  hasWallet: boolean;
  policy: WorkingPolicy | null;
  wallet: MultiChainAddresses | null;
  accessRestrictionReason: string | null;
  activeOtpMobile: string | null;
  setActiveOtpMobile: (mobile: string | null) => void;
  devOtp: string | null;
  setDevOtp: (otp: string | null) => void;
  // Methods
  loginWithGoogle: (credential: string) => Promise<void>;
  requestOtp: (mobile: string) => Promise<{ cooldownSeconds: number; devOtp?: string }>;
  verifyOtp: (mobile: string, otp: string) => Promise<void>;
  verifyMfa: (code: string) => Promise<void>;
  savePolicy: (policy: Partial<WorkingPolicy>) => Promise<void>;
  startWalletCreation: () => Promise<void>;
  retryAccessCheck: () => Promise<void>;
  refreshSession: () => Promise<void>;
  logout: () => void;
}

const SessionContext = createContext<SessionContextType | undefined>(undefined);

export const SessionProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [gate, setGate] = useState<GateStatus>('loading');
  const [user, setUser] = useState<UserProfile | null>(null);
  const [mfaEnrolled, setMfaEnrolled] = useState(false);
  const [mfaVerified, setMfaVerified] = useState(false);
  const [hasPolicy, setHasPolicy] = useState(false);
  const [hasWallet, setHasWallet] = useState(false);
  const [policy, setPolicy] = useState<WorkingPolicy | null>(null);
  const [wallet, setWallet] = useState<MultiChainAddresses | null>(null);
  const [accessRestrictionReason, setAccessRestrictionReason] = useState<string | null>(null);
  const [activeOtpMobile, setActiveOtpMobile] = useState<string | null>(null);
  const [devOtp, setDevOtp] = useState<string | null>(null);

  // Helper to obtain GPS coords safely
  const getCoordinates = async (): Promise<{ lat?: number; lng?: number }> => {
    if (!navigator.geolocation) return {};
    return new Promise((resolve) => {
      navigator.geolocation.getCurrentPosition(
        (pos) => resolve({ lat: pos.coords.latitude, lng: pos.coords.longitude }),
        () => resolve({}),
        { timeout: 5000, enableHighAccuracy: true }
      );
    });
  };

  const evaluateAndResolveGate = useCallback(
    async (
      userData: UserProfile,
      mfaVer: boolean,
      hasPol: boolean,
      hasWal: boolean
    ) => {
      setUser(userData);
      setMfaVerified(mfaVer);
      setHasPolicy(hasPol);
      setHasWallet(hasWal);

      if (!mfaVer) {
        setGate('needs-mfa');
        return;
      }

      if (!hasPol) {
        setGate('needs-policy');
        return;
      }

      // Check Working Policy
      const coords = await getCoordinates();
      try {
        const policyEval = await authApi.evaluateWorkingPolicy(coords.lat, coords.lng);
        if (!policyEval.allowed) {
          setAccessRestrictionReason(policyEval.reason || 'Outside authorized working hours or geofence.');
          setGate('access-restricted');
          return;
        }
      } catch (err: any) {
        setAccessRestrictionReason(err.message || 'Working policy evaluation failed.');
        setGate('access-restricted');
        return;
      }

      if (!hasWal) {
        // First-time user needs wallet creation!
        setGate('creating-wallet');
        return;
      }

      // Returning user! Fetch deterministic addresses
      try {
        const addrRes = await authApi.getMultiChainAddresses(coords.lat, coords.lng);
        setWallet(addrRes);
        setGate('ready');
      } catch (err: any) {
        if (err.statusCode === 403) {
          setAccessRestrictionReason(err.message);
          setGate('access-restricted');
        } else {
          console.warn('[Session] Failed to fetch addresses:', err);
          setGate('ready');
        }
      }
    },
    []
  );

  const refreshSession = useCallback(async () => {
    const token = authApi.getToken();
    if (!token) {
      setGate('anonymous');
      setUser(null);
      return;
    }

    try {
      const sess = await authApi.getSession();
      setMfaEnrolled(sess.mfaEnrolled);
      setPolicy(sess.policy);
      await evaluateAndResolveGate(
        sess.user,
        sess.mfaVerified,
        sess.hasPolicy,
        sess.hasWallet
      );
    } catch (_) {
      authApi.logout();
      setGate('anonymous');
      setUser(null);
    }
  }, [evaluateAndResolveGate]);

  useEffect(() => {
    refreshSession();
  }, [refreshSession]);

  const loginWithGoogle = async (credential: string) => {
    setGate('loading');
    const res = await authApi.loginWithGoogle(credential);
    setMfaEnrolled(res.mfaEnrolled);
    await evaluateAndResolveGate(res.user, res.mfaVerified, res.hasPolicy, res.hasWallet);
  };

  const requestOtp = async (mobile: string) => {
    const res = await authApi.requestPhoneOtp(mobile);
    setActiveOtpMobile(mobile);
    if (res.devOtp) setDevOtp(res.devOtp);
    return { cooldownSeconds: res.cooldownSeconds, devOtp: res.devOtp };
  };

  const verifyOtp = async (mobile: string, otp: string) => {
    setGate('loading');
    const res = await authApi.verifyPhoneOtp(mobile, otp);
    setActiveOtpMobile(null);
    setDevOtp(null);
    setMfaEnrolled(res.mfaEnrolled);
    await evaluateAndResolveGate(res.user, res.mfaVerified, res.hasPolicy, res.hasWallet);
  };

  const verifyMfa = async (code: string) => {
    setGate('loading');
    const res = await authApi.verifyMfa(code);
    setMfaVerified(true);
    setHasPolicy(res.hasPolicy);
    setHasWallet(res.hasWallet);

    if (user) {
      await evaluateAndResolveGate(user, true, res.hasPolicy, res.hasWallet);
    } else {
      await refreshSession();
    }
  };

  const savePolicy = async (policyData: Partial<WorkingPolicy>) => {
    setGate('loading');
    const res = await authApi.saveWorkingPolicy(policyData);
    setPolicy(res.policy);
    setHasPolicy(true);

    if (user) {
      await evaluateAndResolveGate(user, mfaVerified, true, hasWallet);
    }
  };

  const startWalletCreation = async () => {
    setGate('loading');
    const coords = await getCoordinates();
    const res = await authApi.createWallet(coords.lat, coords.lng);
    setHasWallet(true);
    setWallet({
      walletId: res.walletId,
      userId: user?.id || '',
      status: 'READY',
      addresses: res.addresses,
    });
    setGate('ready');
  };

  const retryAccessCheck = async () => {
    setGate('loading');
    await refreshSession();
  };

  const logout = () => {
    authApi.logout();
    setUser(null);
    setMfaVerified(false);
    setHasPolicy(false);
    setHasWallet(false);
    setPolicy(null);
    setWallet(null);
    setAccessRestrictionReason(null);
    setGate('anonymous');
  };

  return (
    <SessionContext.Provider
      value={{
        gate,
        user,
        mfaEnrolled,
        mfaVerified,
        hasPolicy,
        hasWallet,
        policy,
        wallet,
        accessRestrictionReason,
        activeOtpMobile,
        setActiveOtpMobile,
        devOtp,
        setDevOtp,
        loginWithGoogle,
        requestOtp,
        verifyOtp,
        verifyMfa,
        savePolicy,
        startWalletCreation,
        retryAccessCheck,
        refreshSession,
        logout,
      }}
    >
      {children}
    </SessionContext.Provider>
  );
};

export const useSession = (): SessionContextType => {
  const context = useContext(SessionContext);
  if (!context) throw new Error('useSession must be used within a SessionProvider');
  return context;
};
