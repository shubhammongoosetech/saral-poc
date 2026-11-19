export interface User {
  id: string;
  name?: string;
  email?: string;
  mobile?: string;
  login_method: string;
  created_at: string;
}

export interface AuthResponse {
  token: string;
  user: User;
  devOtp?: string;
}

export interface MfaStatusResponse {
  success: boolean;
  enrolled: boolean;
  type?: string;
  verified?: boolean;
}

export interface MfaEnrollResponse {
  success: boolean;
  secret: string;
  qrUri: string;
  recoveryCodes: string[];
  devOtp?: string;
}

export interface MfaOtpResponse {
  devOtp?: string;
  message?: string;
}

export interface MfaVerifyResponse {
  success: boolean;
  token: string;
  hasPolicy: boolean;
  hasWallet: boolean;
}

export interface Policy {
  start_time?: string;
  end_time?: string;
  startTime?: string;
  endTime?: string;
  timezone?: string;
  city?: string;
  lat?: number;
  lng?: number;
  radiusKm?: number;
  radius_km?: number;
  setAt?: string;
  set_at?: string;
}

export interface ProfileResponse {
  user: User;
  hasPolicy: boolean;
  policy: Policy | null;
  hasWallet: boolean;
  mfaVerified?: boolean;
  mfa?: {
    type: string;
    verifiedAt?: string | null;
    verified_at?: string | null;
  } | null;
  topology?: Record<string, unknown>;
}

export interface WalletData {
  address: string;
  balance: string;
  solanaAddress?: string;
  solanaBalance?: string;
  bitcoinAddress?: string;
  bitcoinBalance?: string;
  addresses?: {
    mst?: string;
    solana?: string;
    bitcoin?: string;
  };
}

export interface WalletResponse {
  hasWallet: boolean;
  wallet: WalletData | null;
}

export interface AccessCheckResponse {
  allowed: boolean;
  reason?: string;
}

export interface SignResponse {
  success?: boolean;
  broadcasted?: boolean;
  txHash: string;
  explorerUrl?: string;
  message?: string;
}

export interface Transaction {
  tx_hash: string;
  txHash?: string;
  to_address: string;
  toAddress?: string;
  amount: string;
  created_at: string;
  createdAt?: string;
  status?: string;
  chain?: string;
  direction?: 'sent' | 'received';
}

export interface TransactionsResponse {
  transactions: Transaction[];
}
