export function isValidEvmAddress(address: string): boolean {
  if (!address || typeof address !== 'string') return false;
  return /^0x[a-fA-F0-9]{40}$/.test(address.trim());
}

export function isValidSolanaAddress(address: string): boolean {
  if (!address || typeof address !== 'string') return false;
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address.trim());
}

export function isValidAddress(
  address: string,
  chain: 'mst-testnet' | 'solana-devnet' | 'polygon-amoy'
): boolean {
  if (chain === 'solana-devnet') {
    return isValidSolanaAddress(address);
  }
  return isValidEvmAddress(address);
}

export function isValidMobile(mobile: string): boolean {
  if (!mobile || typeof mobile !== 'string') return false;
  const clean = mobile.replace(/[\s-]/g, '');
  return /^\+?[0-9]{8,15}$/.test(clean);
}

export function isValidOtp(otp: string): boolean {
  if (!otp || typeof otp !== 'string') return false;
  return /^\d{6}$/.test(otp.trim());
}

export function validateAmount(
  amount: string,
  available: string
): { valid: boolean; error?: string } {
  const trimmed = amount.trim();
  if (!trimmed) {
    return { valid: false, error: 'Enter amount' };
  }

  const num = parseFloat(trimmed);
  if (isNaN(num) || num <= 0) {
    return { valid: false, error: 'Enter amount > 0' };
  }

  const availNum = parseFloat(available || '0');
  if (num > availNum) {
    return { valid: false, error: 'Exceeds balance' };
  }

  return { valid: true };
}
