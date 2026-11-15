export function truncateAddress(addr: string, start = 6, end = 4): string {
  if (!addr || typeof addr !== 'string') return '';
  if (addr.length <= start + end) return addr;
  return `${addr.slice(0, start)}...${addr.slice(-end)}`;
}

export function formatAmount(val: string | number, maxDecimals = 4): string {
  const num = typeof val === 'number' ? val : parseFloat(val);
  if (isNaN(num)) return '0.0000';
  return num.toLocaleString(undefined, {
    minimumFractionDigits: 4,
    maximumFractionDigits: maxDecimals,
  });
}

export function formatRelativeTime(dateStr: string): string {
  if (!dateStr) return '';
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
  });
}

export function mapApiError(err: unknown, fallback = 'Request failed'): string {
  if (!err) return fallback;

  const errObj = err as {
    response?: { data?: { code?: string; error?: string; message?: string; error_code?: string } };
    code?: string;
    message?: string;
  };

  const code =
    errObj.response?.data?.code ||
    errObj.response?.data?.error_code ||
    errObj.code;

  const rawMsg =
    errObj.response?.data?.error ||
    errObj.response?.data?.message ||
    errObj.message ||
    '';

  const normalized = (code || rawMsg).toUpperCase();

  if (normalized.includes('MFA_REQUIRED')) return 'MFA verification required';
  if (normalized.includes('OUTSIDE_HOURS') || normalized.includes('WORKING_HOURS')) {
    return 'Outside authorized working hours';
  }
  if (normalized.includes('LOCATION') || normalized.includes('GEO') || normalized.includes('RADIUS')) {
    return 'Outside authorized location';
  }
  if (normalized.includes('POLICY')) return 'Transaction violates working policy';
  if (normalized.includes('INSUFFICIENT')) return 'Insufficient balance';
  if (normalized.includes('INVALID_OTP') || normalized.includes('OTP')) return 'Invalid verification code';
  if (normalized.includes('EXPIRED')) return 'Session expired';
  if (normalized.includes('NETWORK') || errObj.message?.includes('Network Error')) {
    return 'Network connection error';
  }

  if (typeof rawMsg === 'string' && rawMsg.length > 0 && rawMsg.length <= 80 && !rawMsg.includes('at ')) {
    return rawMsg;
  }

  return fallback;
}
