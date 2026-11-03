import { z } from 'zod';

export const googleAuthSchema = z.object({
  credential: z.string().min(1, 'Google credential token is required'),
});

export const requestOtpSchema = z.object({
  mobile: z.string().regex(/^\+?[1-9]\d{7,14}$/, 'Invalid mobile phone number format (e.g. +919876543210)'),
});

export const verifyOtpSchema = z.object({
  mobile: z.string().min(8),
  otp: z.string().length(6, 'OTP must be 6 digits'),
});

export const verifyMfaSchema = z.object({
  otp: z.string().length(6, 'MFA OTP must be 6 digits'),
});

export const workingPolicySchema = z.object({
  startTime: z.string().regex(/^([01]\d|2[0-3]):([0-5]\d)$/, 'Start time must be HH:MM format (24-hour)'),
  endTime: z.string().regex(/^([01]\d|2[0-3]):([0-5]\d)$/, 'End time must be HH:MM format (24-hour)'),
  timezone: z.string().min(1, 'Timezone is required').default('Asia/Kolkata'),
  city: z.string().min(1, 'City is required'),
  lat: z.number().min(-90).max(90, 'Invalid latitude'),
  lng: z.number().min(-180).max(180, 'Invalid longitude'),
  radiusKm: z.number().min(1).max(500).optional().default(25),
});

export const generateWalletSchema = z.object({
  n: z.number().int().min(2).max(255).optional(),
  threshold: z.number().int().min(2).max(255).optional(),
}).refine((data) => {
  if (data.n !== undefined && data.threshold !== undefined) {
    return data.threshold <= data.n;
  }
  return true;
}, {
  message: 'Threshold must be less than or equal to total shares (n)',
  path: ['threshold'],
});

export const sendTransactionSchema = z.object({
  toAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/, 'Invalid Ethereum recipient address'),
  amount: z.string().regex(/^\d+(\.\d+)?$/, 'Amount must be a valid positive number string'),
  lat: z.number().min(-90).max(90).optional(),
  lng: z.number().min(-180).max(180).optional(),
});

export const checkAccessSchema = z.object({
  lat: z.number().min(-90).max(90).optional(),
  lng: z.number().min(-180).max(180).optional(),
});
