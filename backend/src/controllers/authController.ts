import { Request, Response, NextFunction } from 'express';
import {
  googleAuthSchema,
  requestOtpSchema,
  verifyOtpSchema,
} from '../utils/validation';
import {
  verifyGoogleAuth,
  requestMobileOtp,
  verifyMobileOtp,
} from '../services/authService';

export async function handleGoogleLogin(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const validated = googleAuthSchema.parse(req.body);
    console.log("validate", validated)
    const result = await verifyGoogleAuth(validated.credential);
    res.json(result);
  } catch (err) {
    next(err);
  }
}

export async function handleRequestOtp(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const validated = requestOtpSchema.parse(req.body);
    const result = await requestMobileOtp(validated.mobile);
    res.json(result);
  } catch (err) {
    next(err);
  }
}

export async function handleVerifyOtp(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const validated = verifyOtpSchema.parse(req.body);
    const result = await verifyMobileOtp(validated.mobile, validated.otp);
    res.json(result);
  } catch (err) {
    next(err);
  }
}
