import { Request, Response, NextFunction } from 'express';
import { verifyMfaSchema } from '../utils/validation';
import { sendMfaOtp, verifyMfaOtp } from '../services/mfaService';

export async function handleSendMfa(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;
    const result = await sendMfaOtp(userId);
    res.json(result);
  } catch (err) {
    next(err);
  }
}

export async function handleVerifyMfa(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;
    const validated = verifyMfaSchema.parse(req.body);
    const result = await verifyMfaOtp(userId, validated.otp);
    res.json(result);
  } catch (err) {
    next(err);
  }
}
