import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import {
  handleGoogleLogin,
  handleRequestOtp,
  handleVerifyOtp,
} from '../controllers/authController';

const router = Router();

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  message: { error: 'Too many OTP requests from this IP. Please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

router.post('/google', handleGoogleLogin);
router.post('/otp/request', otpLimiter, handleRequestOtp);
router.post('/otp/verify', otpLimiter, handleVerifyOtp);

export default router;
