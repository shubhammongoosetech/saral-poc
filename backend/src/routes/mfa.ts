import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { requireAuth } from '../middleware/authGuard';
import { handleSendMfa, handleVerifyMfa } from '../controllers/mfaController';

const router = Router();

const mfaLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many MFA attempts. Please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

router.post('/send', requireAuth, mfaLimiter, handleSendMfa);
router.post('/verify', requireAuth, mfaLimiter, handleVerifyMfa);

export default router;
