import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { requireAuth, requireMfa } from '../middleware/authGuard';
import {
  handleGetWallet,
  handleGenerateWallet,
  handleCheckAccess,
  handleSignTransaction,
  handleGetTransactions,
} from '../controllers/walletController';

const router = Router();

const signingLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many transaction signing requests. Please wait before retrying.' },
  standardHeaders: true,
  legacyHeaders: false,
});

router.get('/', requireAuth, requireMfa, handleGetWallet);
router.post('/generate', requireAuth, requireMfa, handleGenerateWallet);
router.post('/check-access', requireAuth, requireMfa, handleCheckAccess);
router.post('/sign', requireAuth, requireMfa, signingLimiter, handleSignTransaction);
router.get('/transactions', requireAuth, requireMfa, handleGetTransactions);

export default router;
