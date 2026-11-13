import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { requireAuth, requireMfa } from '../middleware/authGuard';
import {
  handleGetWallet,
  handleGenerateWallet,
  handleCheckAccess,
  handlePrepareTransaction,
  handleSignTransaction,
  handleGetTransactions,
  handleGetClusterHealth,
} from '../controllers/walletController';

const router = Router();

const signingLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many transaction signing requests. Please wait before retrying.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Standard Wallet Endpoints
router.get('/', requireAuth, requireMfa, handleGetWallet);
router.post('/generate', requireAuth, requireMfa, handleGenerateWallet);
router.post('/check-access', requireAuth, requireMfa, handleCheckAccess);
router.post('/prepare', requireAuth, requireMfa, handlePrepareTransaction);
router.post('/sign', requireAuth, requireMfa, signingLimiter, handleSignTransaction);
router.get('/transactions', requireAuth, requireMfa, handleGetTransactions);

// 19-Node Cluster Health Monitoring
router.get('/cluster-health', requireAuth, requireMfa, handleGetClusterHealth);

export default router;
