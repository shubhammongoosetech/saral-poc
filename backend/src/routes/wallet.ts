import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { requireAuth, requireMfa } from '../middleware/authGuard';
import {
  handleGetWallet,
  handleGenerateWallet,
  handleCheckAccess,
  handleSignTransaction,
  handleGetTransactions,
  handleGetClusterHealth,
  handleGetEconomicStats,
  handleInitiateRecovery,
  handleCancelRecovery,
  handleSubmitCustodianApproval,
  handleExecuteRecovery,
  handleGetRecoveryLogs,
} from '../controllers/walletController';

const router = Router();

const signingLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many transaction signing requests. Please wait before retrying.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const recoveryLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many recovery requests. Please wait before retrying.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Standard Wallet Endpoints
router.get('/', requireAuth, requireMfa, handleGetWallet);
router.post('/generate', requireAuth, requireMfa, handleGenerateWallet);
router.post('/check-access', requireAuth, requireMfa, handleCheckAccess);
router.post('/sign', requireAuth, requireMfa, signingLimiter, handleSignTransaction);
router.get('/transactions', requireAuth, requireMfa, handleGetTransactions);

// 27-Node Cluster Health Monitoring
router.get('/cluster-health', requireAuth, requireMfa, handleGetClusterHealth);

// Adaptive Multi-Asset Economic Security Stats (Patent FIG. 4)
router.get('/economic-stats', requireAuth, handleGetEconomicStats);

// Guarded Break-Glass Recovery (Patent FIG. 3)
router.post('/recovery/initiate', requireAuth, requireMfa, recoveryLimiter, handleInitiateRecovery);
router.post('/recovery/cancel', requireAuth, requireMfa, handleCancelRecovery);
router.post('/recovery/approve', requireAuth, handleSubmitCustodianApproval);
router.post('/recovery/execute', requireAuth, handleExecuteRecovery);
router.get('/recovery/logs', requireAuth, requireMfa, handleGetRecoveryLogs);

export default router;
