import { Router } from 'express';
import { WalletController } from '../controllers/wallet.controller';
import { PolicyController } from '../controllers/policy.controller';
import { requireAuth, requireMfa } from '../middleware/authGuard';

const router = Router();

router.get('/', requireAuth, WalletController.getWallet);
router.post('/generate', requireAuth, WalletController.generateWallet);
router.post('/check-access', requireAuth, PolicyController.checkAccess);
router.post('/sign', requireAuth, WalletController.signTransaction);
// Wallet ke recent transactions
router.get('/transactions', requireAuth, WalletController.getTransactions);




// SDK
router.get('/status', requireAuth, WalletController.getStatus);
router.post('/create', requireAuth, requireMfa, WalletController.createWallet);
router.get('/policy', requireAuth, PolicyController.getPolicy);
router.put('/policy', requireAuth, requireMfa, PolicyController.updatePolicy);

// Live coordinates aur server time ke sath working policy evaluate karne ke liye.
router.post('/policy/evaluate', requireAuth, PolicyController.evaluatePolicy);

// Multi-chain (MST, Solana, Bitcoin) live on-chain balances fetch karne ke liye.
router.get('/balances', requireAuth, WalletController.getBalances);

// RAM me derived public addresses return karne ke liye (Database me zero address store hote hain).
router.get('/addresses', requireAuth, WalletController.getAddresses);


export default router;
