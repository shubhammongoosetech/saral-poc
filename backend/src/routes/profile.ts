import { Router } from 'express';
import { requireAuth, requireMfa } from '../middleware/authGuard';
import { handleGetProfile, handleSetPolicy } from '../controllers/profileController';

const router = Router();

router.get('/', requireAuth, handleGetProfile);
router.post('/policy', requireAuth, requireMfa, handleSetPolicy);

export default router;
