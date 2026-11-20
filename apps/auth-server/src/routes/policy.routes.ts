import { Router } from 'express';
import { PolicyController } from '../controllers/policy.controller';
import { requireAuth } from '../middleware/authGuard';

const router = Router();

router.get('/profile', requireAuth, PolicyController.getProfile);
router.post('/profile/policy', requireAuth, PolicyController.savePolicy);

export default router;
