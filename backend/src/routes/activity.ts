import { Router } from 'express';
import { requireAuth, requireMfa } from '../middleware/authGuard';
import { handleGetActivityLogs } from '../controllers/activityController';

const router = Router();

router.get('/', requireAuth, requireMfa, handleGetActivityLogs);

export default router;

