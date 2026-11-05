import { Router } from 'express';
import { requireAuth, requireMfa } from '../middleware/authGuard';
import {
  handleGetDevices,
  handleEnrollDevice,
  handleEnrollGuardian,
  handleRevokeDevice,
} from '../controllers/deviceController';

const router = Router();

router.get('/', requireAuth, requireMfa, handleGetDevices);
router.post('/enroll', requireAuth, requireMfa, handleEnrollDevice);
router.post('/guardian', requireAuth, requireMfa, handleEnrollGuardian);
router.delete('/:id', requireAuth, requireMfa, handleRevokeDevice);

export default router;

