import { Router } from 'express';
import { MfaController } from '../controllers/mfa.controller';

const router = Router();

router.get('/mfa/status', MfaController.getStatus);
router.post('/mfa/enroll', MfaController.enroll);
router.post('/mfa/send', MfaController.sendOtp);
router.post('/mfa/verify', MfaController.verify);

export default router;
