import { Router } from 'express';
import authRouter from './auth.routes';
import mfaRouter from './mfa.routes';
import policyRouter from './policy.routes';

const router = Router();

// Modular feature routes aggregation
router.use('/', authRouter);
router.use('/', mfaRouter);
router.use('/', policyRouter);

export default router;
