/**
 * mpc.ts
 *
 * REST API Routes for Multi-Party Computation (MPC) Threshold Signing Sessions.
 */

import { Router } from 'express';
import { requireAuth } from '../middleware/authGuard';
import {
  handleCreateSigningSession,
  handleGetSigningSessionStatus,
  handleSubmitRound1Commitment,
  handleSubmitRound1Decommitment,
  handleSubmitRound2Delta,
  handleSubmitRound3PartialSig,
  handleGetFinalSignature,
} from '../controllers/mpcController';

const router = Router();

// Signing Session Lifecycle (Protected by AuthGuard)
router.post('/signing/sessions', requireAuth, handleCreateSigningSession);
router.get('/signing/sessions/:id/status', requireAuth, handleGetSigningSessionStatus);
router.get('/signing/sessions/:id/signature', requireAuth, handleGetFinalSignature);

// Interactive Protocol Round Messages
router.post('/signing/sessions/:id/messages/commit', requireAuth, handleSubmitRound1Commitment);
router.post('/signing/sessions/:id/messages/decommit', requireAuth, handleSubmitRound1Decommitment);
router.post('/signing/sessions/:id/messages/delta', requireAuth, handleSubmitRound2Delta);
router.post('/signing/sessions/:id/messages/partial-sig', requireAuth, handleSubmitRound3PartialSig);

export default router;
