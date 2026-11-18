/**
 * dkg.ts
 *
 * REST API Routes for Distributed Key Generation (DKG) Sessions.
 */

import { Router } from 'express';
import { requireAuth } from '../middleware/authGuard';
import {
  handleCreateDkgSession,
  handleRegisterDkgParticipant,
  handleStartDkgSession,
  handleGetDkgSessionStatus,
  handleSubmitDkgEncryptedShare,
  handleSubmitDkgProtocolMessage,
  handlePollDkgMessages,
  handleSubmitDkgFinalConfirmation,
  handleGetDkgPublicKey,
} from '../controllers/dkgController';

const router = Router();

// DKG Session Management (Protected by AuthGuard)
router.post('/sessions', requireAuth, handleCreateDkgSession);
router.post('/sessions/:id/register', requireAuth, handleRegisterDkgParticipant);
router.post('/sessions/:id/start', requireAuth, handleStartDkgSession);
router.get('/sessions/:id/status', requireAuth, handleGetDkgSessionStatus);
router.get('/sessions/:id/public-key', requireAuth, handleGetDkgPublicKey);

// Peer-to-Peer Message Routing & Mailboxes
router.post('/sessions/:id/messages/share', requireAuth, handleSubmitDkgEncryptedShare);
router.post('/sessions/:id/messages/protocol', requireAuth, handleSubmitDkgProtocolMessage);
router.get('/sessions/:id/messages/:nodeIndex', requireAuth, handlePollDkgMessages);

// Finalization
router.post('/sessions/:id/finalize', requireAuth, handleSubmitDkgFinalConfirmation);

export default router;
