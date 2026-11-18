/**
 * dkgController.ts
 *
 * REST API Controller for Dealerless DKG Sessions.
 */

import { Request, Response, NextFunction } from 'express';
import { dkgSessionManager } from '../dkg/DkgSessionManager';
import {
  createDkgSessionSchema,
  registerDkgParticipantSchema,
  submitEncryptedShareSchema,
  submitProtocolMessageSchema,
  submitDkgFinalConfirmationSchema,
} from '../utils/dkgValidation';

function getParam(param: string | string[] | undefined): string {
  if (Array.isArray(param)) return param[0] || '';
  return param || '';
}

export async function handleCreateDkgSession(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const validated = createDkgSessionSchema.parse(req.body);
    const session = dkgSessionManager.createSession(
      validated.domain,
      validated.n,
      validated.t,
      validated.f,
      validated.timeoutMs
    );

    res.status(201).json({
      success: true,
      session,
      message: `DKG Session created for domain ${validated.domain} (n=${session.n}, t=${session.t}, f=${session.f}, threshold=${session.threshold})`,
    });
  } catch (err) {
    next(err);
  }
}

export async function handleRegisterDkgParticipant(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const sessionId = getParam(req.params.id);
    const validated = registerDkgParticipantSchema.parse(req.body);

    dkgSessionManager.registerParticipant(sessionId, validated);

    const status = dkgSessionManager.getSessionStatus(sessionId);
    res.status(200).json({
      success: true,
      sessionId,
      participantId: validated.id,
      nodeIndex: validated.nodeIndex,
      sessionState: status.state,
      registeredParticipants: status.registeredParticipants,
      requiredParticipants: status.config?.n,
    });
  } catch (err) {
    next(err);
  }
}

export async function handleStartDkgSession(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const sessionId = getParam(req.params.id);
    dkgSessionManager.startDkg(sessionId);
    const status = dkgSessionManager.getSessionStatus(sessionId);

    res.status(200).json({
      success: true,
      sessionId,
      sessionState: status.state,
      message: 'Dealerless DKG protocol started. Participants may now distribute polynomials and commitments.',
    });
  } catch (err) {
    next(err);
  }
}

export async function handleGetDkgSessionStatus(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const sessionId = getParam(req.params.id);
    const status = dkgSessionManager.getSessionStatus(sessionId);

    if (!status.config) {
      res.status(404).json({ error: `DKG Session '${sessionId}' not found` });
      return;
    }

    res.status(200).json({
      sessionId,
      state: status.state,
      config: status.config,
      registeredParticipants: status.registeredParticipants,
      completedParticipants: status.completedParticipants,
    });
  } catch (err) {
    next(err);
  }
}

export async function handleSubmitDkgEncryptedShare(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const sessionId = getParam(req.params.id);
    const validated = submitEncryptedShareSchema.parse(req.body);

    dkgSessionManager.submitEncryptedShare({
      type: 'ENCRYPTED_SHARE',
      sessionId,
      domain: req.body.domain,
      ...validated,
    });

    res.status(200).json({ success: true, message: 'Encrypted share envelope routed successfully' });
  } catch (err) {
    next(err);
  }
}

export async function handleSubmitDkgProtocolMessage(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const sessionId = getParam(req.params.id);
    const validated = submitProtocolMessageSchema.parse(req.body);

    dkgSessionManager.submitProtocolMessage({
      type: 'DKG_PROTOCOL_MSG',
      sessionId,
      domain: req.body.domain,
      ...validated,
    });

    res.status(200).json({ success: true, message: 'Protocol message routed successfully' });
  } catch (err) {
    next(err);
  }
}

export async function handlePollDkgMessages(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const sessionId = getParam(req.params.id);
    const nodeIndex = parseInt(getParam(req.params.nodeIndex), 10);

    const messages = dkgSessionManager.pollMessages(sessionId, nodeIndex);
    res.status(200).json({
      sessionId,
      nodeIndex,
      count: messages.length,
      messages,
    });
  } catch (err) {
    next(err);
  }
}

export async function handleSubmitDkgFinalConfirmation(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const sessionId = getParam(req.params.id);
    const validated = submitDkgFinalConfirmationSchema.parse(req.body);

    const result = dkgSessionManager.submitFinalConfirmation(sessionId, validated.nodeIndex, {
      domainPublicKeyHex: validated.domainPublicKeyHex,
      commitments: validated.commitments,
      agreedQ: validated.agreedQ,
    });

    const status = dkgSessionManager.getSessionStatus(sessionId);

    res.status(200).json({
      success: true,
      sessionId,
      sessionState: status.state,
      isFinalized: status.state === 'DKG_COMPLETED',
      result: result || undefined,
    });
  } catch (err) {
    next(err);
  }
}

export async function handleGetDkgPublicKey(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const sessionId = getParam(req.params.id);
    const result = dkgSessionManager.getFinalResult(sessionId);

    if (!result) {
      const status = dkgSessionManager.getSessionStatus(sessionId);
      res.status(400).json({
        error: `DKG session not finalized yet (current state: ${status.state || 'UNKNOWN'})`,
      });
      return;
    }

    res.status(200).json({
      sessionId,
      domain: result.domain,
      domainPublicKeyHex: result.domainPublicKeyHex,
      commitments: result.commitments,
      agreedQ: result.agreedQ,
      threshold: result.threshold,
      completedAt: result.completedAt,
    });
  } catch (err) {
    next(err);
  }
}
