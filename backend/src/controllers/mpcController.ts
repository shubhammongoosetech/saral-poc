/**
 * mpcController.ts
 *
 * REST API Controller for Multi-Party Computation (MPC) Threshold Signing.
 */

import { Request, Response, NextFunction } from 'express';
import { mpcSigningSessionManager } from '../mpc/MpcSigningSessionManager';
import { createSigningSessionSchema } from '../utils/dkgValidation';

function getParam(param: string | string[] | undefined): string {
  if (Array.isArray(param)) return param[0] || '';
  return param || '';
}

export async function handleCreateSigningSession(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const validated = createSigningSessionSchema.parse(req.body);
    const chainId = BigInt(validated.chainId);

    const session = mpcSigningSessionManager.createSigningSession({
      unsignedTxSerialized: validated.unsignedTxSerialized,
      chainId,
      expectedAggregatedPublicKeyHex: validated.expectedAggregatedPublicKeyHex,
      thresholds: validated.thresholds,
      participants: validated.participants,
      timeoutMs: validated.timeoutMs,
    });

    res.status(201).json({
      success: true,
      sessionId: session.sessionId,
      msgHashHex: session.msgHashHex,
      thresholds: session.thresholds,
      participantsCount: session.participants.length,
      expiresAt: session.expiresAt,
      message: 'Threshold signing session initialized. Authorized nodes may now submit Round 1 commitments.',
    });
  } catch (err) {
    next(err);
  }
}

export async function handleGetSigningSessionStatus(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const sessionId = getParam(req.params.id);
    const status = mpcSigningSessionManager.getSessionStatus(sessionId);

    if (!status.config) {
      res.status(404).json({ error: `Signing session '${sessionId}' not found` });
      return;
    }

    res.status(200).json({
      sessionId,
      state: status.state,
      round1CommitmentsCount: status.round1CommitmentsCount,
      round1DecommitmentsCount: status.round1DecommitmentsCount,
      round2DeltaSharesCount: status.round2DeltaSharesCount,
      round3PartialSigsCount: status.round3PartialSigsCount,
    });
  } catch (err) {
    next(err);
  }
}

export async function handleSubmitRound1Commitment(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const sessionId = getParam(req.params.id);
    const { from, commitmentHex, signatureHex, timestamp } = req.body;

    mpcSigningSessionManager.submitRound1Commitment({
      type: 'ROUND1_COMMIT',
      sessionId,
      from,
      commitmentHex,
      signatureHex,
      timestamp: timestamp || Date.now(),
    });

    const status = mpcSigningSessionManager.getSessionStatus(sessionId);
    res.status(200).json({
      success: true,
      sessionId,
      state: status.state,
      commitmentsCount: status.round1CommitmentsCount,
    });
  } catch (err) {
    next(err);
  }
}

export async function handleSubmitRound1Decommitment(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const sessionId = getParam(req.params.id);
    const { from, gammaPointHex, paillierNHex, encryptedGammaHex, encryptedWHex, signatureHex, timestamp } = req.body;

    mpcSigningSessionManager.submitRound1Decommitment({
      type: 'ROUND1_DECOMMIT',
      sessionId,
      from,
      gammaPointHex,
      paillierNHex,
      encryptedGammaHex,
      encryptedWHex,
      signatureHex,
      timestamp: timestamp || Date.now(),
    });

    const status = mpcSigningSessionManager.getSessionStatus(sessionId);
    res.status(200).json({
      success: true,
      sessionId,
      state: status.state,
      decommitmentsCount: status.round1DecommitmentsCount,
    });
  } catch (err) {
    next(err);
  }
}

export async function handleSubmitRound2Delta(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const sessionId = getParam(req.params.id);
    const { from, deltaShareHex, signatureHex, timestamp } = req.body;

    const resObj = mpcSigningSessionManager.submitRound2DeltaShare({
      type: 'ROUND2_DELTA_SHARE',
      sessionId,
      from,
      deltaShareHex,
      signatureHex,
      timestamp: timestamp || Date.now(),
    });

    const status = mpcSigningSessionManager.getSessionStatus(sessionId);
    res.status(200).json({
      success: true,
      sessionId,
      state: status.state,
      deltaSharesCount: status.round2DeltaSharesCount,
      rHex: resObj.rHex,
    });
  } catch (err) {
    next(err);
  }
}

export async function handleSubmitRound3PartialSig(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const sessionId = getParam(req.params.id);
    const { from, sShareHex, signatureHex, timestamp } = req.body;

    const finalSig = mpcSigningSessionManager.submitRound3PartialSignature({
      type: 'ROUND3_PARTIAL_SIG',
      sessionId,
      from,
      sShareHex,
      signatureHex,
      timestamp: timestamp || Date.now(),
    });

    const status = mpcSigningSessionManager.getSessionStatus(sessionId);
    res.status(200).json({
      success: true,
      sessionId,
      state: status.state,
      isComplete: status.state === 'SIGNATURE_COMPLETED',
      signature: finalSig || undefined,
    });
  } catch (err) {
    next(err);
  }
}

export async function handleGetFinalSignature(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const sessionId = getParam(req.params.id);
    const finalSig = mpcSigningSessionManager.getSignatureResult(sessionId);

    if (!finalSig) {
      const status = mpcSigningSessionManager.getSessionStatus(sessionId);
      res.status(400).json({
        error: `Signature not completed yet (current state: ${status.state || 'UNKNOWN'})`,
      });
      return;
    }

    res.status(200).json({
      sessionId,
      r: finalSig.r,
      s: finalSig.s,
      yParity: finalSig.yParity,
      v: finalSig.v,
      rawSignedTx: finalSig.rawSignedTx,
      txHash: finalSig.txHash,
      verified: finalSig.verified,
      signingQuorum: finalSig.signingQuorum,
      completedAt: finalSig.completedAt,
    });
  } catch (err) {
    next(err);
  }
}
