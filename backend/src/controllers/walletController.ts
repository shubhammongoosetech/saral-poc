/**
 * walletController.ts
 *
 * SARAL Wallet API Controller
 *
 * Implements:
 *  - Wallet retrieval & generation via 3-Domain MPC.
 *  - Real-time distributed cluster health monitoring.
 *  - Zero-Trust Context access evaluation.
 *  - Genuine Threshold MPC transaction signing.
 */

import { Request, Response, NextFunction } from 'express';
import {
  generateWalletSchema,
  sendTransactionSchema,
  prepareTransactionSchema,
  checkAccessSchema,
} from '../utils/validation';
import {
  getExistingWallet,
  generateWallet,
  prepareSigningTransaction,
  executeSigningTransaction,
} from '../services/walletService';
import { evaluateAccessPolicy } from '../services/locationService';
import { nodeCluster } from '../services/nodeClusterService';
import { prisma } from '../config/db';
import { getTopologyConfig } from '../config/topologyConfig';

export async function handleGetWallet(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;
    const sessionId = (req.user as any)?.sessionId || userId;
    const wallet = await getExistingWallet(userId, sessionId);
    if (!wallet) {
      res.json({ hasWallet: false, wallet: null });
      return;
    }
    res.json({ hasWallet: true, wallet });
  } catch (err) {
    next(err);
  }
}

export async function handleGenerateWallet(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;
    generateWalletSchema.parse(req.body ?? {});

    const result = await generateWallet(userId);
    const config = getTopologyConfig();
    res.status(201).json({
      success: true,
      wallet: result,
      message: `SARAL MPC Wallet created. Keys additively distributed across 3 Domains: Foundation (${config.foundation.nodes}), Public (${config.public.nodes}), and Private (${config.private.nodes}) with Zero Complete Private Key Reconstruction.`,
    });
  } catch (err) {
    next(err);
  }
}

export async function handleCheckAccess(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;
    const validated = checkAccessSchema.parse(req.body);

    const result = await evaluateAccessPolicy(
      userId,
      req.user!.loginMethod,
      req.user!.mfaVerified,
      validated.lat,
      validated.lng
    );

    res.json(result);
  } catch (err) {
    next(err);
  }
}

export async function handlePrepareTransaction(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;
    const validated = prepareTransactionSchema.parse(req.body);

    const result = await prepareSigningTransaction(
      userId,
      req.user!.loginMethod,
      req.user!.mfaVerified,
      validated.toAddress,
      validated.amount,
      validated.lat,
      validated.lng,
      validated.chain,
      validated.memo,
      (req.user as any)?.sessionId || userId
    );

    res.json(result);
  } catch (err: any) {
    if (err.message && err.message.includes('Access Denied')) {
      res.status(403).json({ error: err.message });
      return;
    }
    next(err);
  }
}

export async function handleSignTransaction(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;
    const validated = sendTransactionSchema.parse(req.body);

    const result = await executeSigningTransaction(
      userId,
      req.user!.loginMethod,
      req.user!.mfaVerified,
      validated.toAddress,
      validated.amount,
      validated.lat,
      validated.lng,
      validated.chain,
      (req.user as any)?.sessionId || userId
    );

    res.status(result.broadcasted ? 200 : 400).json({
      success: result.broadcasted,
      ...(!result.broadcasted ? { error: result.message } : {}),
      txHash: result.txHash,
      broadcasted: result.broadcasted,
      message: result.message,
      explorerUrl: result.explorerUrl,
      domainsSigned: result.domainsSigned,
      signature: result.signature,
    });
  } catch (err: any) {
    if (err.message && err.message.includes('Access Denied')) {
      res.status(403).json({ error: err.message });
      return;
    }
    next(err);
  }
}

export async function handleGetTransactions(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;
    const chain = req.query.chain as string | undefined;

    const rawTx = await prisma.transaction.findMany({
      where: {
        userId,
        ...(chain ? { chain } : {}),
      },
      orderBy: { createdAt: 'desc' },
      take: 50,
      select: { txHash: true, toAddress: true, amount: true, status: true, chain: true, createdAt: true },
    });

    const transactions = rawTx.map((t) => ({
      tx_hash: t.txHash,
      to_address: t.toAddress,
      amount: t.amount,
      status: t.status,
      chain: t.chain,
      created_at: t.createdAt.toISOString(),
      txHash: t.txHash,
      toAddress: t.toAddress,
      createdAt: t.createdAt.toISOString(),
    }));

    res.json({ transactions });
  } catch (err) {
    next(err);
  }
}

/**
 * Node Cluster Health Check Endpoint
 */
export async function handleGetClusterHealth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;
    const status = await nodeCluster.checkClusterHealth(userId);
    res.json(status);
  } catch (err) {
    next(err);
  }
}
