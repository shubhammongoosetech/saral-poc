import { Request, Response, NextFunction } from 'express';
import {
  generateWalletSchema,
  sendTransactionSchema,
  checkAccessSchema,
} from '../utils/validation';
import {
  getExistingWallet,
  generateWallet,
  executeSigningTransaction,
} from '../services/walletService';
import { evaluateAccessPolicy } from '../services/locationService';
import { prisma } from '../config/db';

export async function handleGetWallet(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;
    const wallet = await getExistingWallet(userId);
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
    const validated = generateWalletSchema.parse(req.body);

    const result = await generateWallet(userId, validated.n, validated.threshold);
    res.status(201).json({
      success: true,
      wallet: result,
      message: `Wallet created. Private key split into ${result.n * 3} Docker containers (${result.n} shares × 3 categories) using Shamir Secret Sharing`,
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
      validated.lng
    );

    res.json({
      success: true,
      txHash: result.txHash,
      broadcasted: result.broadcasted,
      message: result.message,
      explorerUrl: result.explorerUrl,
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

    const rawTx = await prisma.transaction.findMany({
      where:   { userId },
      orderBy: { createdAt: 'desc' },
      take:    50,
      select:  { txHash: true, toAddress: true, amount: true, createdAt: true },
    });

    // Provide both snake_case (expected by frontend) and camelCase
    const transactions = rawTx.map((t) => ({
      tx_hash:    t.txHash,
      to_address: t.toAddress,
      amount:     t.amount,
      created_at: t.createdAt.toISOString(),
      txHash:     t.txHash,
      toAddress:  t.toAddress,
      createdAt:  t.createdAt.toISOString(),
    }));

    res.json({ transactions });
  } catch (err) {
    next(err);
  }
}
