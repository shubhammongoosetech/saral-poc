/**
 * SARAL Protocol V3 — Wallet & Policy Management Routes
 *
 * Implements:
 * 1. Strict One-User-One-Wallet Enforcement.
 * 2. Zero-Address Storage in Database: No addresses or public keys stored in database.
 * 3. Working Policy Evaluation: Authoritative time and location checking.
 * 4. Deterministic Address Recomputation in RAM.
 */

import { Router, Request, Response } from 'express';
import { requireAuth, requireMfa } from '../middleware/authGuard';
import { DataStore, WorkingPolicyRecord } from '../storage/store';
import {
  evaluateWorkingPolicy,
} from '../services/policyService';
import {
  createOrGetWallet,
  getAuthenticatedWalletAddresses,
} from '../services/walletService';

const router = Router();
const store = DataStore.getInstance();

// GET /wallet/policy
router.get('/policy', requireAuth, (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const policy = store.getPolicy(userId);
  res.json({
    success: true,
    policy: policy || null,
  });
});

// PUT /wallet/policy (Requires MFA)
router.put('/policy', requireAuth, requireMfa, (req: Request, res: Response) => {
  try {
    const userId = req.user!.userId;
    const {
      timeRestrictionEnabled = true,
      startTime = '09:00',
      endTime = '18:00',
      days = ['MON', 'TUE', 'WED', 'THU', 'FRI'],
      timezone = 'Asia/Kolkata',
      expiresAt,
      locationRestrictionEnabled = false,
      allowedRegion = 'Primary Workspace',
      geofenceEnabled = false,
      lat,
      lng,
      radiusMeters = 25000,
    } = req.body;

    const record: WorkingPolicyRecord = {
      userId,
      timeRestrictionEnabled: Boolean(timeRestrictionEnabled),
      startTime,
      endTime,
      days: Array.isArray(days) ? days : ['MON', 'TUE', 'WED', 'THU', 'FRI'],
      timezone,
      expiresAt,
      locationRestrictionEnabled: Boolean(locationRestrictionEnabled),
      allowedRegion,
      geofenceEnabled: Boolean(geofenceEnabled),
      lat: lat !== undefined ? Number(lat) : undefined,
      lng: lng !== undefined ? Number(lng) : undefined,
      radiusMeters: radiusMeters !== undefined ? Number(radiusMeters) : 25000,
      updatedAt: new Date().toISOString(),
    };

    store.savePolicy(record);

    res.json({
      success: true,
      message: 'Working policy saved successfully',
      policy: record,
    });
  } catch (err: any) {
    res.status(400).json({ success: false, error: err.message || 'Failed to save policy' });
  }
});

// POST /wallet/policy/evaluate
router.post('/policy/evaluate', requireAuth, (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const lat = req.body?.lat !== undefined ? Number(req.body.lat) : undefined;
  const lng = req.body?.lng !== undefined ? Number(req.body.lng) : undefined;

  const result = evaluateWorkingPolicy(userId, lat, lng);
  res.json({
    success: true,
    ...result,
  });
});

// GET /wallet/status
router.get('/status', requireAuth, (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const wallet = store.getWalletByUserId(userId);
  const policy = store.getPolicy(userId);
  const mfa = store.getMfa(userId);

  res.json({
    success: true,
    hasWallet: !!wallet && wallet.status === 'READY',
    walletId: wallet?.walletId || null,
    status: wallet?.status || 'NO_WALLET',
    hasPolicy: !!policy,
    mfaVerified: !!mfa?.verifiedAt,
  });
});

// POST /wallet/create (Strict One-User-One-Wallet Idempotent Creation)
router.post('/create', requireAuth, requireMfa, async (req: Request, res: Response) => {
  try {
    const userId = req.user!.userId;

    // Check policy before creation
    const lat = req.body?.lat !== undefined ? Number(req.body.lat) : undefined;
    const lng = req.body?.lng !== undefined ? Number(req.body.lng) : undefined;
    const policyResult = evaluateWorkingPolicy(userId, lat, lng);

    if (!policyResult.allowed) {
      res.status(403).json({
        success: false,
        error: policyResult.reason || 'Access denied by Working Policy',
        policyResult,
      });
      return;
    }

    const result = await createOrGetWallet(userId);
    res.status(result.isNew ? 201 : 200).json({
      success: true,
      isNew: result.isNew,
      walletId: result.wallet.walletId,
      status: result.wallet.status,
      message: result.isNew
        ? 'SARAL Wallet created successfully. Keys distributed across 3 Domains.'
        : 'Existing SARAL Wallet retrieved. One-user-one-wallet invariant preserved.',
      addresses: result.addresses,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message || 'Failed to initialize wallet' });
  }
});

// GET /wallet
router.get('/', requireAuth, (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const wallet = store.getWalletByUserId(userId);
  if (!wallet) {
    res.json({ success: true, hasWallet: false, wallet: null });
    return;
  }

  // Returns ONLY metadata (NO addresses in database!)
  res.json({
    success: true,
    hasWallet: true,
    wallet: {
      walletId: wallet.walletId,
      status: wallet.status,
      keyReferences: wallet.keyReferences,
      createdAt: wallet.createdAt,
    },
  });
});

// GET /wallet/addresses (Requires Auth + Policy check; derives addresses in RAM)
router.get('/addresses', requireAuth, (req: Request, res: Response) => {
  try {
    const userId = req.user!.userId;
    const lat = req.query?.lat !== undefined ? Number(req.query.lat) : undefined;
    const lng = req.query?.lng !== undefined ? Number(req.query.lng) : undefined;

    const result = getAuthenticatedWalletAddresses(userId, lat, lng);
    res.json({
      success: true,
      ...result,
    });
  } catch (err: any) {
    const status = err.statusCode || 500;
    res.status(status).json({
      success: false,
      error: err.message || 'Failed to retrieve wallet addresses',
      policyResult: err.policyResult || null,
    });
  }
});

export default router;
