import { Router, Request, Response } from 'express';
import { requireAuth, requireMfa } from '../middleware/authGuard';
import { DataStore } from '../storage/store';
import {
  InvalidWorkingPolicy,
  PolicyEvaluationResult,
  parseCoordinate,
  parseWorkingPolicy,
} from '../services/policyService';
import {
  WalletStateError,
  createOrGetWallet,
  evaluateWalletAccess,
  legacyWalletMessage,
  readReadyWalletAddresses,
  signTransaction,
  walletLifecycleStatus,
} from '../services/walletService';
import { getLiveActivity, getLiveBalances } from '../services/chainService';

const router = Router();
const store = DataStore.getInstance();

router.use((_req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
}, requireAuth, requireMfa);

function bodyCoordinates(req: Request) {
  return { lat: parseCoordinate(req.body?.lat), lng: parseCoordinate(req.body?.lng) };
}

function queryCoordinates(req: Request) {
  return {
    lat: parseCoordinate(req.query.lat ?? req.headers['x-client-lat']),
    lng: parseCoordinate(req.query.lng ?? req.headers['x-client-lng']),
  };
}

async function checkWalletAccess(req: Request, coords: ReturnType<typeof bodyCoordinates>) {
  return evaluateWalletAccess(req.user!.userId, coords.lat, coords.lng);
}

function requireAllowed(policyResult: PolicyEvaluationResult): void {
  if (!policyResult.allowed) {
    throw new WalletStateError(policyResult.reason ?? 'Access denied by Working Policy.', 403,
      policyResult.code ?? 'POLICY_DENIED');
  }
}

function handleWalletError(res: Response, error: unknown): void {
  if (error instanceof WalletStateError) {
    res.status(error.statusCode).json({ success: false, code: error.code, error: error.message });
    return;
  }
  if (error instanceof InvalidWorkingPolicy) {
    res.status(400).json({ success: false, error: error.message });
    return;
  }
  console.error('[Wallet] Request failed:', error instanceof Error ? error.message : error);
  res.status(503).json({
    success: false,
    code: 'WALLET_SERVICE_UNAVAILABLE',
    error: 'Wallet service is temporarily unavailable. Please try again.',
  });
}

router.get('/policy', async (req, res) => {
  try {
    const policy = await store.loadPolicy(req.user!.userId);
    res.json({ success: true, policy });
  } catch (error) {
    handleWalletError(res, error);
  }
});

router.put('/policy', async (req, res) => {
  try {
    const policy = parseWorkingPolicy(req.user!.userId, req.body ?? {});
    await store.savePolicy(policy);
    res.json({ success: true, message: 'Working policy saved successfully', policy });
  } catch (error) {
    handleWalletError(res, error);
  }
});

router.post('/policy/evaluate', async (req, res) => {
  try {
    const result = await checkWalletAccess(req, bodyCoordinates(req));
    res.json({ success: true, ...result });
  } catch (error) {
    handleWalletError(res, error);
  }
});

router.post('/check-access', async (req, res) => {
  try {
    const policyResult = await checkWalletAccess(req, bodyCoordinates(req));
    res.json({
      allowed: policyResult.allowed,
      reason: policyResult.reason,
      code: policyResult.code,
      policyResult,
    });
  } catch (error) {
    handleWalletError(res, error);
  }
});

router.get('/status', async (req, res) => {
  try {
    const userId = req.user!.userId;
    const [wallet, policy] = await Promise.all([store.loadWallet(userId), store.loadPolicy(userId)]);
    const status = wallet ? walletLifecycleStatus(wallet) : 'NO_WALLET';
    res.json({
      success: true,
      hasWallet: status === 'READY',
      walletId: wallet?.walletId ?? null,
      status,
      hasPolicy: !!policy,
      mfaVerified: true,
    });
  } catch (error) {
    handleWalletError(res, error);
  }
});

type WalletAddresses = Awaited<ReturnType<typeof readReadyWalletAddresses>>;

function extractAddressStrings(addresses: WalletAddresses) {
  return { mst: addresses.mst.address, solana: addresses.solana.address, bitcoin: addresses.bitcoin.address };
}

async function formatReadyWallet(walletId: string, createdAt: string, addresses: WalletAddresses) {
  const raw = extractAddressStrings(addresses);
  const balances = await getLiveBalances(raw);
  return {
    success: true,
    hasWallet: true,
    wallet: {
      walletId, createdAt, status: 'READY',
      address: raw.mst, balance: balances.mst,
      solanaAddress: raw.solana, solanaBalance: balances.solana,
      bitcoinAddress: raw.bitcoin, bitcoinBalance: balances.bitcoin,
      addresses: raw,
      chains: {
        mst: { network: addresses.mst.network, address: raw.mst, balance: balances.mst },
        solana: { network: addresses.solana.network, address: raw.solana, balance: balances.solana },
        bitcoin: { network: addresses.bitcoin.network, address: raw.bitcoin, balance: balances.bitcoin },
      },
    },
    addresses,
    balances,
  };
}

async function handleWalletGeneration(req: Request, res: Response) {
  try {
    const coords = bodyCoordinates(req);
    requireAllowed(await checkWalletAccess(req, coords));
    const { wallet, isNew, addresses } = await createOrGetWallet(req.user!.userId);
    requireAllowed(await checkWalletAccess(req, coords));
    res.status(isNew ? 201 : 200).json({
      ...await formatReadyWallet(wallet.walletId, wallet.createdAt, addresses),
      isNew,
      walletId: wallet.walletId,
      status: 'READY',
      message: isNew ? 'Wallet created successfully.' : 'Existing wallet retrieved.',
    });
  } catch (error) {
    handleWalletError(res, error);
  }
}

router.post('/create', handleWalletGeneration);
router.post('/generate', handleWalletGeneration);

router.get('/', async (req, res) => {
  try {
    requireAllowed(await checkWalletAccess(req, queryCoordinates(req)));
    const wallet = await store.loadWallet(req.user!.userId);
    if (!wallet) {
      res.json({ success: true, hasWallet: false, wallet: null });
      return;
    }

    const status = walletLifecycleStatus(wallet);
    if (status !== 'READY') {
      const error = status === 'UNAVAILABLE' ? legacyWalletMessage
        : status === 'ERROR' ? 'Wallet creation could not finish. You can retry with the existing wallet.' : undefined;
      res.json({
        success: true,
        hasWallet: true,
        wallet: { walletId: wallet.walletId, status, error, createdAt: wallet.createdAt },
      });
      return;
    }
    const addresses = await readReadyWalletAddresses(wallet);
    res.json(await formatReadyWallet(wallet.walletId, wallet.createdAt, addresses));
  } catch (error) {
    handleWalletError(res, error);
  }
});

async function loadAuthorizedAddresses(req: Request) {
  const policyStatus = await checkWalletAccess(req, queryCoordinates(req));
  requireAllowed(policyStatus);
  const wallet = await store.loadWallet(req.user!.userId);
  if (!wallet) throw new WalletStateError('No wallet exists for this account.', 404, 'NO_WALLET');
  const addresses = await readReadyWalletAddresses(wallet);
  return { walletId: wallet.walletId, userId: wallet.userId, status: 'READY', addresses, policyStatus };
}

router.get('/balances', async (req, res) => {
  try {
    const { addresses } = await loadAuthorizedAddresses(req);
    res.json({ success: true, balances: await getLiveBalances(extractAddressStrings(addresses)) });
  } catch (error) {
    handleWalletError(res, error);
  }
});

async function handleActivity(req: Request, res: Response) {
  try {
    const { addresses } = await loadAuthorizedAddresses(req);
    res.json({ success: true, transactions: await getLiveActivity(extractAddressStrings(addresses)) });
  } catch (error) {
    handleWalletError(res, error);
  }
}

router.get('/transactions', handleActivity);
router.get('/activity', handleActivity);

router.get('/addresses', async (req, res) => {
  try {
    res.json({ success: true, ...await loadAuthorizedAddresses(req) });
  } catch (error) {
    handleWalletError(res, error);
  }
});

router.post('/sign', async (req, res) => {
  try {
    requireAllowed(await checkWalletAccess(req, bodyCoordinates(req)));
    const user = req.user!;
    const { chain, toAddress, amount, data, memo } = req.body || {};
    if (!chain || !toAddress || !amount) {
      res.status(400).json({
        success: false,
        code: 'INVALID_PARAMS',
        error: 'chain, toAddress, and amount are required.',
      });
      return;
    }
    const result = await signTransaction(user.userId, {
      chain,
      toAddress,
      amount,
      data,
      memo,
    });
    res.json(result);
  } catch (error) {
    handleWalletError(res, error);
  }
});

export default router;
