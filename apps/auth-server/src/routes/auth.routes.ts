import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { requireAuth } from '../middleware/authGuard';

const router = Router();

// Server ki live health aur uptime status check karne ke liye.
router.get('/health', AuthController.healthCheck);


router.post('/auth/otp/request', AuthController.requestOtp);
router.post('/auth/otp/verify', AuthController.verifyOtp);

// Mesh operators aur coordinators ke liye RS256 JWT token issue karne ke liye.
router.post('/auth/token', AuthController.issueToken);

// Security audit ya emergency me admin key rotate karne ke liye.
router.post('/auth/rotate-admin-key', AuthController.rotateAdminKey);

// Go verifier nodes ke liye RSA public key (PEM) download karne ke liye.
router.get('/auth/public-key', AuthController.getPublicKeyPem);

// Google One-Tap / Sign-In ke liye.
router.post('/auth/google', AuthController.loginWithGoogle);

// Google OAuth consent screen ka login URL generate karne ke liye.
router.get('/auth/google/url', AuthController.getGoogleAuthUrl);

// Google consent ke baad authorization code ko exchange karne ke liye.
router.get('/auth/google/callback', AuthController.handleGoogleCallback);


// Account me naya login method (Google/Phone) link karne ke liye.
router.post('/auth/link-account', requireAuth, AuthController.linkAccount);

// Active user session logout karne ke liye.
router.post('/auth/logout', AuthController.logout);

// Active session ka gate status (needs-mfa, needs-policy, ready) fetch karne ke liye.
router.get('/auth/session', requireAuth, AuthController.getSession);

export default router;
