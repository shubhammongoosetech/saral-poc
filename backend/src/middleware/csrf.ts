import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { env } from '../config/env';

/**
 * CSRF double-submit cookie pattern (D-07).
 *
 * On safe methods (GET, HEAD, OPTIONS):
 *   - Issues a fresh csrf_token cookie + sets X-CSRF-Token response header
 *     so the SPA can read it and store it for subsequent state-changing calls.
 *
 * On state-changing methods (POST, PUT, DELETE, PATCH):
 *   - Verifies that the X-CSRF-Token request header matches the csrf_token cookie.
 *   - SameSite=Strict on the auth cookies already mitigates most CSRF; this is
 *     defence-in-depth per D-07.
 *
 * Skipped for paths that explicitly opt out (e.g., /api/auth/csrf-token).
 */

const CSRF_SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const CSRF_SKIP_PATHS = new Set(['/api/auth/csrf-token']);

function generateCsrfToken(): string {
  return crypto.createHmac('sha256', env.CSRF_SECRET)
    .update(crypto.randomBytes(32))
    .digest('hex');
}

export function csrfMiddleware(req: Request, res: Response, next: NextFunction): void {
  const isSafeMethod = CSRF_SAFE_METHODS.has(req.method.toUpperCase());
  const isSkippedPath = CSRF_SKIP_PATHS.has(req.path);

  if (isSafeMethod || isSkippedPath) {
    // Issue / refresh the CSRF token so the client always has a fresh one
    const token = generateCsrfToken();
    res.cookie('csrf_token', token, {
      httpOnly: false, // Must be readable by JavaScript (double-submit pattern)
      secure: env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
    });
    res.setHeader('X-CSRF-Token', token);
    next();
    return;
  }

  // For state-changing requests, enforce CSRF check
  const headerToken = req.headers['x-csrf-token'];
  const cookieToken = req.cookies?.csrf_token as string | undefined;

  if (
    typeof headerToken !== 'string' ||
    typeof cookieToken !== 'string' ||
    !crypto.timingSafeEqual(Buffer.from(headerToken), Buffer.from(cookieToken))
  ) {
    res.status(403).json({ error: 'CSRF token mismatch.' });
    return;
  }

  next();
}
