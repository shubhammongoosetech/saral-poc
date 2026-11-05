import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { AppError } from '../utils/errors';
import { logger } from '../utils/logger';

/**
 * Global error handler.
 *
 * Security contract:
 *  - NEVER includes stack traces in client responses (even in development).
 *  - NEVER includes internal data, topology, or share material in responses.
 *  - Only returns { error: string, requestId?: string }.
 *  - In development, full error is logged server-side only.
 */
export function errorHandler(
  err: unknown,
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  const requestId = (req as Request & { requestId?: string }).requestId;
  const errMsg = err instanceof Error ? err.message : String(err);

  // Server-side only logging — never expose stack to client
  if (process.env.NODE_ENV === 'development' && err instanceof Error) {
    logger.error('ErrorHandler', `${req.method} ${req.path} failed: ${errMsg}`);
    console.error('[ErrorHandler]', err.stack ?? err);
  } else {
    logger.error('ErrorHandler', `${req.method} ${req.path} failed: ${errMsg}`);
  }

  if (err instanceof ZodError) {
    const issues = err.issues ?? [];
    res.status(400).json({
      error: 'Validation error',
      details: issues.map((e) => ({
        field: Array.isArray(e.path) ? e.path.join('.') : String(e.path ?? ''),
        message: e.message,
      })),
      ...(requestId ? { requestId } : {}),
    });
    return;
  }

  if (err instanceof AppError) {
    res.status(err.statusCode).json({
      error: err.message,
      ...(requestId ? { requestId } : {}),
    });
    return;
  }

  // Generic error — sanitize to prevent leaking internals
  const statusCode =
    typeof (err as Record<string, unknown>).statusCode === 'number'
      ? (err as Record<string, unknown>).statusCode as number
      : errMsg.includes('Access Denied')
      ? 403
      : 500;

  res.status(statusCode).json({
    error: 'An unexpected error occurred.',
    ...(requestId ? { requestId } : {}),
  });
}
