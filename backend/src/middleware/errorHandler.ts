import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { AppError } from '../utils/errors';
import { logger } from '../utils/logger';

export function errorHandler(
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  // Never log private key material or raw secrets in error logs
  const errMsg = err?.message || String(err);
  logger.error('ErrorHandler', `${req.method} ${req.path} failed: ${errMsg}`);

  if (err instanceof ZodError) {
    const issues = (err as any).issues || (err as any).errors || [];
    res.status(400).json({
      error: 'Validation error',
      details: issues.map((e: any) => ({
        field: Array.isArray(e.path) ? e.path.join('.') : String(e.path || ''),
        message: e.message,
      })),
    });
    return;
  }

  if (err instanceof AppError) {
    res.status(err.statusCode).json({
      error: err.message,
    });
    return;
  }

  const statusCode = err.statusCode || (errMsg.includes('Access Denied') ? 403 : 400);
  res.status(statusCode).json({
    error: errMsg || 'An unexpected error occurred',
  });
}
