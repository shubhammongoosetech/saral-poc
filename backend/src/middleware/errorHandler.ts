import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';

export function errorHandler(
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  // Never log private keys or raw data in error outputs
  console.error('[Error]', req.method, req.path, err.message || err);

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

  const statusCode = err.statusCode || (err.message?.includes('Access Denied') ? 403 : 400);

  res.status(statusCode).json({
    error: err.message || 'An unexpected error occurred',
  });
}
