import { Request, Response, NextFunction } from 'express';

export function errorHandler(err: any, req: Request, res: Response, next: NextFunction): void {
  if (res.headersSent) {
    next(err);
    return;
  }
  const intendedStatus = err?.status || err?.statusCode;
  const status = Number.isInteger(intendedStatus) && intendedStatus >= 400 && intendedStatus < 600
    ? intendedStatus
    : 500;
  if (status >= 500) console.error(`[Error] ${req.method} ${req.path} returned ${status}`);

  let message = 'Request failed';
  if (status === 400) message = 'Invalid request';
  if (status === 413) message = 'Request body too large';
  if (status >= 500) message = 'Internal server error';
  res.status(status).json({
    success: false,
    error: message,
  });
}

