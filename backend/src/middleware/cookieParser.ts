import { Request, Response, NextFunction } from 'express';

declare global {
  namespace Express {
    interface Request {
      cookies?: Record<string, string>;
    }
  }
}

/**
 * Lightweight, zero-dependency cookie parser middleware factory.
 * Parses the incoming `Cookie` HTTP header into `req.cookies`.
 */
export function cookieParser() {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const cookieHeader = req.headers.cookie;
    const cookies: Record<string, string> = {};

    if (cookieHeader) {
      const pairs = cookieHeader.split(';');
      for (const pair of pairs) {
        const eqIdx = pair.indexOf('=');
        if (eqIdx > 0) {
          const key = pair.slice(0, eqIdx).trim();
          const rawVal = pair.slice(eqIdx + 1).trim();
          try {
            cookies[key] = decodeURIComponent(rawVal);
          } catch {
            cookies[key] = rawVal;
          }
        }
      }
    }

    req.cookies = cookies;
    next();
  };
}
