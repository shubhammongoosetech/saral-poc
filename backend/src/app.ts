import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { cookieParser } from './middleware/cookieParser';
import rateLimit from 'express-rate-limit';
import { v4 as uuidv4 } from 'uuid';
import authRoutes from './routes/auth';
import mfaRoutes from './routes/mfa';
import profileRoutes from './routes/profile';
import walletRoutes from './routes/wallet';
import topologyRoutes from './routes/topology';
import activityRoutes from './routes/activity';
import { errorHandler } from './middleware/errorHandler';
import { getStartupMetrics } from './bootstrap';
import { env } from './config/env';

export const app = express();

// --- Security middleware ---

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'accounts.google.com', 'apis.google.com'],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true },
    crossOriginEmbedderPolicy: false,
  })
);

app.use(
  cors({
    origin: env.FRONTEND_URL,
    credentials: true,
  })
);

// Cookie parser (required for httpOnly cookie JWT strategy — D-07)
app.use(cookieParser());

// Body size limits
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));

// Request ID middleware — attaches a UUID v4 to every request for tracing
app.use((req: Request, res: Response, next: NextFunction): void => {
  const requestId = uuidv4();
  res.setHeader('X-Request-ID', requestId);
  (req as Request & { requestId: string }).requestId = requestId;
  next();
});

// Global rate limiter: generous in dev/test, sensible in production
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: env.NODE_ENV === 'production' ? 1000 : 10000,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});
app.use(globalLimiter);

// --- Health check ---
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'SARAL Wallet API',
    timestamp: new Date().toISOString(),
    metrics: getStartupMetrics(),
  });
});

// --- Lazy-loaded Swagger documentation ---
let swaggerRouter: express.Router | null = null;
app.use('/docs', (req: Request, res: Response, next: NextFunction) => {
  if (swaggerRouter) {
    return swaggerRouter(req, res, next);
  }

  Promise.all([
    import('swagger-ui-express'),
    import('./config/swagger'),
  ])
    .then(([swaggerUiModule, { swaggerDocument }]) => {
      const swaggerUi = swaggerUiModule.default || swaggerUiModule;
      swaggerRouter = express.Router();
      swaggerRouter.use(swaggerUi.serve);
      swaggerRouter.use(swaggerUi.setup(swaggerDocument));
      return swaggerRouter(req, res, next);
    })
    .catch((err) => next(err));
});

// --- API Routes ---
app.use('/api/auth', authRoutes);
app.use('/api/mfa', mfaRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/wallet', walletRoutes);
app.use('/api/topology', topologyRoutes);
app.use('/api/activity', activityRoutes);

// --- Global Error Handler ---
app.use(errorHandler);
