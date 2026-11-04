import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import authRoutes from './routes/auth';
import mfaRoutes from './routes/mfa';
import profileRoutes from './routes/profile';
import walletRoutes from './routes/wallet';
import { errorHandler } from './middleware/errorHandler';
import { getStartupMetrics } from './bootstrap';

export const app = express();

// Security and utility middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// Health Check
app.get('/api/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'SARAL Wallet API',
    timestamp: new Date().toISOString(),
    metrics: getStartupMetrics(),
  });
});

// Lazy-loaded Swagger documentation (defers schema parsing until route access)
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

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/mfa', mfaRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/wallet', walletRoutes);

// Global Error Handler
app.use(errorHandler);
