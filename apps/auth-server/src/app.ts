import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import authRoutes from './routes/auth';
import walletRoutes from './routes/wallet';
import { errorHandler } from './middleware/errorHandler';

export function createApp(): express.Application {
  const app = express();

  app.use(helmet());
  app.use(cors({ origin: true, credentials: true }));
  app.use(express.json());

  // Request logger for visibility
  app.use((req, _res, next) => {
    next();
  });

  // Mount routes
  app.use('/', authRoutes);
  app.use('/api', authRoutes);
  app.use('/wallet', walletRoutes);
  app.use('/api/wallet', walletRoutes);

  // Error handling middleware
  app.use(errorHandler);

  return app;
}

export const app = createApp();
export default app;

