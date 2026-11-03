import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import swaggerUi from 'swagger-ui-express';
import authRoutes from './routes/auth';
import mfaRoutes from './routes/mfa';
import profileRoutes from './routes/profile';
import walletRoutes from './routes/wallet';
import { errorHandler } from './middleware/errorHandler';

import { swaggerDocument } from './config/swagger';

export const app = express();

// Security and utility middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'SARAL Wallet API', timestamp: new Date().toISOString() });
});

// Swagger UI docs
if (swaggerDocument) {
  app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
}

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/mfa', mfaRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/wallet', walletRoutes);

// Global Error Handler
app.use(errorHandler);
