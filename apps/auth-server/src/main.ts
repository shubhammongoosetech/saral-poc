import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import authRoutes from './routes/auth';
import walletRoutes from './routes/wallet';
import { initPostgres } from './storage/db';
import { DataStore } from './storage/store';

const app = express();
const port = parseInt(process.env.PORT || '3001', 10);

app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

app.use('/', authRoutes);
app.use('/api', authRoutes);
app.use('/wallet', walletRoutes);
app.use('/api/wallet', walletRoutes);

// Initialize PostgreSQL and sync state
initPostgres()
  .then((connected) => {
    if (connected) {
      return DataStore.getInstance().syncFromPostgres();
    }
  })
  .catch((err) => {
    console.warn('[SARAL Auth Server] Database initialization warning:', err.message);
  });

app.listen(port, () => {
  console.log(`[SARAL Auth Server] Active and listening on port ${port}`);
});

export default app;
