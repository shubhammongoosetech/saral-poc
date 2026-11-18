import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import authRoutes from './routes/auth';
import walletRoutes from './routes/wallet';

const app = express();
const port = parseInt(process.env.PORT || '3001', 10);

app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

app.use('/', authRoutes);
app.use('/wallet', walletRoutes);

app.listen(port, () => {
  console.log(`[SARAL Auth Server] Active and listening on port ${port}`);
});

export default app;
