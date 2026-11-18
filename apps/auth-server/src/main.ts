import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import authRoutes from './routes/auth';

const app = express();
const port = parseInt(process.env.PORT || '3001', 10);

app.use(helmet());
app.use(cors());
app.use(express.json());

app.use('/', authRoutes);

app.listen(port, () => {
  console.log(`[SARAL Auth Server] Active and listening on port ${port}`);
});

export default app;

