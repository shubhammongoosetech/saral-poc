import { app } from './app';
import { env } from './config/env';
import { testConnection } from './config/db';

async function startServer() {
  await testConnection();

  const server = app.listen(env.PORT, () => {
    console.log(`=======================================================`);
    console.log(`SARAL Wallet Backend running at http://localhost:${env.PORT}`);
    console.log(`Environment: ${env.NODE_ENV}`);
    console.log(`Swagger Docs: http://localhost:${env.PORT}/docs`);
    console.log(`MST Testnet RPC: ${env.RPC_URL}`);
    console.log(`=======================================================`);
  });

  const shutdown = () => {
    console.log('\nShutting down SARAL Wallet server gracefully...');
    server.close(() => {
      console.log('Server terminated.');
      process.exit(0);
    });
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

startServer().catch((err) => {
  console.error('Fatal error during server startup:', err);
  process.exit(1);
});
