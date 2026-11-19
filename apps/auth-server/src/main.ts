import { app } from './app';
import { startServer } from './server';

// Start server when executed directly
if (require.main === module) {
  startServer().catch((err) => {
    console.error('[SARAL Auth Server] Fatal startup error:', err);
    process.exit(1);
  });
}

export default app;
