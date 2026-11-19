import { app } from './app';
import { env } from './config/env';
import { connectPrisma, disconnectPrisma } from './database/prisma';
import { DataStore } from './storage/store';

export async function startServer(): Promise<any> {
  const port = env.PORT;

  // 1. Initialize Prisma & sync store
  try {
    const connected = await connectPrisma();
    if (connected) {
      await DataStore.getInstance().syncFromPostgres();
    }
  } catch (err: any) {
    console.warn('[SARAL Auth Server] Database initialization warning:', err.message);
  }

  // 2. Start Express server
  const server = app.listen(port, () => {
    console.log(`[SARAL Auth Server] Active and listening on port ${port} (Prisma ORM enabled)`);
  });

  // 3. Graceful shutdown handler
  const shutdown = async (signal: string) => {
    console.log(`[SARAL Auth Server] Received ${signal}, closing server gracefully...`);
    server.close(async () => {
      await disconnectPrisma();
      console.log('[SARAL Auth Server] Server closed, database disconnected.');
      process.exit(0);
    });
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  return server;
}

if (require.main === module) {
  startServer().catch((err) => {
    console.error('[SARAL Auth Server] Fatal startup error:', err);
    process.exit(1);
  });
}

