import { app } from './app';
import { env } from './config/env';
import { bootstrapSystem, registerGracefulShutdown } from './bootstrap';

async function startServer() {
  const t0 = performance.now();
  const metrics = await bootstrapSystem();

  const server = app.listen(env.PORT, () => {
    const totalListenMs = (performance.now() - t0).toFixed(2);
    console.log(`[SARAL] Server listening on port ${env.PORT} (${env.NODE_ENV}) [ready in ${totalListenMs}ms]`);
    console.log(`[SARAL] Bootstrap metrics: dirs=${metrics.runtimeDirsMs.toFixed(1)}ms, db=${metrics.databaseCheckMs.toFixed(1)}ms, env=${metrics.envValidationMs.toFixed(1)}ms`);
    console.log(`[SARAL] API documentation available at http://localhost:${env.PORT}/docs`);
    console.log(`[SARAL] RPC upstream: ${env.RPC_URL} (Chain ID: ${env.CHAIN_ID})`);
  });

  registerGracefulShutdown(server);
}

startServer().catch((err) => {
  console.error('[SARAL] Fatal error during startup:', err);
  process.exit(1);
});
