/**
 * SARAL System Bootstrap & Initialization Orchestrator
 *
 * Coordinates startup sequence:
 * 1. Environment validation
 * 2. Runtime directory preparation with strict 0o700 permissions
 * 3. Stale IPC socket cleanup
 * 4. Database connectivity verification
 * 5. Startup timing instrumentation and metrics capture
 */

import fs from 'fs';
import path from 'path';
import { Server } from 'http';
import { env } from './config/env';
import { testConnection, prisma } from './config/db';
import { getProtectedSocketDirectory } from './participant/participantDaemonProcess';

export interface StartupMetrics {
  envValidationMs: number;
  runtimeDirsMs: number;
  databaseCheckMs: number;
  totalBootstrapMs: number;
  startedAt: string;
}

let bootstrapMetrics: StartupMetrics | null = null;
let isBootstrapped = false;

/**
 * Ensures a directory exists with strict owner-only permissions (0o700).
 */
export function ensureSecureDirectory(dirPath: string): void {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
  }
  try {
    fs.chmodSync(dirPath, 0o700);
  } catch {
    // Ignore chmod errors on platforms that do not support POSIX permissions
  }
}

/**
 * Cleans up orphaned domain sockets left behind by previous crashes.
 */
export function cleanupStaleSockets(socketDir: string): number {
  let cleaned = 0;
  if (!fs.existsSync(socketDir)) return cleaned;

  try {
    const files = fs.readdirSync(socketDir);
    for (const file of files) {
      if (file.endsWith('.sock')) {
        const fullPath = path.join(socketDir, file);
        try {
          fs.unlinkSync(fullPath);
          cleaned++;
        } catch {
          // Socket might be actively locked by another running daemon
        }
      }
    }
  } catch (err) {
    console.warn('[Bootstrap] Warning during stale socket cleanup:', err);
  }
  return cleaned;
}

/**
 * Initializes runtime directories required by the coordinator and participants.
 */
export function initializeRuntimeDirectories(): void {
  const registryDir = process.env.SARAL_REGISTRY_DIR || path.resolve(process.cwd(), '.saral_registry');
  const vaultDir = process.env.SARAL_VAULT_DIR || path.resolve(process.cwd(), '.saral_node_vault');
  const socketDir = getProtectedSocketDirectory();

  ensureSecureDirectory(registryDir);
  ensureSecureDirectory(vaultDir);
  ensureSecureDirectory(socketDir);

  cleanupStaleSockets(socketDir);
}

/**
 * Validates essential security and infrastructure environment variables.
 */
export function validateEnvironment(): void {
  if (!env.PORT || env.PORT <= 0 || env.PORT > 65535) {
    throw new Error(`[Bootstrap] Invalid PORT: ${env.PORT}`);
  }

  if (env.NODE_ENV === 'production') {
    if (!process.env.SARAL_REGISTRY_ADMIN_SECRET || process.env.SARAL_REGISTRY_ADMIN_SECRET.length < 32) {
      throw new Error('[Bootstrap] In production, SARAL_REGISTRY_ADMIN_SECRET must be at least 32 characters long');
    }
    if (!process.env.SARAL_IPC_AUTH_KEY || process.env.SARAL_IPC_AUTH_KEY.length < 32) {
      throw new Error('[Bootstrap] In production, SARAL_IPC_AUTH_KEY must be configured with a 32-byte secret');
    }
  }
}

/**
 * Primary startup orchestration function. Idempotent: safe to invoke multiple times.
 */
export async function bootstrapSystem(options: { checkDatabase?: boolean } = {}): Promise<StartupMetrics> {
  if (isBootstrapped && bootstrapMetrics) {
    return bootstrapMetrics;
  }

  const startTime = performance.now();

  // 1. Validate environment
  const tEnvStart = performance.now();
  validateEnvironment();
  const envValidationMs = performance.now() - tEnvStart;

  // 2. Prepare runtime directories
  const tDirStart = performance.now();
  initializeRuntimeDirectories();
  const runtimeDirsMs = performance.now() - tDirStart;

  // 3. Test Database Connection
  const tDbStart = performance.now();
  const shouldCheckDb = options.checkDatabase ?? (env.NODE_ENV !== 'test');
  if (shouldCheckDb) {
    const isDbConnected = await testConnection();
    if (!isDbConnected && env.NODE_ENV === 'production') {
      throw new Error('[Bootstrap] Fatal: Database connection verification failed in production environment');
    }
  }
  const databaseCheckMs = performance.now() - tDbStart;

  const totalBootstrapMs = performance.now() - startTime;

  bootstrapMetrics = {
    envValidationMs,
    runtimeDirsMs,
    databaseCheckMs,
    totalBootstrapMs,
    startedAt: new Date().toISOString(),
  };

  isBootstrapped = true;
  return bootstrapMetrics;
}

/**
 * Returns recorded bootstrap metrics or null if not yet bootstrapped.
 */
export function getStartupMetrics(): StartupMetrics | null {
  return bootstrapMetrics;
}

/**
 * Resets bootstrap state (used primarily in test suites).
 */
export function resetBootstrapState(): void {
  isBootstrapped = false;
  bootstrapMetrics = null;
}

/**
 * Handles graceful server shutdown by closing network listeners and freeing resources.
 */
export function registerGracefulShutdown(server: Server): void {
  let isShuttingDown = false;

  const shutdown = async (signal: string) => {
    if (isShuttingDown) return;
    isShuttingDown = true;

    console.log(`\n[Bootstrap] Received ${signal}. Initiating graceful shutdown...`);

    const shutdownTimeout = setTimeout(() => {
      console.error('[Bootstrap] Graceful shutdown timed out after 5000ms. Forcing exit.');
      process.exit(1);
    }, 5000);

    try {
      // 1. Close HTTP server
      await new Promise<void>((resolve, reject) => {
        server.close((err) => {
          if (err) return reject(err);
          resolve();
        });
      });
      console.log('[Bootstrap] HTTP server closed.');

      // 2. Disconnect Prisma client
      await prisma.$disconnect();
      console.log('[Bootstrap] Database connections closed.');

      // 3. Clean runtime domain sockets
      const socketDir = getProtectedSocketDirectory();
      cleanupStaleSockets(socketDir);
      console.log('[Bootstrap] Runtime sockets cleaned.');

      clearTimeout(shutdownTimeout);
      console.log('[Bootstrap] Clean shutdown complete.');
      process.exit(0);
    } catch (err) {
      console.error('[Bootstrap] Error during shutdown:', err);
      clearTimeout(shutdownTimeout);
      process.exit(1);
    }
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

