/**
 * clearDb.ts
 *
 * Script to completely reset & clear the SARAL database and stored key shares.
 *
 * Actions:
 *  1. Truncates all PostgreSQL database tables (users, mfa, policy, key_shares, logs, txs, otps).
 *  2. Deletes all local node vault share files (.saral_node_vault/*.vault).
 *  3. Attempts to remove any Docker share containers if Docker is available.
 */

import fs from 'fs';
import path from 'path';
import { PrismaClient } from '@prisma/client';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);
const prisma = new PrismaClient();

async function clearPostgres() {
  console.log('🔄 Checking PostgreSQL connection...');
  try {
    await prisma.$connect();
    console.log('Connected to PostgreSQL.');

    // Truncate tables with CASCADE
    console.log('🧹 Truncating all database tables...');
    await prisma.$executeRawUnsafe(`
      DO $$ 
      DECLARE
        r RECORD;
      BEGIN
        FOR r IN (
          SELECT tablename FROM pg_tables 
          WHERE schemaname = 'public' 
            AND tablename NOT LIKE '_prisma%'
        ) LOOP
          EXECUTE 'TRUNCATE TABLE ' || quote_ident(r.tablename) || ' CASCADE;';
        END LOOP;
      END $$;
    `);

    console.log('✅ PostgreSQL database cleared successfully (all tables truncated with CASCADE).');
  } catch (err: any) {
    console.warn(`⚠️ PostgreSQL is currently offline or unreachable: ${err.message}`);
    console.log('ℹ️ If you are using Docker Compose, run: docker compose down -v && docker compose up -d');
  } finally {
    await prisma.$disconnect().catch(() => {});
  }
}

async function clearNodeVault() {
  const vaultDir = path.resolve(__dirname, '../../.saral_node_vault');
  console.log(`🧹 Clearing local node vault files in: ${vaultDir}`);

  if (fs.existsSync(vaultDir)) {
    const files = await fs.promises.readdir(vaultDir);
    let count = 0;
    for (const file of files) {
      if (file.endsWith('.vault') || file.endsWith('.json')) {
        await fs.promises.unlink(path.join(vaultDir, file));
        count++;
      }
    }
    console.log(`✅ Cleared ${count} node vault share file(s).`);
  } else {
    console.log('ℹ️ Node vault directory is already clean.');
  }
}

async function clearDockerContainers() {
  console.log('🧹 Checking for Docker share containers...');
  try {
    const { stdout } = await execFileAsync('docker', [
      'ps',
      '-a',
      '--filter', 'name=saral-node-',
      '--filter', 'name=saral-share-',
      '--format', '{{.Names}}',
    ]);

    const names = stdout.split('\n').map((s) => s.trim()).filter(Boolean);
    if (names.length > 0) {
      console.log(`Removing ${names.length} Docker container(s): ${names.join(', ')}`);
      await execFileAsync('docker', ['rm', '-f', ...names]);
      console.log('✅ Docker share containers removed.');
    } else {
      console.log('ℹ️ No active SARAL share containers found in Docker.');
    }
  } catch {
    console.log('ℹ️ Docker daemon is not active; skipped Docker container cleanup.');
  }
}

async function main() {
  console.log('═══════════════════════════════════════════════════════');
  console.log('          SARAL — DATABASE & SHARE CLEAR UTILITY       ');
  console.log('═══════════════════════════════════════════════════════');

  await clearPostgres();
  await clearNodeVault();
  await clearDockerContainers();

  console.log('═══════════════════════════════════════════════════════');
  console.log('🎉 Reset complete! All user data and shares have been cleared.');
  console.log('═══════════════════════════════════════════════════════');
}

main().catch((e) => {
  console.error('Fatal error during clear:', e);
  process.exit(1);
});

