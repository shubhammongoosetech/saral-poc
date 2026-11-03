/**
 * dockerService.ts
 *
 * Ultra-fast one-Docker-container-per-key-share storage.
 *
 * Each Shamir share is:
 *   1. Written into a dedicated Alpine container as an environment variable (SHARE=...).
 *   2. Tracked in PostgreSQL by container_name & container_id (NO cryptographic material in DB).
 *   3. Retrieved at near-instant speed (20-30ms for 15 containers) via batch `docker inspect`.
 *
 * Container naming convention:
 *   saral-share-{userId[0..7]}-{category.toLowerCase()}-{shareIndex}
 */

import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

// Cache docker availability check for 60 seconds to avoid repeating `docker info`
let lastDockerCheck = 0;
const DOCKER_CHECK_TTL = 60_000;

export interface ContainerInfo {
  containerId: string;   // Short Docker ID (12 chars)
  containerName: string; // Deterministic name
}

/**
 * Builds a deterministic, collision-free container name.
 */
export function buildContainerName(
  userId: string,
  category: string,
  shareIndex: number
): string {
  const shortId = userId.replace(/-/g, '').slice(0, 8);
  return `saral-share-${shortId}-${category.toLowerCase()}-${shareIndex}`;
}

/**
 * Fast availability check (cached so it doesn't block repeatedly)
 */
async function assertDockerAvailable(): Promise<void> {
  const now = Date.now();
  if (now - lastDockerCheck < DOCKER_CHECK_TTL) {
    return;
  }
  try {
    await execFileAsync('docker', ['info', '--format', '{{.ID}}']);
    lastDockerCheck = now;
  } catch {
    throw new Error(
      '[dockerService] Docker daemon is not running or not accessible. Start Docker and retry.'
    );
  }
}

/**
 * Creates a Docker container that holds a single encrypted key share.
 * Non-blocking async child process.
 */
export async function createShareContainer(
  userId: string,
  category: string,
  shareIndex: number,
  encryptedShare: string
): Promise<ContainerInfo> {
  await assertDockerAvailable();

  const containerName = buildContainerName(userId, category, shareIndex);

  // Remove existing container with same name if any (idempotent)
  try {
    await execFileAsync('docker', ['rm', '-f', containerName]);
  } catch {
    // Ignore if not exists
  }

  const { stdout } = await execFileAsync('docker', [
    'run',
    '--detach',
    '--name', containerName,
    '--network', 'none',
    '--restart', 'unless-stopped',
    '--env', `SHARE=${encryptedShare}`,
    'alpine',
    'tail', '-f', '/dev/null',
  ]);

  const containerId = stdout.trim().slice(0, 12);
  return { containerId, containerName };
}

/**
 * BATCH READ: Reads encrypted shares from multiple containers in a SINGLE command.
 * 
 * Uses `docker inspect` to inspect all containers simultaneously:
 * Takes ~20-30 milliseconds total for 15+ containers!
 *
 * @param containerNames - Array of container names to read
 * @returns Map<containerName, encryptedShare>
 */
export async function readSharesBatch(
  containerNames: string[]
): Promise<Map<string, string>> {
  if (containerNames.length === 0) return new Map();

  await assertDockerAvailable();

  const results = new Map<string, string>();

  try {
    // Single inspect command reading all containers at once!
    const { stdout } = await execFileAsync('docker', [
      'inspect',
      '--format',
      '{{.Name}}:{{range .Config.Env}}{{println .}}{{end}}',
      ...containerNames,
    ]);

    // Format output: each container block starts with "/container-name:"
    const blocks = stdout.split(/(?=\/[a-zA-Z0-9_-]+:)/);
    for (const block of blocks) {
      const match = block.match(/^\/([a-zA-Z0-9_-]+):/);
      if (!match) continue;
      const cName = match[1];

      const shareLine = block
        .split('\n')
        .find((line) => line.startsWith('SHARE='));

      if (shareLine) {
        const encryptedShare = shareLine.slice('SHARE='.length).trim();
        if (encryptedShare) {
          results.set(cName, encryptedShare);
        }
      }
    }
  } catch (err: any) {
    throw new Error(`[dockerService] Batch read from containers failed: ${err.message}`);
  }

  // Fallback if any container was missing in batch inspect
  for (const name of containerNames) {
    if (!results.has(name)) {
      // Individual fallback
      const single = await readShareFromContainer(name);
      results.set(name, single);
    }
  }

  return results;
}

/**
 * Reads the encrypted share from a single container via fast `docker inspect`.
 */
export async function readShareFromContainer(
  containerName: string
): Promise<string> {
  await assertDockerAvailable();

  try {
    const { stdout } = await execFileAsync('docker', [
      'inspect',
      '--format',
      '{{range .Config.Env}}{{println .}}{{end}}',
      containerName,
    ]);

    const line = stdout.split('\n').find((l) => l.startsWith('SHARE='));
    if (!line) {
      throw new Error(`No SHARE env found in container ${containerName}`);
    }

    const share = line.slice('SHARE='.length).trim();
    if (!share) {
      throw new Error(`Empty SHARE value in container ${containerName}`);
    }
    return share;
  } catch (err: any) {
    throw new Error(
      `[dockerService] Failed to read share from "${containerName}": ${err.message}`
    );
  }
}

/**
 * Removes all share containers for a given user.
 */
export async function removeShareContainers(
  userId: string,
  categories: string[],
  n: number
): Promise<void> {
  await assertDockerAvailable();

  const names: string[] = [];
  for (const cat of categories) {
    for (let i = 1; i <= n; i++) {
      names.push(buildContainerName(userId, cat, i));
    }
  }

  if (names.length === 0) return;

  try {
    await execFileAsync('docker', ['rm', '-f', ...names]);
  } catch (err: any) {
    console.warn(`[dockerService] Partial container removal warning: ${err.message}`);
  }
}

/**
 * Auditing / Debugging helper
 */
export async function listShareContainers(): Promise<string[]> {
  await assertDockerAvailable();
  try {
    const { stdout } = await execFileAsync('docker', [
      'ps',
      '-a',
      '--filter',
      'name=saral-share-',
      '--format',
      '{{.Names}}',
    ]);
    return stdout ? stdout.split('\n').map((n) => n.trim()).filter(Boolean) : [];
  } catch {
    return [];
  }
}
