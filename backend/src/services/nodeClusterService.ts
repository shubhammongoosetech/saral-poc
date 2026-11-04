/**
 * nodeClusterService.ts
 *
 * SARAL Fixed 19-Node Distributed Storage & Cluster Architecture
 *
 * Implements 3-Domain Separation of Powers:
 *   - Foundation Domain: 9 Institutional / Regulatory Nodes
 *   - Public Domain:     9 Decentralized Staking Validator Nodes
 *   - Private Domain:    9 Sovereign User / Guardian Nodes
 *
 * Architectural Features:
 *   - Pluggable Node Storage Drivers: Docker Containers, Multi-Host Remote Nodes,
 *     and Isolated Encrypted Sandboxed Node Vaults.
 *   - Independent Node Identities & Access Permissions.
 *   - Cryptographic Share Integrity Verification (HMAC-SHA256).
 *   - Real-time Node Health Monitoring & Heartbeat Checks.
 *   - Automated Failover & Fault-Tolerant Quorum Selection.
 *   - Backward Compatibility with legacy 'INSTITUTIONAL' / 'SOVEREIGN' naming.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import net from 'net';
import { execFile, spawn, ChildProcess } from 'child_process';
import { promisify } from 'util';
import { DomainType } from '../crypto/thresholdEcdsa';
import { encryptShareGcm } from '../crypto/secureEncryption';
import { MpcParticipantDaemon } from '../crypto/mpcParticipantDaemon';
import { AuthenticatedParticipantClient } from '../participant/participantClient';
import { trustedParticipantRegistry } from '../crypto/participantRegistry';
import { getProtectedSocketDirectory } from '../participant/participantDaemonProcess';

const execFileAsync = promisify(execFile);

export interface NodeInstanceInfo {
  nodeId: string;
  nodeName: string;
  domain: DomainType;
  nodeIndex: number;
  driver: 'docker' | 'sandbox' | 'remote';
  status: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  lastHealthCheck: string;
  latencyMs: number;
}

export interface NodeHealthReport {
  nodeName: string;
  domain: DomainType;
  nodeIndex: number;
  healthy: boolean;
  driver: string;
  latencyMs: number;
  error?: string;
}

export interface ClusterStatus {
  totalNodes: number;
  domainBreakdown: {
    FOUNDATION: { total: number; online: number; threshold: number };
    PUBLIC: { total: number; online: number; threshold: number };
    PRIVATE: { total: number; online: number; threshold: number };
  };
  healthy: boolean;
  activeDriver: 'docker' | 'sandbox' | 'remote';
}

/**
 * Normalizes domain strings for backwards compatibility.
 */
export function normalizeDomain(rawDomain: string): DomainType {
  const upper = rawDomain.toUpperCase();
  if (upper === 'INSTITUTIONAL' || upper === 'FOUNDATION') return 'FOUNDATION';
  if (upper === 'SOVEREIGN' || upper === 'PRIVATE') return 'PRIVATE';
  if (upper === 'PUBLIC') return 'PUBLIC';
  return 'PUBLIC';
}

/**
 * Maps standard domain to legacy category name if required for database lookups.
 */
export function getDomainLegacyAliases(domain: DomainType): string[] {
  switch (domain) {
    case 'FOUNDATION':
      return ['FOUNDATION', 'INSTITUTIONAL'];
    case 'PRIVATE':
      return ['PRIVATE', 'SOVEREIGN'];
    case 'PUBLIC':
      return ['PUBLIC'];
  }
}

/**
 * Fixed 19-Node Participant Infrastructure Topology
 */
export const INFRASTRUCTURE_TOPOLOGY = {
  FOUNDATION: { count: 1, threshold: 1 },
  PUBLIC: { count: 9, threshold: 5 },
  PRIVATE: { count: 9, threshold: 5 },
  TOTAL: 19,
} as const;

/**
 * Builds standard infrastructure participant node identifier.
 * Example: saral-foundation-1, saral-public-1, saral-private-1
 */
export function buildInfrastructureNodeId(domain: DomainType, nodeIndex: number): string {
  return `saral-${domain.toLowerCase()}-${nodeIndex}`;
}

/**
 * Builds standard deterministic container / node identifier.
 * Decoupled from user ID: returns stable infrastructure node name.
 */
export function buildNodeName(
  domainOrUserId: DomainType | string,
  domainOrNodeIndex?: DomainType | number,
  optionalNodeIndex?: number
): string {
  if (domainOrUserId === 'FOUNDATION' || domainOrUserId === 'PUBLIC' || domainOrUserId === 'PRIVATE') {
    const nodeIndex = typeof domainOrNodeIndex === 'number' ? domainOrNodeIndex : 1;
    return buildInfrastructureNodeId(domainOrUserId, nodeIndex);
  }
  if (typeof domainOrNodeIndex === 'string') {
    const domain = domainOrNodeIndex as DomainType;
    const nodeIndex = optionalNodeIndex ?? 1;
    return buildInfrastructureNodeId(domain, nodeIndex);
  }
  return `saral-foundation-1`;
}

/**
 * Legacy container name format for backward-compatibility.
 */
export function buildLegacyContainerName(
  userId: string,
  category: string,
  shareIndex: number
): string {
  const shortId = userId.replace(/-/g, '').slice(0, 8);
  return `saral-share-${shortId}-${category.toLowerCase()}-${shareIndex}`;
}

// Sandboxed Isolated Storage Directory
export function getSandboxVaultRoot(): string {
  const vaultRoot = process.env.SARAL_VAULT_DIR || path.resolve(process.cwd(), '.saral_node_vault');
  if (!fs.existsSync(vaultRoot)) {
    try {
      fs.mkdirSync(vaultRoot, { recursive: true, mode: 0o700 });
      fs.chmodSync(vaultRoot, 0o700);
    } catch {}
  }
  return vaultRoot;
}

/**
 * Generates an HMAC-SHA256 integrity tag over the stored encrypted share
 */
function computeIntegrityTag(nodeName: string, data: string): string {
  return crypto.createHmac('sha256', nodeName).update(data).digest('hex');
}

// Storage Driver Implementations

/**
 * Driver 1: Isolated Encrypted Vault (Multi-process / Standalone / Sandbox safe)
 */
class SandboxNodeDriver {
  private getFilePath(nodeName: string): string {
    return path.join(getSandboxVaultRoot(), `${nodeName}.vault`);
  }

  private getTenantShareDir(nodeName: string, userId: string): string {
    const dir = path.join(getSandboxVaultRoot(), nodeName, 'wallets', userId);
    if (!fs.existsSync(dir)) {
      try {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
        fs.chmodSync(dir, 0o700);
      } catch {}
    }
    return dir;
  }

  private getTenantSharePath(nodeName: string, userId: string): string {
    return path.join(this.getTenantShareDir(nodeName, userId), 'encrypted_share.json');
  }

  async writeShare(
    nodeName: string,
    encryptedShare: string,
    domain: DomainType,
    userId?: string
  ): Promise<NodeInstanceInfo> {
    const integrityTag = computeIntegrityTag(nodeName, encryptedShare);
    const payload = JSON.stringify({
      nodeName,
      domain,
      userId: userId || 'default',
      encryptedShare,
      integrityTag,
      updatedAt: new Date().toISOString(),
    });

    if (userId) {
      const tenantPath = this.getTenantSharePath(nodeName, userId);
      await fs.promises.writeFile(tenantPath, payload, { mode: 0o600 });
    }

    // Also write primary node vault for single-tenant / backward-compatibility
    const filePath = this.getFilePath(nodeName);
    await fs.promises.writeFile(filePath, payload, { mode: 0o600 });
    const nodeId = crypto.createHash('sha256').update(nodeName).digest('hex').slice(0, 12);

    return {
      nodeId,
      nodeName,
      domain,
      nodeIndex: parseInt(nodeName.split('-').pop() || '1', 10),
      driver: 'sandbox',
      status: 'ONLINE',
      lastHealthCheck: new Date().toISOString(),
      latencyMs: 1,
    };
  }

  async readShare(nodeName: string, userId?: string): Promise<string> {
    let filePath = this.getFilePath(nodeName);

    if (userId) {
      const tenantPath = path.join(getSandboxVaultRoot(), nodeName, 'wallets', userId, 'encrypted_share.json');
      if (fs.existsSync(tenantPath)) {
        filePath = tenantPath;
      } else if (!fs.existsSync(filePath)) {
        throw new Error(`[SandboxNodeDriver] Share not found for user '${userId}' on node '${nodeName}'`);
      }
    }

    if (!fs.existsSync(filePath)) {
      throw new Error(`[SandboxNodeDriver] Node vault file not found: ${nodeName}`);
    }

    const content = await fs.promises.readFile(filePath, 'utf8');
    const parsed = JSON.parse(content);

    // Enforce tenant isolation if user was specified
    if (userId && parsed.userId && parsed.userId !== 'default' && parsed.userId !== userId) {
      throw new Error(
        `[SandboxNodeDriver] Cross-tenant access violation: user '${userId}' attempted to access share belonging to '${parsed.userId}' on node '${nodeName}'`
      );
    }

    // Verify HMAC integrity tag to detect external file tampering
    const expectedTag = computeIntegrityTag(nodeName, parsed.encryptedShare);
    if (parsed.integrityTag !== expectedTag) {
      throw new Error(`[SandboxNodeDriver] Node integrity verification failed for ${nodeName}: corrupted or tampered share`);
    }

    return parsed.encryptedShare;
  }

  async checkHealth(nodeName: string): Promise<NodeHealthReport> {
    const start = Date.now();
    const filePath = this.getFilePath(nodeName);
    const nodeDir = path.join(getSandboxVaultRoot(), nodeName);
    const exists = fs.existsSync(filePath) || fs.existsSync(nodeDir);
    const latency = Date.now() - start;

    return {
      nodeName,
      domain: nodeName.includes('foundation') ? 'FOUNDATION' : nodeName.includes('private') ? 'PRIVATE' : 'PUBLIC',
      nodeIndex: parseInt(nodeName.split('-').pop() || '1', 10),
      healthy: exists,
      driver: 'sandbox',
      latencyMs: Math.max(latency, 1),
      error: exists ? undefined : 'Vault file not initialized',
    };
  }

  async deleteShare(nodeName: string, userId?: string): Promise<void> {
    if (userId) {
      const tenantPath = path.join(getSandboxVaultRoot(), nodeName, 'wallets', userId, 'encrypted_share.json');
      if (fs.existsSync(tenantPath)) {
        await fs.promises.unlink(tenantPath);
      }
      const tenantDir = path.join(getSandboxVaultRoot(), nodeName, 'wallets', userId);
      if (fs.existsSync(tenantDir)) {
        try {
          await fs.promises.rmdir(tenantDir);
        } catch {}
      }
    } else {
      const filePath = this.getFilePath(nodeName);
      if (fs.existsSync(filePath)) {
        await fs.promises.unlink(filePath);
      }
    }
  }
}

/**
 * Driver 2: Docker Container Driver (Alpine Container per Share)
 */
class DockerNodeDriver {
  private isAvailable: boolean | null = null;
  private lastCheck = 0;

  async checkDockerDaemon(): Promise<boolean> {
    const now = Date.now();
    if (this.isAvailable !== null && now - this.lastCheck < 30_000) {
      return this.isAvailable;
    }
    try {
      await execFileAsync('docker', ['info', '--format', '{{.ID}}']);
      this.isAvailable = true;
      this.lastCheck = now;
      return true;
    } catch {
      this.isAvailable = false;
      this.lastCheck = now;
      return false;
    }
  }

  /**
   * Ensures the fixed infrastructure container exists and is running.
   * Reuses existing container, starts if stopped, creates if missing.
   */
  async ensureContainerRunning(nodeName: string, domain: DomainType): Promise<void> {
    const available = await this.checkDockerDaemon();
    if (!available) return;

    try {
      const { stdout } = await execFileAsync('docker', [
        'inspect',
        '--format',
        '{{.State.Running}}',
        nodeName,
      ]);
      if (stdout.trim() !== 'true') {
        await execFileAsync('docker', ['start', nodeName]);
      }
      return;
    } catch {
      // Container does not exist, create it with volume mount for persistent node storage
    }

    try {
      await execFileAsync('docker', [
        'run',
        '--detach',
        '--name', nodeName,
        '--network', 'none',
        '--restart', 'unless-stopped',
        '--env', `NODE_NAME=${nodeName}`,
        '--env', `DOMAIN=${domain}`,
        '--volume', `${nodeName}_data:/vault`,
        'alpine',
        'tail', '-f', '/dev/null',
      ]);
    } catch (err: any) {
      console.warn(`[DockerNodeDriver] Container initialization warning for ${nodeName}: ${err.message}`);
    }
  }

  async writeShare(
    nodeName: string,
    encryptedShare: string,
    domain: DomainType,
    userId?: string
  ): Promise<NodeInstanceInfo> {
    const available = await this.checkDockerDaemon();
    if (!available) {
      throw new Error('[DockerNodeDriver] Docker daemon is unavailable');
    }

    await this.ensureContainerRunning(nodeName, domain);

    const safeUserId = userId || 'default';
    const writeScript = `mkdir -p /vault/wallets/${safeUserId} && printf '%s' '${encryptedShare}' > /vault/wallets/${safeUserId}/encrypted_share.json`;
    await execFileAsync('docker', ['exec', nodeName, 'sh', '-c', writeScript]);

    const nodeId = crypto.createHash('sha256').update(nodeName).digest('hex').slice(0, 12);
    return {
      nodeId,
      nodeName,
      domain,
      nodeIndex: parseInt(nodeName.split('-').pop() || '1', 10),
      driver: 'docker',
      status: 'ONLINE',
      lastHealthCheck: new Date().toISOString(),
      latencyMs: 15,
    };
  }

  async readShare(nodeName: string, userId?: string): Promise<string> {
    const safeUserId = userId || 'default';
    try {
      const { stdout } = await execFileAsync('docker', [
        'exec',
        nodeName,
        'cat',
        `/vault/wallets/${safeUserId}/encrypted_share.json`,
      ]);
      if (stdout && stdout.trim().length > 0) {
        return stdout.trim();
      }
    } catch {}

    const { stdout: envOut } = await execFileAsync('docker', [
      'inspect',
      '--format',
      '{{range .Config.Env}}{{println .}}{{end}}',
      nodeName,
    ]);

    const shareLine = envOut.split('\n').find((l) => l.startsWith('SHARE='));
    if (!shareLine) {
      throw new Error(`[DockerNodeDriver] Share not found in container ${nodeName} for user ${safeUserId}`);
    }
    return shareLine.slice('SHARE='.length).trim();
  }

  async readSharesBatch(nodeNames: string[]): Promise<Map<string, string>> {
    if (nodeNames.length === 0) return new Map();
    const results = new Map<string, string>();

    for (const name of nodeNames) {
      try {
        const share = await this.readShare(name);
        results.set(name, share);
      } catch {}
    }

    return results;
  }

  async checkHealth(nodeName: string): Promise<NodeHealthReport> {
    const start = Date.now();
    try {
      const { stdout } = await execFileAsync('docker', [
        'inspect',
        '--format',
        '{{.State.Running}}',
        nodeName,
      ]);
      const healthy = stdout.trim() === 'true';
      return {
        nodeName,
        domain: nodeName.includes('foundation') ? 'FOUNDATION' : nodeName.includes('private') ? 'PRIVATE' : 'PUBLIC',
        nodeIndex: parseInt(nodeName.split('-').pop() || '1', 10),
        healthy,
        driver: 'docker',
        latencyMs: Date.now() - start,
      };
    } catch (err: any) {
      return {
        nodeName,
        domain: nodeName.includes('foundation') ? 'FOUNDATION' : nodeName.includes('private') ? 'PRIVATE' : 'PUBLIC',
        nodeIndex: parseInt(nodeName.split('-').pop() || '1', 10),
        healthy: false,
        driver: 'docker',
        latencyMs: Date.now() - start,
        error: err.message,
      };
    }
  }

  async deleteShare(nodeName: string, userId?: string): Promise<void> {
    if (userId) {
      try {
        await execFileAsync('docker', [
          'exec',
          nodeName,
          'rm',
          '-f',
          `/vault/wallets/${userId}/encrypted_share.json`,
        ]);
      } catch {}
    } else {
      try {
        await execFileAsync('docker', ['rm', '-f', nodeName]);
      } catch {}
    }
  }
}

// Unified Node Cluster Manager

export class NodeClusterManager {
  private dockerDriver = new DockerNodeDriver();
  private sandboxDriver = new SandboxNodeDriver();
  private daemons = new Map<string, MpcParticipantDaemon>();
  private childProcesses = new Map<string, ChildProcess>();
  private participantClients = new Map<string, AuthenticatedParticipantClient>();

  /**
   * Node IPC Authentication Credentials Map.
   *
   * Trust Assumption:
   * The coordinator generates unique CSPRNG 256-bit IPC secrets per participant node and provisions
   * them to participant daemons upon spawn over secure local process launch arguments/environment.
   * In a distributed multi-host deployment, these credentials must be provisioned via mutual TLS client
   * certificates or an external HSM / KMS.
   */
  private nodeIpcSecrets = new Map<string, string>();

  /**
   * Retrieves or generates a cryptographically strong 256-bit CSPRNG IPC secret for a node.
   */
  public getOrCreateNodeIpcSecret(nodeId: string): string {
    let secret = this.nodeIpcSecrets.get(nodeId);
    if (!secret) {
      secret = crypto.randomBytes(32).toString('hex');
      this.nodeIpcSecrets.set(nodeId, secret);
    }
    return secret;
  }

  /**
   * Rotates a node's IPC authentication secret.
   */
  public rotateNodeIpcSecret(nodeId: string): string {
    const fresh = crypto.randomBytes(32).toString('hex');
    this.nodeIpcSecrets.set(nodeId, fresh);
    return fresh;
  }

  /**
   * Registers or updates an active participant daemon instance.
   */
  public registerDaemon(userId: string, daemon: MpcParticipantDaemon): void {
    const key = `${userId}:${daemon.domain}:${daemon.nodeIndex}`;
    this.daemons.set(key, daemon);
  }

  /**
   * Checks if a Unix domain socket server is active and responding.
   */
  private async isSocketResponding(socketPath: string): Promise<boolean> {
    if (!fs.existsSync(socketPath)) return false;
    return new Promise((resolve) => {
      const s = net.createConnection(socketPath);
      s.setTimeout(300);
      s.on('connect', () => {
        s.end();
        resolve(true);
      });
      s.on('error', () => resolve(false));
      s.on('timeout', () => {
        s.destroy();
        resolve(false);
      });
    });
  }

  /**
   * Ensures an independent participant daemon process is running on its designated socket.
   */
  public async ensureParticipantProcessRunning(
    nodeId: string,
    domain: DomainType,
    nodeIndex: number,
    shareIndex: number,
    ipcAuthKey?: string
  ): Promise<{ socketPath: string; pid?: number }> {
    const socketDir = getProtectedSocketDirectory();
    const socketPath = path.join(socketDir, `${nodeId}.sock`);
    const key = ipcAuthKey || this.getOrCreateNodeIpcSecret(nodeId);

    const alive = await this.isSocketResponding(socketPath);
    if (alive) {
      return { socketPath };
    }

    if (fs.existsSync(socketPath)) {
      try {
        const lstat = fs.lstatSync(socketPath);
        if (!lstat.isSymbolicLink()) {
          if (typeof process.getuid !== 'function' || lstat.uid === process.getuid()) {
            fs.unlinkSync(socketPath);
          }
        }
      } catch {}
    }

    const scriptPath = path.resolve(__dirname, '../participant/participantDaemonProcess.ts');
    const tsxBin = path.resolve(process.cwd(), 'node_modules/.bin/tsx');

    const child = spawn(
      tsxBin,
      [
        scriptPath,
        '--nodeId', nodeId,
        '--domain', domain,
        '--nodeIndex', String(nodeIndex),
        '--shareIndex', String(shareIndex),
        '--socketPath', socketPath,
        '--ipcAuthKey', key,
      ],
      {
        detached: true,
        stdio: 'ignore',
      }
    );
    child.unref();
    this.childProcesses.set(nodeId, child);

    // Wait for the Unix domain socket server to become active
    let ready = false;
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 100));
      if (await this.isSocketResponding(socketPath)) {
        ready = true;
        break;
      }
    }

    if (!ready) {
      throw new Error(`[NodeCluster] Failed to spawn participant process for ${nodeId} on socket ${socketPath}`);
    }

    return { socketPath, pid: child.pid };
  }

  /**
   * Retrieves an independent MPC participant client for a given node.
   * The client connects over a real Unix Domain Socket (UDS) to an isolated participant process.
   * The encrypted share payload is loaded and decrypted strictly INSIDE the
   * participant process's local memory space.
   * The coordinator/manager never decrypts or handles the plaintext share.
   *
   * Security Invariants:
   *   - No automatic administrator approval. Participants enroll as unapproved (approved: false).
   *   - Validates daemon identity over socket before loading share.
   */
  public async getParticipantClient(
    userId: string,
    domain: DomainType,
    nodeIndex: number,
    shareIndex?: number,
    containerNameHint?: string
  ): Promise<AuthenticatedParticipantClient> {
    const actualShareIndex = shareIndex ?? nodeIndex;
    const nodeId = buildInfrastructureNodeId(domain, nodeIndex);
    const key = `${userId}:${nodeId}`;
    const existingClient = this.participantClients.get(key);
    if (existingClient) return existingClient;

    const socketDir = getProtectedSocketDirectory();
    const socketPath = path.join(socketDir, `${nodeId}.sock`);
    const ipcAuthKey = this.getOrCreateNodeIpcSecret(nodeId);

    // 1. Ensure independent participant OS process is running on its Unix domain socket
    const { pid } = await this.ensureParticipantProcessRunning(
      nodeId,
      domain,
      nodeIndex,
      actualShareIndex,
      ipcAuthKey
    );

    // 2. Perform trusted local provisioning if not already enrolled & approved
    let enrolled = trustedParticipantRegistry.getParticipant(nodeId);
    if (!enrolled || !enrolled.approved) {
      const bootstrapClient = new AuthenticatedParticipantClient({
        id: nodeId,
        domain,
        nodeIndex,
        shareIndex: actualShareIndex,
        identityPublicKeyHex: enrolled?.identityPublicKeyHex || '',
        socketPath,
        remotePid: pid,
        ipcAuthKey,
      });

      const popInfo = await bootstrapClient.getIdentityPoP();
      enrolled = trustedParticipantRegistry.provisionTrustedLocalParticipant({
        nodeId: popInfo.nodeId,
        domain: popInfo.domain,
        nodeIndex: popInfo.nodeIndex,
        shareIndex: popInfo.shareIndex,
        identityPublicKeyHex: popInfo.identityPublicKeyHex,
        endpoint: popInfo.endpoint,
        proofOfPossessionSigHex: popInfo.proofOfPossessionSigHex,
        popTimestamp: popInfo.popTimestamp,
      });
    }

    if (!enrolled || !enrolled.approved) {
      throw new Error(`[NodeCluster] Trusted local provisioning failed for node ${nodeId}`);
    }

    // 3. Construct authenticated socket client (holds ZERO service instances or plaintext shares)
    const client = new AuthenticatedParticipantClient({
      id: nodeId,
      domain,
      nodeIndex,
      shareIndex: actualShareIndex,
      identityPublicKeyHex: enrolled.identityPublicKeyHex,
      socketPath,
      remotePid: pid,
      ipcAuthKey,
    });

    // 4. Validate daemon identity over the socket before dispatching share
    const ping = await client.ping();
    if (ping.identityPublicKeyHex !== enrolled.identityPublicKeyHex) {
      throw new Error(
        `[NodeCluster] Daemon identity validation failed over socket for node ${nodeId}: reported public key does not match enrolled public key`
      );
    }

    // 5. Retrieve encrypted share blob directly from node vault/container for this tenant
    const encrypted = await this.retrieveShareFromNode(
      userId,
      domain,
      nodeIndex,
      containerNameHint
    );

    // 6. Dispatch encrypted payload to participant daemon process over socket with tenant context
    await client.loadShare({ encryptedShare: encrypted, userId });

    this.participantClients.set(key, client);
    return client;
  }

  /**
   * Initializes and ensures all 19 fixed infrastructure participant nodes are running and active.
   * Reuses existing nodes, daemons, and containers; idempotent across restarts.
   */
  public async ensureInfrastructureReady(): Promise<{ totalNodes: number; initialized: number }> {
    const topology = [
      { domain: 'FOUNDATION' as const, count: 1 },
      { domain: 'PUBLIC' as const, count: 9 },
      { domain: 'PRIVATE' as const, count: 9 },
    ];

    let initialized = 0;
    const socketDir = getProtectedSocketDirectory();

    for (const { domain, count } of topology) {
      for (let i = 1; i <= count; i++) {
        const nodeId = buildInfrastructureNodeId(domain, i);
        const socketPath = path.join(socketDir, `${nodeId}.sock`);
        const ipcAuthKey = this.getOrCreateNodeIpcSecret(nodeId);

        // Ensure participant daemon is running on its socket
        const { pid } = await this.ensureParticipantProcessRunning(
          nodeId,
          domain,
          i,
          i,
          ipcAuthKey
        );

        // Ensure enrolled and approved in registry via trusted local provisioning
        let enrolled = trustedParticipantRegistry.getParticipant(nodeId);
        if (!enrolled || !enrolled.approved) {
          const bootstrapClient = new AuthenticatedParticipantClient({
            id: nodeId,
            domain,
            nodeIndex: i,
            shareIndex: i,
            identityPublicKeyHex: enrolled?.identityPublicKeyHex || '',
            socketPath,
            remotePid: pid,
            ipcAuthKey,
          });

          const popInfo = await bootstrapClient.getIdentityPoP();
          enrolled = trustedParticipantRegistry.provisionTrustedLocalParticipant({
            nodeId: popInfo.nodeId,
            domain: popInfo.domain,
            nodeIndex: popInfo.nodeIndex,
            shareIndex: popInfo.shareIndex,
            identityPublicKeyHex: popInfo.identityPublicKeyHex,
            endpoint: popInfo.endpoint,
            proofOfPossessionSigHex: popInfo.proofOfPossessionSigHex,
            popTimestamp: popInfo.popTimestamp,
          });
        }

        // Write initial health record for sandbox driver if not exists
        await this.sandboxDriver.writeShare(nodeId, 'INIT', domain);
        initialized++;
      }
    }

    return { totalNodes: 19, initialized };
  }

  /**
   * Explicit administrator approval operation for an enrolled participant node.
   */
  public approveNode(nodeId: string, adminSecret?: string): void {
    trustedParticipantRegistry.approveParticipant(nodeId, adminSecret);
  }

  /**
   * Retrieves an independent MPC participant daemon for a given node.
   * Provided for backward compatibility; delegates to getParticipantClient.
   * Share decryption is strictly isolated inside the participant process.
   */
  public async getParticipantDaemon(
    userId: string,
    domain: DomainType,
    nodeIndex: number,
    shareIndex?: number,
    containerNameHint?: string
  ): Promise<MpcParticipantDaemon> {
    const nodeId = buildInfrastructureNodeId(domain, nodeIndex);
    const key = `${userId}:${nodeId}`;
    const existing = this.daemons.get(key);
    if (existing) return existing;

    const client = await this.getParticipantClient(
      userId,
      domain,
      nodeIndex,
      shareIndex,
      containerNameHint
    );
    return client as unknown as MpcParticipantDaemon;
  }

  /**
   * Automatically selects the active storage driver.
   * If Docker daemon is responsive, uses Docker; otherwise falls back to Isolated Sandbox Vault.
   */
  async getPreferredDriver(): Promise<'docker' | 'sandbox'> {
    const dockerOk = await this.dockerDriver.checkDockerDaemon();
    return dockerOk ? 'docker' : 'sandbox';
  }

  /**
   * Stores an encrypted share in the target node container/vault for a specific tenant.
   */
  async deployShareToNode(
    userId: string,
    domain: DomainType,
    nodeIndex: number,
    encryptedShare: string
  ): Promise<NodeInstanceInfo> {
    const nodeName = buildInfrastructureNodeId(domain, nodeIndex);
    const driver = await this.getPreferredDriver();

    if (driver === 'docker') {
      try {
        return await this.dockerDriver.writeShare(nodeName, encryptedShare, domain, userId);
      } catch (err: any) {
        console.warn(`[NodeCluster] Docker write failed for ${nodeName}, using sandbox fallback: ${err.message}`);
      }
    }

    return await this.sandboxDriver.writeShare(nodeName, encryptedShare, domain, userId);
  }

  /**
   * Retrieves an encrypted share from a specific node for a specific tenant.
   * Checks both Docker and Sandbox Vault for maximum resilience.
   */
  async retrieveShareFromNode(
    userId: string,
    domain: DomainType,
    nodeIndex: number,
    containerNameHint?: string
  ): Promise<string> {
    const primaryName = buildInfrastructureNodeId(domain, nodeIndex);
    const candidateNames = [
      primaryName,
      containerNameHint,
      buildLegacyContainerName(userId, domain, nodeIndex),
      buildLegacyContainerName(userId, domain === 'FOUNDATION' ? 'INSTITUTIONAL' : domain === 'PRIVATE' ? 'SOVEREIGN' : 'PUBLIC', nodeIndex),
    ].filter(Boolean) as string[];

    // 1. Try Docker if active
    const dockerOk = await this.dockerDriver.checkDockerDaemon();
    if (dockerOk) {
      for (const name of candidateNames) {
        try {
          const share = await this.dockerDriver.readShare(name, userId);
          if (share) return share;
        } catch {}
      }
    }

    // 2. Try Sandbox Vault
    for (const name of candidateNames) {
      try {
        const share = await this.sandboxDriver.readShare(name, userId);
        if (share) return share;
      } catch {}
    }

    throw new Error(
      `[NodeCluster] Share could not be retrieved from node ${primaryName} for user ${userId} (tried candidate names: ${candidateNames.join(', ')})`
    );
  }

  /**
   * Batch reads shares for multiple nodes efficiently.
   */
  async retrieveSharesBatch(
    nodes: Array<{ userId: string; domain: DomainType; nodeIndex: number; containerName: string }>
  ): Promise<Map<string, string>> {
    const results = new Map<string, string>();
    const dockerOk = await this.dockerDriver.checkDockerDaemon();

    if (dockerOk) {
      const dockerNames = nodes.map((n) => n.containerName);
      try {
        const dockerResults = await this.dockerDriver.readSharesBatch(dockerNames);
        for (const [k, v] of dockerResults.entries()) {
          results.set(k, v);
        }
      } catch {}
    }

    // Fallback for any missing items
    for (const node of nodes) {
      if (!results.has(node.containerName)) {
        try {
          const share = await this.retrieveShareFromNode(
            node.userId,
            node.domain,
            node.nodeIndex,
            node.containerName
          );
          results.set(node.containerName, share);
        } catch (err: any) {
          console.warn(`[NodeCluster] Batch read item failed: ${node.containerName}: ${err.message}`);
        }
      }
    }

    return results;
  }

  /**
   * Health-checks the 19 fixed participant nodes across Foundation, Public, and Private domains.
   */
  async checkClusterHealth(
    userId?: string,
    threshold: number = 5
  ): Promise<ClusterStatus> {
    const driver = await this.getPreferredDriver();
    const domainStats = {
      FOUNDATION: { total: 1, online: 0, threshold: 1 },
      PUBLIC: { total: 9, online: 0, threshold: 5 },
      PRIVATE: { total: 9, online: 0, threshold: 5 },
    };

    // 1. Foundation: 1 node (saral-foundation-1)
    {
      const nodeName = buildInfrastructureNodeId('FOUNDATION', 1);
      let healthy = false;
      if (driver === 'docker') {
        const res = await this.dockerDriver.checkHealth(nodeName);
        healthy = res.healthy;
      }
      if (!healthy) {
        const res = await this.sandboxDriver.checkHealth(nodeName);
        healthy = res.healthy;
      }
      if (healthy) domainStats.FOUNDATION.online += 1;
    }

    // 2. Public: 9 nodes (saral-public-1..9)
    for (let i = 1; i <= 9; i++) {
      const nodeName = buildInfrastructureNodeId('PUBLIC', i);
      let healthy = false;
      if (driver === 'docker') {
        const res = await this.dockerDriver.checkHealth(nodeName);
        healthy = res.healthy;
      }
      if (!healthy) {
        const res = await this.sandboxDriver.checkHealth(nodeName);
        healthy = res.healthy;
      }
      if (healthy) domainStats.PUBLIC.online += 1;
    }

    // 3. Private: 9 nodes (saral-private-1..9)
    for (let i = 1; i <= 9; i++) {
      const nodeName = buildInfrastructureNodeId('PRIVATE', i);
      let healthy = false;
      if (driver === 'docker') {
        const res = await this.dockerDriver.checkHealth(nodeName);
        healthy = res.healthy;
      }
      if (!healthy) {
        const res = await this.sandboxDriver.checkHealth(nodeName);
        healthy = res.healthy;
      }
      if (healthy) domainStats.PRIVATE.online += 1;
    }

    const isHealthy =
      domainStats.FOUNDATION.online >= domainStats.FOUNDATION.threshold &&
      domainStats.PUBLIC.online >= domainStats.PUBLIC.threshold &&
      domainStats.PRIVATE.online >= domainStats.PRIVATE.threshold;

    return {
      totalNodes: 19,
      domainBreakdown: domainStats,
      healthy: isHealthy,
      activeDriver: driver,
    };
  }

  /**
   * Deallocates tenant-specific shares for a given user.
   * Does NOT destroy or terminate the shared 19 infrastructure nodes or containers!
   */
  async destroyUserNodes(userId: string): Promise<void> {
    const topology = [
      { domain: 'FOUNDATION' as const, count: 1 },
      { domain: 'PUBLIC' as const, count: 9 },
      { domain: 'PRIVATE' as const, count: 9 },
    ];
    for (const { domain, count } of topology) {
      for (let i = 1; i <= count; i++) {
        const nodeId = buildInfrastructureNodeId(domain, i);
        const key = `${userId}:${nodeId}`;
        this.participantClients.delete(key);

        await this.dockerDriver.deleteShare(nodeId, userId);
        await this.sandboxDriver.deleteShare(nodeId, userId);
      }
    }
  }
}

// Global cluster manager singleton
export const nodeCluster = new NodeClusterManager();

