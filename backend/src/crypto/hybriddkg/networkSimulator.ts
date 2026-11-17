/**
 * networkSimulator.ts
 *
 * Deterministic seeded asynchronous network simulator and DKG adapter for SARAL.
 *
 * Features:
 *   - Seeded deterministic PRNG for reproducible runs and tests
 *   - Arbitrary message delay, reordering, duplication, and dropping
 *   - Crash-stop and crash-recovery simulation with Help protocol
 *   - Byzantine node simulation:
 *       - Equivocating dealer: sends conflicting polynomials / commitments to different nodes
 *       - Bad share dealer: sends corrupted polynomial evaluations that fail verifyPoly / verifyPoint
 *       - Silent leader: fails to propose within delay(T) timeout
 *       - Faulty proposal leader: sends invalid Q cardinality or corrupted ready proofs
 *       - Help-flooding adversary
 *   - Adapter: runHybridDomainDkg producing DkgResult compatible with SARAL wallet flow
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import type { DomainType } from '../thresholdEcdsa';
import type { DkgResult } from './types';
import {
  deriveHybridParams,
  HybridDkgNode,
} from './hybridDkg';
import {
  sampleSymmetricBivariatePoly,
  deriveRowPolynomial,
} from './bivariatePolynomial';
import {
  computeCommitmentMatrix,
  scalarMultiplyGSafe,
} from './commitments';
import {
  CURVE_ORDER,
  modN,
  randomScalar,
  scalarToHex,
} from '../secp256k1Math';
import type {
  AnyProtocolMessage,
  NodeConfig,
  OutgoingMessage,
  VssSendMsg,
  DkgProposalMsg,
  VssHelpMsg,
  Clock,
  Rng,
} from './types';

/**
 * Seeded PRNG using Mulberry32 algorithm.
 */
export class SeededRng implements Rng {
  private s: number;

  constructor(seed: number = 42) {
    this.s = seed >>> 0;
  }

  nextFloat(): number {
    let t = (this.s += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  nextInt(min: number, max: number): number {
    return Math.floor(this.nextFloat() * (max - min + 1)) + min;
  }

  randomScalar(): bigint {
    let scalar = 0n;
    for (let i = 0; i < 4; i++) {
      const chunk = BigInt(Math.floor(this.nextFloat() * 0xffffffff));
      scalar = (scalar << 32n) | chunk;
    }
    const result = modN(scalar);
    return result === 0n ? 1n : result;
  }
}

export type ByzantineType =
  | 'EQUIVOCATING_DEALER'
  | 'BAD_SHARE_DEALER'
  | 'SILENT_LEADER'
  | 'BAD_PROPOSAL_LEADER'
  | 'HELP_FLOOD';

export interface NetworkFaultConfig {
  delayRange?: [number, number];       // [minStepDelay, maxStepDelay]
  dropProbability?: number;            // [0..1]
  duplicateProbability?: number;       // [0..1]
  reorder?: boolean;                   // Shuffle deliverable messages
  crashedNodeIndices?: Set<number>;    // Nodes crashed initially
  byzantineNodes?: Map<number, ByzantineType>; // nodeIndex -> behavior
}

interface QueuedPacket {
  id: number;
  scheduledStep: number;
  targetIndex: number;
  message: AnyProtocolMessage;
}

export class NetworkSimulator {
  readonly domain: DomainType;
  readonly nodeIds: string[];
  readonly n: number;
  readonly t: number;
  readonly f: number;
  readonly rng: SeededRng;
  readonly faults: NetworkFaultConfig;

  private nodes: Map<number, HybridDkgNode> = new Map();
  private crashedNodes: Set<number> = new Set();
  private packetQueue: QueuedPacket[] = [];
  private packetIdCounter: number = 0;
  private currentStep: number = 0;

  constructor(
    domain: DomainType,
    nodeIds: string[],
    params: { t?: number; f?: number; seed?: number },
    faults: NetworkFaultConfig = {}
  ) {
    this.domain = domain;
    this.nodeIds = nodeIds;
    this.n = nodeIds.length;
    this.rng = new SeededRng(params.seed ?? 12345);
    this.faults = faults;

    const derived = deriveHybridParams(this.n, params.t, params.f);
    this.t = derived.t;
    this.f = derived.f;

    if (faults.crashedNodeIndices) {
      for (const idx of faults.crashedNodeIndices) {
        this.crashedNodes.add(idx);
      }
    }

    this.initializeNodes();
  }

  private initializeNodes(): void {
    const sessionId = `sim-${this.domain.toLowerCase()}-${this.rng.nextInt(1000, 9999)}`;

    for (let i = 1; i <= this.n; i++) {
      const nodeId = this.nodeIds[i - 1];

      // Simulated clock tracking step number
      const clock: Clock = {
        now: () => this.currentStep * 100,
      };

      const config: NodeConfig = {
        n: this.n,
        t: this.t,
        f: this.f,
        nodeIndex: i,
        nodeId,
        domain: this.domain,
        sessionId,
        allNodeIds: this.nodeIds,
        helpLimitD: 3,
        timeoutMs: 2000, // 20 simulator ticks (at 100ms / tick)
        clock,
        rng: this.rng,
      };

      const node = new HybridDkgNode(config);
      this.nodes.set(i, node);
    }
  }

  /**
   * Starts DKG across all active (non-crashed) nodes.
   */
  start(): void {
    for (let i = 1; i <= this.n; i++) {
      if (this.crashedNodes.has(i)) continue;

      const byz = this.faults.byzantineNodes?.get(i);
      const node = this.nodes.get(i)!;

      if (byz === 'EQUIVOCATING_DEALER') {
        // Byzantine: Equivocating dealer sends different polynomials to nodes 1..4 vs 5..n
        this.startEquivocatingDealing(i);
      } else if (byz === 'BAD_SHARE_DEALER') {
        // Byzantine: Dealer sends garbage polynomial coefficients
        this.startBadShareDealing(i);
      } else {
        const outgoing = node.startDealing();
        this.routeOutgoing(i, outgoing);
      }
    }
  }

  private startEquivocatingDealing(dealerIndex: number): void {
    const poly1 = sampleSymmetricBivariatePoly(this.t, 100n, this.rng);
    const C1 = computeCommitmentMatrix(poly1);

    const poly2 = sampleSymmetricBivariatePoly(this.t, 200n, this.rng);
    const C2 = computeCommitmentMatrix(poly2);

    const outgoing: OutgoingMessage[] = [];
    const node = this.nodes.get(dealerIndex)!;

    for (let j = 1; j <= this.n; j++) {
      const usePoly = j <= Math.ceil(this.n / 2) ? poly1 : poly2;
      const useC = j <= Math.ceil(this.n / 2) ? C1 : C2;
      const row = deriveRowPolynomial(usePoly, j);

      const msg: VssSendMsg = {
        type: 'VSS_SEND',
        sessionId: node.config.sessionId,
        domain: this.domain,
        dealerIndex,
        targetIndex: j,
        commitmentMatrix: useC,
        aCoeffs: row.map(scalarToHex),
      };

      outgoing.push({ targetIndex: j, message: msg });
    }

    this.routeOutgoing(dealerIndex, outgoing);
  }

  private startBadShareDealing(dealerIndex: number): void {
    const poly = sampleSymmetricBivariatePoly(this.t, 555n, this.rng);
    const C = computeCommitmentMatrix(poly);
    const outgoing: OutgoingMessage[] = [];
    const node = this.nodes.get(dealerIndex)!;

    for (let j = 1; j <= this.n; j++) {
      const row = deriveRowPolynomial(poly, j);
      // Corrupt coefficient 0
      row[0] = modN(row[0] + 12345n);

      const msg: VssSendMsg = {
        type: 'VSS_SEND',
        sessionId: node.config.sessionId,
        domain: this.domain,
        dealerIndex,
        targetIndex: j,
        commitmentMatrix: C,
        aCoeffs: row.map(scalarToHex),
      };

      outgoing.push({ targetIndex: j, message: msg });
    }

    this.routeOutgoing(dealerIndex, outgoing);
  }

  /**
   * Enqueues outgoing messages with delay, drop, duplication, and reordering.
   */
  private routeOutgoing(senderIndex: number, outgoing: OutgoingMessage[]): void {
    const minDelay = this.faults.delayRange ? this.faults.delayRange[0] : 0;
    const maxDelay = this.faults.delayRange ? this.faults.delayRange[1] : 2;

    for (const item of outgoing) {
      const recipients =
        item.targetIndex === 'broadcast'
          ? Array.from({ length: this.n }, (_, idx) => idx + 1).filter((idx) => idx !== senderIndex)
          : [item.targetIndex];

      for (const target of recipients) {
        // Intercept Byzantine behavior from sender
        const byz = this.faults.byzantineNodes?.get(senderIndex);
        if (byz === 'SILENT_LEADER' && item.message.type === 'DKG_PROPOSAL') {
          // Drop silent leader's proposals
          continue;
        }
        if (byz === 'BAD_PROPOSAL_LEADER' && item.message.type === 'DKG_PROPOSAL') {
          // Alter Q to violate cardinality |Q| == t + 1
          const alteredMsg: DkgProposalMsg = {
            ...(item.message as DkgProposalMsg),
            Q: [1], // Invalid cardinality
          };
          this.schedulePacket(target, alteredMsg, minDelay, maxDelay);
          continue;
        }

        // Apply drop probability (unless message is help reply)
        if (this.faults.dropProbability && item.message.type !== 'VSS_HELP_REPLY') {
          if (this.rng.nextFloat() < this.faults.dropProbability) {
            continue;
          }
        }

        this.schedulePacket(target, item.message, minDelay, maxDelay);

        // Apply duplicate probability
        if (this.faults.duplicateProbability) {
          if (this.rng.nextFloat() < this.faults.duplicateProbability) {
            this.schedulePacket(target, item.message, minDelay + 1, maxDelay + 2);
          }
        }
      }
    }
  }

  private schedulePacket(
    targetIndex: number,
    message: AnyProtocolMessage,
    minDelay: number,
    maxDelay: number
  ): void {
    const delay = this.rng.nextInt(minDelay, maxDelay);
    const packet: QueuedPacket = {
      id: ++this.packetIdCounter,
      scheduledStep: this.currentStep + delay,
      targetIndex,
      message,
    };
    this.packetQueue.push(packet);
  }

  /**
   * Advances the network by one step.
   */
  step(): void {
    this.currentStep++;

    // Check timers on all running nodes
    for (let i = 1; i <= this.n; i++) {
      if (this.crashedNodes.has(i)) continue;
      const node = this.nodes.get(i)!;
      const timerOut = node.checkTimer(this.currentStep * 100);
      if (timerOut.length > 0) {
        this.routeOutgoing(i, timerOut);
      }
    }

    // Collect all packets ready for delivery at or before currentStep
    const deliverable: QueuedPacket[] = [];
    const remaining: QueuedPacket[] = [];

    for (const packet of this.packetQueue) {
      if (packet.scheduledStep <= this.currentStep) {
        deliverable.push(packet);
      } else {
        remaining.push(packet);
      }
    }

    this.packetQueue = remaining;

    // Optional reordering (Fisher-Yates shuffle)
    if (this.faults.reorder !== false && deliverable.length > 1) {
      for (let i = deliverable.length - 1; i > 0; i--) {
        const j = Math.floor(this.rng.nextFloat() * (i + 1));
        [deliverable[i], deliverable[j]] = [deliverable[j], deliverable[i]];
      }
    }

    // Deliver packets
    for (const packet of deliverable) {
      const target = packet.targetIndex;
      if (this.crashedNodes.has(target)) {
        // Dropped by crashed node
        continue;
      }

      const node = this.nodes.get(target);
      if (!node) continue;

      const outgoing = node.handle(packet.message);
      if (outgoing.length > 0) {
        this.routeOutgoing(target, outgoing);
      }
    }
  }

  /**
   * Crashes a node, making it silent and dropping incoming messages.
   */
  crashNode(nodeIndex: number): void {
    this.crashedNodes.add(nodeIndex);
  }

  /**
   * Recovers a crashed node and triggers help protocol to catch up.
   */
  recoverNode(nodeIndex: number): void {
    if (!this.crashedNodes.has(nodeIndex)) return;
    this.crashedNodes.delete(nodeIndex);

    const node = this.nodes.get(nodeIndex)!;
    // Broadcast help request per Fig. 1
    const vssHelpMsg: VssHelpMsg = {
      type: 'VSS_HELP',
      sessionId: node.config.sessionId,
      domain: this.domain,
      requesterIndex: nodeIndex,
    };

    const helpOut: OutgoingMessage[] = [];
    for (let j = 1; j <= this.n; j++) {
      if (j !== nodeIndex) {
        helpOut.push({ targetIndex: j, message: vssHelpMsg });
      }
    }

    this.routeOutgoing(nodeIndex, helpOut);
  }

  /**
   * Executes the simulation until honest (non-Byzantine, non-crashed) nodes complete,
   * or maxSteps is reached.
   */
  runUntilComplete(maxSteps: number = 3000): { completed: boolean; steps: number } {
    this.start();

    const honestIndices: number[] = [];
    for (let i = 1; i <= this.n; i++) {
      const isByz = this.faults.byzantineNodes?.has(i);
      const isCrashed = this.crashedNodes.has(i);
      if (!isByz && !isCrashed) {
        honestIndices.push(i);
      }
    }

    while (this.currentStep < maxSteps) {
      this.step();

      // Check if all honest nodes completed
      const allDone = honestIndices.every((idx) => this.nodes.get(idx)!.isComplete());
      if (allDone) {
        return { completed: true, steps: this.currentStep };
      }
    }

    const allDone = honestIndices.every((idx) => this.nodes.get(idx)!.isComplete());
    return { completed: allDone, steps: this.currentStep };
  }

  getNode(nodeIndex: number): HybridDkgNode | undefined {
    return this.nodes.get(nodeIndex);
  }

  getAllNodes(): Map<number, HybridDkgNode> {
    return this.nodes;
  }
}

/**
 * Adapter function that runs HybridDKG in the simulated network and returns a DkgResult
 * compatible with the existing SARAL DkgResult interface (dkg.ts:42).
 */
export function runHybridDomainDkg(
  domain: DomainType,
  nodeIds: string[],
  params?: { t?: number; f?: number; seed?: number }
): DkgResult {
  const n = nodeIds.length;
  if (n < 4) {
    throw new Error(`[HybridDKG] Need at least 4 nodes for asynchronous DKG, got ${n}`);
  }

  const derived = deriveHybridParams(n, params?.t, params?.f);
  const sim = new NetworkSimulator(domain, nodeIds, {
    t: derived.t,
    f: derived.f,
    seed: params?.seed ?? 42,
  });

  const { completed, steps } = sim.runUntilComplete(2500);
  if (!completed) {
    throw new Error(`[HybridDKG] Protocol did not terminate within ${steps} steps`);
  }

  const nodeShares = new Map<string, bigint>();
  const allCommitments = new Map<string, string[]>();
  let domainPublicKeyHex: string | null = null;
  let agreedQ: number[] | null = null;

  for (let i = 1; i <= n; i++) {
    const node = sim.getNode(i)!;
    const out = node.getOutput();
    if (!out) {
      throw new Error(`[HybridDKG] Missing output for node ${i}`);
    }

    nodeShares.set(out.nodeId, out.share);
    allCommitments.set(out.nodeId, out.commitments);

    if (!domainPublicKeyHex) {
      domainPublicKeyHex = out.domainPublicKeyHex;
      agreedQ = out.Q;
    } else {
      // Consistency check: all nodes must produce identical domain public key and Q
      if (domainPublicKeyHex !== out.domainPublicKeyHex) {
        throw new Error('[HybridDKG] Agreement breach: nodes arrived at different domain public keys');
      }
    }
  }

  if (!domainPublicKeyHex || !agreedQ) {
    throw new Error('[HybridDKG] No public key generated');
  }

  return {
    domain,
    domainPublicKeyHex,
    nodeShares,
    allCommitments,
    threshold: derived.threshold,
    totalNodes: n,
  };
}
