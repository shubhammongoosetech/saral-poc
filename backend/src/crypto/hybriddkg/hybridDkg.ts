/**
 * hybridDkg.ts
 *
 * Asynchronous Distributed Key Generation (HybridDKG) Node State Machine.
 *
 * Reference:
 *   "Distributed Key Generation in the Wild" (Kate, Huang, Goldberg), Section 3.2-3.3, Figures 2 & 3.
 *
 * Implements:
 *   - n parallel HybridVSS instances per node
 *   - Optimistic Phase (Figure 2):
 *       - Leader L proposes set Q-hat of t+1 completed dealers with ready proofs
 *       - Reliable broadcast (echo, ready) with quorums ceil((n+t+1)/2), t+1, n-t-f
 *       - Delivery of Q and local share / commitment matrix accumulation
 *   - Pessimistic Phase / Leader Change (Figure 3):
 *       - Timer delay(T) expires or invalid proposal -> lead-ch(L+1, Q, M)
 *       - Join with t + f + 1 lead-ch messages
 *       - Accept new leader with n - t - f lead-ch messages
 *       - New leader re-proposes previously reported Q or proposes new Q
 *   - Parameter derivation & validator enforcing n >= 3t + 2f + 1 fail-closed
 */

import crypto from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  modN,
  CURVE_ORDER,
} from '../secp256k1Math';
import {
  addCommitmentMatrices,
  parseCurvePoint,
} from './commitments';
import { HybridVssNode } from './hybridVss';
import type {
  NodeConfig,
  HybridDkgParams,
  AnyProtocolMessage,
  OutgoingMessage,
  DkgProposalMsg,
  DkgEchoMsg,
  DkgReadyMsg,
  DkgLeadChMsg,
  VssReadyMsg,
  VssHelpMsg,
  VssHelpReplyMsg,
  HybridDkgOutput,
  Clock,
} from './types';

/**
 * Validates and derives parameters for HybridDKG per Kate, Huang, Goldberg (Section 3).
 * Enforces the fundamental asynchronous consensus bound: n >= 3t + 2f + 1.
 * Fail-closed: throws Error on any violation.
 */
export function deriveHybridParams(
  n: number,
  t?: number,
  f?: number
): HybridDkgParams {
  if (n < 4) {
    throw new Error(`[HybridDKG Params] Node count n=${n} must be at least 4`);
  }

  let derivedT: number;
  let derivedF: number;

  if (t !== undefined) {
    if (t < 1) {
      throw new Error(`[HybridDKG Params] Byzantine bound t=${t} must be >= 1`);
    }
    derivedT = t;
    derivedF = f !== undefined ? f : 0;
  } else {
    // Derive maximal t assuming f = 1 if possible, otherwise f = 0
    // 3t + 2f + 1 <= n
    const targetF = f !== undefined ? f : (n >= 9 ? 1 : 0);
    derivedT = Math.floor((n - 2 * targetF - 1) / 3);
    if (derivedT < 1) derivedT = 1;
    derivedF = targetF;
  }

  if (derivedF < 0) {
    throw new Error(`[HybridDKG Params] Crash bound f=${derivedF} cannot be negative`);
  }

  const minRequiredNodes = 3 * derivedT + 2 * derivedF + 1;
  if (n < minRequiredNodes) {
    throw new Error(
      `[HybridDKG Params] Asynchronous bound violated: n=${n} is less than 3t + 2f + 1 = ${minRequiredNodes} (t=${derivedT}, f=${derivedF})`
    );
  }

  const degree = derivedT;
  const threshold = derivedT + 1;
  const echoQuorum = Math.ceil((n + derivedT + 1) / 2);
  const readyInterpolateThreshold = derivedT + 1;
  const readyCompleteThreshold = n - derivedT - derivedF;

  return {
    n,
    t: derivedT,
    f: derivedF,
    degree,
    threshold,
    echoQuorum,
    readyInterpolateThreshold,
    readyCompleteThreshold,
  };
}

export class HybridDkgNode {
  readonly config: NodeConfig;
  readonly params: HybridDkgParams;
  readonly clock: Clock;

  // n parallel HybridVSS instances: dealerIndex (1..n) -> HybridVssNode
  private vssNodes: Map<number, HybridVssNode> = new Map();

  // Pure outbox B recording all outgoing messages
  private outbox: AnyProtocolMessage[] = [];

  // Rate-limiting help counters (Figure 1)
  private cnt_l: Map<number, number> = new Map();
  private totalCnt: number = 0;
  readonly helpLimitD: number;

  // Metrics: dropped messages counter
  public droppedMessagesCount: number = 0;

  // Deduplication cache: key = `${type}:${leader}:${fromIndex}`
  private seenMessages: Set<string> = new Set();

  // Optimistic Phase RBC state per leader round:
  // leaderIndex -> DkgProposalMsg
  private proposals: Map<number, DkgProposalMsg> = new Map();
  // leaderIndex -> Map<fromIndex, DkgEchoMsg>
  private echoes: Map<number, Map<number, DkgEchoMsg>> = new Map();
  // leaderIndex -> Map<fromIndex, DkgReadyMsg>
  private readies: Map<number, Map<number, DkgReadyMsg>> = new Map();
  private echoSent: Map<number, boolean> = new Map();
  private readySent: Map<number, boolean> = new Map();

  // Leader state
  private currentLeader: number = 1; // 1-based index
  private proposalSentForLeader: Map<number, boolean> = new Map();

  // Timer state
  private timerStartedAt: number | null = null;
  private timerExpired: boolean = false;
  readonly timeoutMs: number;

  // Leader change state: proposedLeader -> Map<fromIndex, DkgLeadChMsg>
  private leadChMessages: Map<number, Map<number, DkgLeadChMsg>> = new Map();
  private leadChSent: Map<number, boolean> = new Map();

  // Final agreement state
  private agreedQ: number[] | null = null;
  private isFinalized: boolean = false;
  private finalOutput: HybridDkgOutput | null = null;

  constructor(config: NodeConfig) {
    this.config = config;
    this.params = deriveHybridParams(config.n, config.t, config.f);
    this.clock = config.clock ?? { now: () => Date.now() };
    this.timeoutMs = config.timeoutMs ?? 2000;
    this.helpLimitD = config.helpLimitD ?? 3;

    // Initialize n parallel VSS sessions for dealers 1..n
    for (let d = 1; d <= this.params.n; d++) {
      const vss = new HybridVssNode(this.config, d);
      this.vssNodes.set(d, vss);
    }
  }

  /**
   * Initializes DKG by initiating this node's own VSS dealing.
   */
  startDealing(secret?: bigint): OutgoingMessage[] {
    const vss = this.vssNodes.get(this.config.nodeIndex);
    if (!vss) return [];

    const msgs = vss.startDealing(secret);
    for (const m of msgs) {
      this.outbox.push(m.message);
    }

    // Check if dealer's own VSS self-completes or triggers leader logic
    const outgoing = [...msgs];
    this.checkVssCompletions(outgoing);
    return outgoing;
  }

  /**
   * Primary entrypoint: processes any incoming message (VSS or DKG).
   * Returns newly emitted outgoing messages.
   */
  handle(msg: AnyProtocolMessage): OutgoingMessage[] {
    if (msg.sessionId !== this.config.sessionId || msg.domain !== this.config.domain) {
      this.droppedMessagesCount++;
      return [];
    }

    const outgoing: OutgoingMessage[] = [];

    switch (msg.type) {
      case 'VSS_SEND':
      case 'VSS_ECHO':
      case 'VSS_READY': {
        const dealer = 'dealerIndex' in msg ? msg.dealerIndex : undefined;
        if (dealer !== undefined) {
          const vss = this.vssNodes.get(dealer);
          if (vss) {
            const vssOutgoing = vss.handle(msg);
            for (const m of vssOutgoing) {
              this.outbox.push(m.message);
              outgoing.push(m);
            }
          }
        }
        this.checkVssCompletions(outgoing);
        break;
      }

      case 'VSS_HELP':
        outgoing.push(...this.handleHelp(msg));
        break;

      case 'VSS_HELP_REPLY':
        outgoing.push(...this.handleHelpReply(msg));
        break;

      case 'DKG_PROPOSAL':
        outgoing.push(...this.handleDkgProposal(msg));
        break;

      case 'DKG_ECHO':
        outgoing.push(...this.handleDkgEcho(msg));
        break;

      case 'DKG_READY':
        outgoing.push(...this.handleDkgReady(msg));
        break;

      case 'DKG_LEAD_CH':
        outgoing.push(...this.handleDkgLeadCh(msg));
        break;

      default:
        this.droppedMessagesCount++;
        break;
    }

    // Attempt finalization if agreement on Q was reached
    if (this.agreedQ && !this.isFinalized) {
      this.tryFinalize();
    }

    return outgoing;
  }

  /**
   * Fig. 1: Answers incoming Help request from peer requesterIndex.
   * Strictly limited by cnt_l <= d(kappa) and totalCnt <= (t+1)*d(kappa).
   */
  private handleHelp(msg: VssHelpMsg): OutgoingMessage[] {
    const peer = msg.requesterIndex;
    if (peer < 1 || peer > this.params.n || peer === this.config.nodeIndex) {
      this.droppedMessagesCount++;
      return [];
    }

    const currentPeerCount = this.cnt_l.get(peer) ?? 0;
    const maxGlobal = (this.params.t + 1) * this.helpLimitD;

    if (currentPeerCount >= this.helpLimitD || this.totalCnt >= maxGlobal) {
      this.droppedMessagesCount++;
      return [];
    }

    this.cnt_l.set(peer, currentPeerCount + 1);
    this.totalCnt++;

    // Collect all outbox messages destined for requester or broadcast
    const relevant = this.outbox.filter((m) => {
      if ('targetIndex' in m && m.targetIndex === peer) return true;
      if (
        m.type === 'DKG_PROPOSAL' ||
        m.type === 'DKG_ECHO' ||
        m.type === 'DKG_READY' ||
        m.type === 'DKG_LEAD_CH'
      ) {
        return true;
      }
      return false;
    });

    const replyMsg: VssHelpReplyMsg = {
      type: 'VSS_HELP_REPLY',
      sessionId: this.config.sessionId,
      domain: this.config.domain,
      fromIndex: this.config.nodeIndex,
      targetIndex: peer,
      messages: relevant,
    };

    return [{ targetIndex: peer, message: replyMsg }];
  }

  /**
   * Replays messages received in HelpReply to catch up local state.
   */
  private handleHelpReply(msg: VssHelpReplyMsg): OutgoingMessage[] {
    if (msg.targetIndex !== this.config.nodeIndex || !Array.isArray(msg.messages)) {
      this.droppedMessagesCount++;
      return [];
    }

    const outgoing: OutgoingMessage[] = [];
    for (const subMsg of msg.messages) {
      const res = this.handle(subMsg);
      outgoing.push(...res);
    }
    return outgoing;
  }

  /**
   * Periodically checks timer status and initiates leader change on expiry.
   */
  checkTimer(currentTime?: number): OutgoingMessage[] {
    if (this.agreedQ || this.timerStartedAt === null || this.timerExpired) {
      return [];
    }

    const now = currentTime ?? this.clock.now();
    const elapsed = now - this.timerStartedAt;

    if (elapsed >= this.timeoutMs) {
      this.timerExpired = true;
      return this.triggerLeaderChange(this.currentLeader + 1, null);
    }

    return [];
  }

  /**
   * Inspects local VSS completions to advance optimistic phase.
   */
  private checkVssCompletions(outgoing: OutgoingMessage[]): void {
    const completedDealers: number[] = [];
    for (const [d, vss] of this.vssNodes) {
      if (vss.isComplete()) {
        completedDealers.push(d);
      }
    }

    // Start timer once t+1 VSS instances finish locally
    if (completedDealers.length >= this.params.t + 1 && this.timerStartedAt === null) {
      this.timerStartedAt = this.clock.now();
    }

    // If this node is the active leader and has not proposed yet:
    if (
      this.currentLeader === this.config.nodeIndex &&
      completedDealers.length >= this.params.t + 1 &&
      !this.proposalSentForLeader.get(this.currentLeader)
    ) {
      const proposal = this.createLeaderProposal(this.currentLeader, completedDealers);
      if (proposal) {
        this.proposalSentForLeader.set(this.currentLeader, true);
        this.outbox.push(proposal);
        outgoing.push({ targetIndex: 'broadcast', message: proposal });

        // Leader self-echoes
        const selfEchoes = this.handleDkgProposal(proposal);
        outgoing.push(...selfEchoes);
      }
    }
  }

  /**
   * Creates proposal message from leader L selecting first t+1 completed sessions.
   */
  private createLeaderProposal(
    leaderIndex: number,
    completedDealers: number[]
  ): DkgProposalMsg | null {
    if (completedDealers.length < this.params.t + 1) return null;

    const q = [...completedDealers].sort((a, b) => a - b).slice(0, this.params.t + 1);
    const proofs: Record<number, VssReadyMsg[]> = {};

    for (const d of q) {
      const vss = this.vssNodes.get(d);
      const shared = vss?.getSharedOutput();
      if (!shared || shared.readyProofs.length < this.params.readyCompleteThreshold) {
        return null;
      }
      proofs[d] = shared.readyProofs;
    }

    return {
      type: 'DKG_PROPOSAL',
      sessionId: this.config.sessionId,
      domain: this.config.domain,
      leaderIndex,
      Q: q,
      proofs,
    };
  }

  /**
   * Fig. 2: On proposal from leader L
   * Receivers verify proofs in R-hat. If valid, send echo(L, Q) to all.
   */
  private handleDkgProposal(msg: DkgProposalMsg): OutgoingMessage[] {
    if (msg.leaderIndex !== this.currentLeader) {
      this.droppedMessagesCount++;
      return [];
    }

    const dedupKey = `DKG_PROPOSAL:${msg.leaderIndex}:${msg.leaderIndex}`;
    if (this.seenMessages.has(dedupKey)) {
      return [];
    }
    this.seenMessages.add(dedupKey);

    // Verify |Q| == t + 1
    if (!Array.isArray(msg.Q) || msg.Q.length !== this.params.t + 1) {
      this.droppedMessagesCount++;
      return this.triggerLeaderChange(this.currentLeader + 1, null);
    }

    // Verify ready proofs: each d in Q must have >= n - t - f valid ready messages
    for (const d of msg.Q) {
      const readyList = msg.proofs[d];
      if (!Array.isArray(readyList) || readyList.length < this.params.readyCompleteThreshold) {
        this.droppedMessagesCount++;
        return this.triggerLeaderChange(this.currentLeader + 1, null);
      }

      const signers = new Set<number>();
      for (const r of readyList) {
        if (r.dealerIndex !== d) {
          this.droppedMessagesCount++;
          return this.triggerLeaderChange(this.currentLeader + 1, null);
        }
        signers.add(r.fromIndex);
      }

      if (signers.size < this.params.readyCompleteThreshold) {
        this.droppedMessagesCount++;
        return this.triggerLeaderChange(this.currentLeader + 1, null);
      }
    }

    this.proposals.set(msg.leaderIndex, msg);
    const outgoing: OutgoingMessage[] = [];

    // Send echo(L, Q) if not sent yet
    if (!this.echoSent.get(msg.leaderIndex)) {
      this.echoSent.set(msg.leaderIndex, true);

      const echoMsg: DkgEchoMsg = {
        type: 'DKG_ECHO',
        sessionId: this.config.sessionId,
        domain: this.config.domain,
        leaderIndex: msg.leaderIndex,
        fromIndex: this.config.nodeIndex,
        Q: msg.Q,
      };

      this.outbox.push(echoMsg);
      outgoing.push({ targetIndex: 'broadcast', message: echoMsg });

      // Self-deliver echo
      outgoing.push(...this.handleDkgEcho(echoMsg));
    }

    return outgoing;
  }

  /**
   * Fig. 2: On echo(L, Q) from P_m
   * Reliable broadcast echo counter
   */
  private handleDkgEcho(msg: DkgEchoMsg): OutgoingMessage[] {
    if (msg.leaderIndex !== this.currentLeader) {
      this.droppedMessagesCount++;
      return [];
    }

    const dedupKey = `DKG_ECHO:${msg.leaderIndex}:${msg.fromIndex}`;
    if (this.seenMessages.has(dedupKey)) {
      return [];
    }
    this.seenMessages.add(dedupKey);

    let map = this.echoes.get(msg.leaderIndex);
    if (!map) {
      map = new Map();
      this.echoes.set(msg.leaderIndex, map);
    }
    map.set(msg.fromIndex, msg);

    const echoCount = map.size;
    const readyMap = this.readies.get(msg.leaderIndex);
    const readyCount = readyMap ? readyMap.size : 0;
    const outgoing: OutgoingMessage[] = [];

    // When echoCount >= ceil((n+t+1)/2) or readyCount >= t+1, send ready
    if (
      !this.readySent.get(msg.leaderIndex) &&
      (echoCount >= this.params.echoQuorum || readyCount >= this.params.readyInterpolateThreshold)
    ) {
      this.readySent.set(msg.leaderIndex, true);

      const readyMsg: DkgReadyMsg = {
        type: 'DKG_READY',
        sessionId: this.config.sessionId,
        domain: this.config.domain,
        leaderIndex: msg.leaderIndex,
        fromIndex: this.config.nodeIndex,
        Q: msg.Q,
      };

      this.outbox.push(readyMsg);
      outgoing.push({ targetIndex: 'broadcast', message: readyMsg });

      // Self-deliver ready
      outgoing.push(...this.handleDkgReady(readyMsg));
    }

    return outgoing;
  }

  /**
   * Fig. 2: On ready(L, Q) from P_m
   * Reliable broadcast ready counter: amplify on t+1, deliver on n-t-f
   */
  private handleDkgReady(msg: DkgReadyMsg): OutgoingMessage[] {
    if (msg.leaderIndex !== this.currentLeader) {
      this.droppedMessagesCount++;
      return [];
    }

    const dedupKey = `DKG_READY:${msg.leaderIndex}:${msg.fromIndex}`;
    if (this.seenMessages.has(dedupKey)) {
      return [];
    }
    this.seenMessages.add(dedupKey);

    let map = this.readies.get(msg.leaderIndex);
    if (!map) {
      map = new Map();
      this.readies.set(msg.leaderIndex, map);
    }
    map.set(msg.fromIndex, msg);

    const readyCount = map.size;
    const echoMap = this.echoes.get(msg.leaderIndex);
    const echoCount = echoMap ? echoMap.size : 0;
    const outgoing: OutgoingMessage[] = [];

    // Amplification: if readyCount >= t+1 or echoCount >= ceil((n+t+1)/2), send ready
    if (
      !this.readySent.get(msg.leaderIndex) &&
      (readyCount >= this.params.readyInterpolateThreshold || echoCount >= this.params.echoQuorum)
    ) {
      this.readySent.set(msg.leaderIndex, true);

      const readyMsg: DkgReadyMsg = {
        type: 'DKG_READY',
        sessionId: this.config.sessionId,
        domain: this.config.domain,
        leaderIndex: msg.leaderIndex,
        fromIndex: this.config.nodeIndex,
        Q: msg.Q,
      };

      this.outbox.push(readyMsg);
      outgoing.push({ targetIndex: 'broadcast', message: readyMsg });

      // Self-deliver ready
      outgoing.push(...this.handleDkgReady(readyMsg));
    }

    // Delivery: readyCount >= n - t - f
    if (readyCount >= this.params.readyCompleteThreshold && !this.agreedQ) {
      this.agreedQ = [...msg.Q].sort((a, b) => a - b);
    }

    return outgoing;
  }

  /**
   * Fig. 3: Triggers leader change for proposedLeader (L+1).
   */
  private triggerLeaderChange(
    proposedLeader: number,
    candidateQ: number[] | null
  ): OutgoingMessage[] {
    if (this.leadChSent.get(proposedLeader)) return [];
    this.leadChSent.set(proposedLeader, true);

    const qHat = candidateQ ?? this.agreedQ ?? null;

    const leadChMsg: DkgLeadChMsg = {
      type: 'DKG_LEAD_CH',
      sessionId: this.config.sessionId,
      domain: this.config.domain,
      proposedLeaderIndex: proposedLeader,
      fromIndex: this.config.nodeIndex,
      qHat,
    };

    this.outbox.push(leadChMsg);
    const outgoing: OutgoingMessage[] = [{ targetIndex: 'broadcast', message: leadChMsg }];

    // Self-deliver lead-ch
    outgoing.push(...this.handleDkgLeadCh(leadChMsg));
    return outgoing;
  }

  /**
   * Fig. 3: Handles incoming lead-ch messages.
   * Rule 1: with t + f + 1 lead-ch for leaders > L -> join
   * Rule 2: with n - t - f lead-ch for L' > L -> accept new leader L'
   */
  private handleDkgLeadCh(msg: DkgLeadChMsg): OutgoingMessage[] {
    if (msg.proposedLeaderIndex <= this.currentLeader) {
      this.droppedMessagesCount++;
      return [];
    }

    const dedupKey = `DKG_LEAD_CH:${msg.proposedLeaderIndex}:${msg.fromIndex}`;
    if (this.seenMessages.has(dedupKey)) {
      return [];
    }
    this.seenMessages.add(dedupKey);

    let map = this.leadChMessages.get(msg.proposedLeaderIndex);
    if (!map) {
      map = new Map();
      this.leadChMessages.set(msg.proposedLeaderIndex, map);
    }
    map.set(msg.fromIndex, msg);

    const count = map.size;
    const outgoing: OutgoingMessage[] = [];

    // Rule 1: with t + f + 1 lead-ch, join leader change
    if (
      count >= this.params.t + this.params.f + 1 &&
      !this.leadChSent.get(msg.proposedLeaderIndex)
    ) {
      outgoing.push(...this.triggerLeaderChange(msg.proposedLeaderIndex, msg.qHat));
    }

    // Rule 2: with n - t - f lead-ch, accept the new leader
    if (
      count >= this.params.readyCompleteThreshold &&
      this.currentLeader < msg.proposedLeaderIndex
    ) {
      this.currentLeader = msg.proposedLeaderIndex;
      this.timerStartedAt = this.clock.now(); // Reset timer for new leader
      this.timerExpired = false;

      // If this node is the new leader:
      if (this.currentLeader === this.config.nodeIndex) {
        // Check if any lead-ch reported a candidate Q
        let candidateQ: number[] | null = null;
        for (const [, leadMsg] of map) {
          if (leadMsg.qHat && leadMsg.qHat.length === this.params.t + 1) {
            candidateQ = leadMsg.qHat;
            break;
          }
        }

        const completedDealers: number[] = [];
        for (const [d, vss] of this.vssNodes) {
          if (vss.isComplete()) completedDealers.push(d);
        }

        const qToPropose = candidateQ ?? completedDealers;
        const proposal = this.createLeaderProposal(this.currentLeader, qToPropose);

        if (proposal) {
          this.proposalSentForLeader.set(this.currentLeader, true);
          this.outbox.push(proposal);
          outgoing.push({ targetIndex: 'broadcast', message: proposal });

          // Self-echo
          outgoing.push(...this.handleDkgProposal(proposal));
        }
      }
    }

    return outgoing;
  }

  /**
   * Finalizes DKG once agreement on Q is reached and all dealers in Q have completed locally.
   */
  private tryFinalize(): void {
    if (!this.agreedQ || this.isFinalized) return;

    // Check if every dealer in Q has finished locally
    for (const d of this.agreedQ) {
      const vss = this.vssNodes.get(d);
      if (!vss || !vss.isComplete()) {
        return;
      }
    }

    // 1. Accumulated share: s_i = sum_{d in Q} s_{i,d} mod n
    let s_i = 0n;
    for (const d of this.agreedQ) {
      const vss = this.vssNodes.get(d)!;
      const shared = vss.getSharedOutput()!;
      s_i = modN(s_i + shared.share);
    }

    if (s_i === 0n || s_i >= CURVE_ORDER) {
      this.droppedMessagesCount++;
      return;
    }

    // 2. Combined commitment matrix: C = sum_{d in Q} C_d
    const firstMatrix = this.vssNodes.get(this.agreedQ[0])!.getSharedOutput()!.commitmentMatrix;
    let combinedMatrix = firstMatrix;

    for (let idx = 1; idx < this.agreedQ.length; idx++) {
      const nextMatrix = this.vssNodes.get(this.agreedQ[idx])!.getSharedOutput()!.commitmentMatrix;
      combinedMatrix = addCommitmentMatrices(combinedMatrix, nextMatrix);
    }

    // 3. Domain public key: Q_d = sum_{d in Q} C_{d,00} = combinedMatrix[0][0]
    const domainPublicKeyHex = combinedMatrix[0][0];

    // 4. DLog commitments (paper sec 5.3) for share verification: C_k = combinedMatrix[k][0] for k in 0..t
    const commitments: string[] = [];
    for (let k = 0; k <= this.params.t; k++) {
      commitments.push(combinedMatrix[k][0]);
    }

    this.isFinalized = true;
    this.finalOutput = {
      nodeIndex: this.config.nodeIndex,
      nodeId: this.config.nodeId,
      domain: this.config.domain,
      share: s_i,
      domainPublicKeyHex,
      commitments,
      fullCommitmentMatrix: combinedMatrix,
      Q: [...this.agreedQ],
    };
  }

  isComplete(): boolean {
    return this.isFinalized;
  }

  getOutput(): HybridDkgOutput | null {
    return this.finalOutput;
  }

  getAgreedQ(): number[] | null {
    return this.agreedQ ? [...this.agreedQ] : null;
  }

  getCurrentLeader(): number {
    return this.currentLeader;
  }

  getVssNode(dealerIndex: number): HybridVssNode | undefined {
    return this.vssNodes.get(dealerIndex);
  }
}
