/**
 * hybridVss.ts
 *
 * Asynchronous Verifiable Secret Sharing (HybridVSS) Node State Machine.
 *
 * Reference:
 *   "Distributed Key Generation in the Wild" (Kate, Huang, Goldberg), Section 3.1 & Figure 1.
 *
 * Implements:
 *   - Pure state machine: handle(msg) -> OutgoingMessage[]
 *   - Dealer: samples bivariate phi(x,y), sends row a_j(y) to P_j
 *   - Echo broadcast on valid send: echo(C, a_i(j)) to all P_j
 *   - Ready amplification: on ceil((n+t+1)/2) echoes or t+1 readies, interpolate a_i and send ready
 *   - Completion quorum: on n - t - f readies, output shared(C, s_i = a_i(0))
 *   - Crash recovery & help: bounded by d(kappa) per-peer and (t+1)*d(kappa) global
 *   - Deduplication and fail-closed message validation
 */

import crypto from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  CURVE_ORDER,
  modN,
  scalarToHex,
  hexToScalar,
} from '../secp256k1Math';
import {
  sampleSymmetricBivariatePoly,
  deriveRowPolynomial,
  evaluateUnivariate,
  interpolatePolynomial,
  zeroizeBigIntArray,
  zeroizeBigIntMatrix,
  SymmetricBivariatePoly,
} from './bivariatePolynomial';
import {
  computeCommitmentMatrix,
  computeMatrixHash,
  validateCommitmentMatrix,
  verifyPoly,
  verifyPoint,
  verifyReconstructShare,
} from './commitments';
import type {
  NodeConfig,
  AnyProtocolMessage,
  OutgoingMessage,
  VssSendMsg,
  VssEchoMsg,
  VssReadyMsg,
  VssHelpMsg,
  VssHelpReplyMsg,
  VssReconstructShareMsg,
  HybridVssSharedOutput,
} from './types';

export class HybridVssNode {
  readonly config: NodeConfig;
  readonly dealerIndex: number;
  readonly n: number;
  readonly t: number;
  readonly f: number;
  readonly echoQuorum: number;                // ceil((n + t + 1) / 2)
  readonly readyInterpolateThreshold: number; // t + 1
  readonly readyCompleteThreshold: number;    // n - t - f
  readonly helpLimitD: number;                // d(kappa)

  // Pure outbox B recording all messages sent by this node
  private outbox: AnyProtocolMessage[] = [];

  // Rate-limiting help counters (Figure 1)
  private cnt_l: Map<number, number> = new Map(); // peer -> count
  private totalCnt: number = 0;                  // global count

  // Deduplication cache: key = `${type}:${dealer}:${matrixHash}:${fromIndex}`
  private seenMessages: Set<string> = new Set();

  // Metrics: dropped messages counter
  public droppedMessagesCount: number = 0;

  // Session state
  private commitmentMatrix: string[][] | null = null;
  private matrixHash: string | null = null;
  private aCoeffs: bigint[] | null = null;      // a_i(y) coeffs

  private sendReceived: boolean = false;
  private echoSent: boolean = false;
  private readySent: boolean = false;

  // Counters and verified point store A_C per matrixHash
  // matrixHash -> Map<senderIndex, alpha>
  private pointsPerMatrix: Map<string, Map<number, bigint>> = new Map();
  // matrixHash -> echoCount
  private echoCountPerMatrix: Map<string, number> = new Map();
  // matrixHash -> Map<senderIndex, VssReadyMsg>
  private readiesPerMatrix: Map<string, Map<number, VssReadyMsg>> = new Map();

  // Completed shared output
  private sharedOutput: HybridVssSharedOutput | null = null;

  // Dealer secret polynomial (only populated if this node is dealer)
  private dealerPoly: SymmetricBivariatePoly | null = null;

  constructor(config: NodeConfig, dealerIndex: number) {
    this.config = config;
    this.dealerIndex = dealerIndex;
    this.n = config.n;
    this.t = config.t;
    this.f = config.f;
    this.echoQuorum = Math.ceil((this.n + this.t + 1) / 2);
    this.readyInterpolateThreshold = this.t + 1;
    this.readyCompleteThreshold = this.n - this.t - this.f;
    this.helpLimitD = config.helpLimitD ?? 3;
  }

  /**
   * Initializes dealing if this node is the designated dealer.
   * Generates symmetric bivariate poly, commitment matrix C, and Send messages for all nodes.
   */
  startDealing(secret?: bigint): OutgoingMessage[] {
    if (this.dealerIndex !== this.config.nodeIndex) {
      throw new Error(`[HybridVSS] Node ${this.config.nodeIndex} is not designated dealer ${this.dealerIndex}`);
    }

    this.dealerPoly = sampleSymmetricBivariatePoly(this.t, secret, this.config.rng);
    const C = computeCommitmentMatrix(this.dealerPoly);
    const mHash = computeMatrixHash(C);
    this.commitmentMatrix = C;
    this.matrixHash = mHash;

    const outgoing: OutgoingMessage[] = [];

    for (let j = 1; j <= this.n; j++) {
      const rowCoeffs = deriveRowPolynomial(this.dealerPoly, j);
      const rowCoeffsHex = rowCoeffs.map(scalarToHex);

      const sendMsg: VssSendMsg = {
        type: 'VSS_SEND',
        sessionId: this.config.sessionId,
        domain: this.config.domain,
        dealerIndex: this.dealerIndex,
        targetIndex: j,
        commitmentMatrix: C,
        aCoeffs: rowCoeffsHex,
      };

      this.outbox.push(sendMsg);
      outgoing.push({ targetIndex: j, message: sendMsg });
    }

    return outgoing;
  }

  /**
   * Primary entrypoint: handles an incoming protocol message.
   * Returns newly emitted outgoing messages.
   * Fails closed: drops invalid messages silently and increments droppedMessagesCount.
   */
  handle(msg: AnyProtocolMessage): OutgoingMessage[] {
    if (msg.sessionId !== this.config.sessionId || msg.domain !== this.config.domain) {
      this.droppedMessagesCount++;
      return [];
    }

    switch (msg.type) {
      case 'VSS_SEND':
        return this.handleSend(msg);
      case 'VSS_ECHO':
        return this.handleEcho(msg);
      case 'VSS_READY':
        return this.handleReady(msg);
      case 'VSS_HELP':
        return this.handleHelp(msg);
      case 'VSS_HELP_REPLY':
        return this.handleHelpReply(msg);
      default:
        return [];
    }
  }

  /**
   * Fig. 1: On send(C, a_j) from dealer (first time)
   * If verify-poly(C, i, a): send echo(C, a(j)) to all P_j
   */
  private handleSend(msg: VssSendMsg): OutgoingMessage[] {
    if (msg.dealerIndex !== this.dealerIndex) {
      this.droppedMessagesCount++;
      return [];
    }
    if (msg.targetIndex !== this.config.nodeIndex) {
      this.droppedMessagesCount++;
      return [];
    }

    const mHash = computeMatrixHash(msg.commitmentMatrix);
    const dedupKey = `VSS_SEND:${msg.dealerIndex}:${mHash}:${msg.dealerIndex}`;
    if (this.seenMessages.has(dedupKey)) {
      return [];
    }
    this.seenMessages.add(dedupKey);

    // Validate commitment matrix
    if (!validateCommitmentMatrix(msg.commitmentMatrix, this.t)) {
      this.droppedMessagesCount++;
      return [];
    }

    const coeffs = msg.aCoeffs.map(hexToScalar);
    // verify-poly(C, i, a)
    if (!verifyPoly(msg.commitmentMatrix, this.config.nodeIndex, coeffs)) {
      this.droppedMessagesCount++;
      return [];
    }

    // Accept first valid SEND
    if (!this.sendReceived) {
      this.sendReceived = true;
      this.commitmentMatrix = msg.commitmentMatrix;
      this.matrixHash = mHash;
      this.aCoeffs = coeffs;
    }

    // Broadcast echo to all peers if not sent yet
    if (!this.echoSent) {
      this.echoSent = true;
      return this.broadcastEchoes(msg.commitmentMatrix, mHash, coeffs);
    }

    return [];
  }

  /**
   * Broadcasts echo(C, a_i(j)) to all nodes j in 1..n.
   */
  private broadcastEchoes(C: string[][], mHash: string, coeffs: bigint[]): OutgoingMessage[] {
    const outgoing: OutgoingMessage[] = [];

    for (let j = 1; j <= this.n; j++) {
      const alpha_j = evaluateUnivariate(coeffs, BigInt(j));
      const echoMsg: VssEchoMsg = {
        type: 'VSS_ECHO',
        sessionId: this.config.sessionId,
        domain: this.config.domain,
        dealerIndex: this.dealerIndex,
        fromIndex: this.config.nodeIndex,
        targetIndex: j,
        commitmentMatrix: C,
        alpha: scalarToHex(alpha_j),
      };

      this.outbox.push(echoMsg);
      outgoing.push({ targetIndex: j, message: echoMsg });
    }

    return outgoing;
  }

  /**
   * Fig. 1: On echo(C, alpha) from P_m (first time)
   * If verify-point(C, i, m, alpha): A_C += (m, alpha), e_C++
   * If e_C == ceil((n+t+1)/2) and r_C < t+1: interpolate a and send ready(C, a(j)) to all P_j
   */
  private handleEcho(msg: VssEchoMsg): OutgoingMessage[] {
    if (msg.dealerIndex !== this.dealerIndex) {
      this.droppedMessagesCount++;
      return [];
    }
    if (msg.targetIndex !== this.config.nodeIndex) {
      this.droppedMessagesCount++;
      return [];
    }
    if (msg.fromIndex < 1 || msg.fromIndex > this.n) {
      this.droppedMessagesCount++;
      return [];
    }

    const mHash = computeMatrixHash(msg.commitmentMatrix);
    const dedupKey = `VSS_ECHO:${msg.dealerIndex}:${mHash}:${msg.fromIndex}`;
    if (this.seenMessages.has(dedupKey)) {
      return [];
    }
    this.seenMessages.add(dedupKey);

    const alpha = hexToScalar(msg.alpha);
    // verify-point(C, i, m, alpha) where i = recipient (myNodeIndex), m = sender (fromIndex)
    if (!verifyPoint(msg.commitmentMatrix, this.config.nodeIndex, msg.fromIndex, alpha)) {
      this.droppedMessagesCount++;
      return [];
    }

    // Add to A_C
    let points = this.pointsPerMatrix.get(mHash);
    if (!points) {
      points = new Map();
      this.pointsPerMatrix.set(mHash, points);
    }
    points.set(msg.fromIndex, alpha);

    const echoCount = (this.echoCountPerMatrix.get(mHash) ?? 0) + 1;
    this.echoCountPerMatrix.set(mHash, echoCount);

    const readies = this.readiesPerMatrix.get(mHash);
    const readyCount = readies ? readies.size : 0;

    // Check ready broadcast condition:
    // If e_C == ceil((n+t+1)/2) and r_C < t+1
    if (!this.readySent && echoCount >= this.echoQuorum && readyCount < this.readyInterpolateThreshold) {
      return this.sendReadyAmplification(msg.commitmentMatrix, mHash, points);
    }

    return [];
  }

  /**
   * Fig. 1: On ready(C, beta) from P_m (first time)
   * If verify-point(C, i, m, beta): A_C += (m, beta), r_C++
   * If r_C == t+1 and e_C < ceil((n+t+1)/2): interpolate a and send ready(C, a(j)) to all P_j
   * If r_C == n - t - f: output shared(C, s_i = a(0))
   */
  private handleReady(msg: VssReadyMsg): OutgoingMessage[] {
    if (msg.dealerIndex !== this.dealerIndex) {
      this.droppedMessagesCount++;
      return [];
    }
    if (msg.targetIndex !== this.config.nodeIndex) {
      this.droppedMessagesCount++;
      return [];
    }
    if (msg.fromIndex < 1 || msg.fromIndex > this.n) {
      this.droppedMessagesCount++;
      return [];
    }

    const mHash = computeMatrixHash(msg.commitmentMatrix);
    const dedupKey = `VSS_READY:${msg.dealerIndex}:${mHash}:${msg.fromIndex}`;
    if (this.seenMessages.has(dedupKey)) {
      return [];
    }
    this.seenMessages.add(dedupKey);

    const beta = hexToScalar(msg.beta);
    // verify-point(C, i, m, beta)
    if (!verifyPoint(msg.commitmentMatrix, this.config.nodeIndex, msg.fromIndex, beta)) {
      this.droppedMessagesCount++;
      return [];
    }

    // Add to A_C
    let points = this.pointsPerMatrix.get(mHash);
    if (!points) {
      points = new Map();
      this.pointsPerMatrix.set(mHash, points);
    }
    points.set(msg.fromIndex, beta);

    let readies = this.readiesPerMatrix.get(mHash);
    if (!readies) {
      readies = new Map();
      this.readiesPerMatrix.set(mHash, readies);
    }
    readies.set(msg.fromIndex, msg);

    const readyCount = readies.size;
    const echoCount = this.echoCountPerMatrix.get(mHash) ?? 0;
    const outgoing: OutgoingMessage[] = [];

    // Amplification: if r_C == t+1 and e_C < ceil((n+t+1)/2)
    if (!this.readySent && readyCount >= this.readyInterpolateThreshold && echoCount < this.echoQuorum) {
      const ampMessages = this.sendReadyAmplification(msg.commitmentMatrix, mHash, points);
      outgoing.push(...ampMessages);
    }

    // Completion quorum: r_C == n - t - f
    if (readyCount >= this.readyCompleteThreshold && !this.sharedOutput) {
      // Ensure we have a(y)
      if (!this.aCoeffs && points.size >= this.t + 1) {
        this.interpolateAndSetPolynomial(points);
      }

      if (this.aCoeffs) {
        const s_i = evaluateUnivariate(this.aCoeffs, 0n);
        if (s_i === 0n || s_i >= CURVE_ORDER) {
          // Reject invalid zero share
          this.droppedMessagesCount++;
          return outgoing;
        }

        const readyProofs = Array.from(readies.values()).slice(0, this.readyCompleteThreshold);
        this.sharedOutput = {
          dealerIndex: this.dealerIndex,
          share: s_i,
          commitmentMatrix: msg.commitmentMatrix,
          matrixHash: mHash,
          readyProofs,
        };

        // Wipe dealer secret poly if present
        if (this.dealerPoly) {
          zeroizeBigIntMatrix(this.dealerPoly.coeffs);
          this.dealerPoly = null;
        }
      }
    }

    return outgoing;
  }

  /**
   * Interpolates a_i(y) and broadcasts ready(C, a_i(j)) to all nodes j in 1..n.
   */
  private sendReadyAmplification(
    C: string[][],
    mHash: string,
    points: Map<number, bigint>
  ): OutgoingMessage[] {
    if (this.readySent) return [];

    if (!this.aCoeffs && points.size >= this.t + 1) {
      this.interpolateAndSetPolynomial(points);
    }

    if (!this.aCoeffs) {
      return [];
    }

    this.readySent = true;
    this.commitmentMatrix = C;
    this.matrixHash = mHash;

    const outgoing: OutgoingMessage[] = [];

    for (let j = 1; j <= this.n; j++) {
      const beta_j = evaluateUnivariate(this.aCoeffs, BigInt(j));
      let signature: string | undefined;

      if (this.config.signerPrivateKeyHex) {
        try {
          const payload = `READY:${this.config.sessionId}:${this.config.domain}:${this.dealerIndex}:${mHash}:${j}:${scalarToHex(beta_j)}`;
          const hash = crypto.createHash('sha256').update(payload).digest();
          const cleanPriv = this.config.signerPrivateKeyHex.startsWith('0x')
            ? this.config.signerPrivateKeyHex.slice(2)
            : this.config.signerPrivateKeyHex;
          const sig = secp256k1.sign(hash, cleanPriv);
          signature = sig.toCompactHex();
        } catch {}
      }

      const readyMsg: VssReadyMsg = {
        type: 'VSS_READY',
        sessionId: this.config.sessionId,
        domain: this.config.domain,
        dealerIndex: this.dealerIndex,
        fromIndex: this.config.nodeIndex,
        targetIndex: j,
        commitmentMatrix: C,
        beta: scalarToHex(beta_j),
        signature,
      };

      this.outbox.push(readyMsg);
      outgoing.push({ targetIndex: j, message: readyMsg });
    }

    return outgoing;
  }

  /**
   * Interpolates the degree-t polynomial a_i(y) from at least t+1 verified points in A_C.
   */
  private interpolateAndSetPolynomial(points: Map<number, bigint>): void {
    if (points.size < this.t + 1) return;

    const ptArray: { x: bigint; y: bigint }[] = [];
    let count = 0;
    for (const [idx, val] of points) {
      ptArray.push({ x: BigInt(idx), y: val });
      count++;
      if (count === this.t + 1) break; // t+1 points are sufficient for degree-t
    }

    this.aCoeffs = interpolatePolynomial(ptArray);
  }

  /**
   * Fig. 1 Crash recovery: Handles incoming help request from peer requesterIndex.
   * Answers with outbox messages destined for requester or broadcast, strictly limited by:
   *   cnt_l <= d(kappa)
   *   cnt <= (t + 1) * d(kappa)
   */
  private handleHelp(msg: VssHelpMsg): OutgoingMessage[] {
    const peer = msg.requesterIndex;
    if (peer < 1 || peer > this.n || peer === this.config.nodeIndex) {
      this.droppedMessagesCount++;
      return [];
    }

    const currentPeerCount = this.cnt_l.get(peer) ?? 0;
    const maxGlobal = (this.t + 1) * this.helpLimitD;

    if (currentPeerCount >= this.helpLimitD || this.totalCnt >= maxGlobal) {
      // Rate limit exceeded: silently drop
      this.droppedMessagesCount++;
      return [];
    }

    this.cnt_l.set(peer, currentPeerCount + 1);
    this.totalCnt++;

    // Filter relevant outbox messages for requester
    const relevant = this.outbox.filter((m) => {
      if ('targetIndex' in m && (m.targetIndex === peer || m.targetIndex === this.config.nodeIndex)) {
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
   * Handles incoming HelpReply from helper peer.
   * Replays included messages into state machine.
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
   * Emits a help request message after recovery/restart.
   */
  createHelpRequest(): OutgoingMessage[] {
    const helpMsg: VssHelpMsg = {
      type: 'VSS_HELP',
      sessionId: this.config.sessionId,
      domain: this.config.domain,
      requesterIndex: this.config.nodeIndex,
    };

    const outgoing: OutgoingMessage[] = [];
    for (let j = 1; j <= this.n; j++) {
      if (j !== this.config.nodeIndex) {
        outgoing.push({ targetIndex: j, message: helpMsg });
      }
    }
    return outgoing;
  }

  /**
   * Rec (Reconstruction, Fig. 1):
   * Reconstructs secret scalar s = phi(0,0) from at least t+1 verified shares.
   */
  static reconstructSecretFromShares(
    shares: { index: number; sigma: bigint }[],
    commitmentMatrix: string[][]
  ): bigint {
    const t = commitmentMatrix.length - 1;
    const validShares = shares.filter((s) =>
      verifyReconstructShare(commitmentMatrix, s.index, s.sigma)
    );

    if (validShares.length < t + 1) {
      throw new Error(
        `[HybridVSS] Cannot reconstruct secret: need ${t + 1} valid shares, got ${validShares.length}`
      );
    }

    const points = validShares.slice(0, t + 1).map((s) => ({
      x: BigInt(s.index),
      y: s.sigma,
    }));

    // Constant term of polynomial is evaluated at 0
    return interpolatePolynomial(points)[0];
  }

  isComplete(): boolean {
    return this.sharedOutput !== null;
  }

  getSharedOutput(): HybridVssSharedOutput | null {
    return this.sharedOutput;
  }

  getOutbox(): AnyProtocolMessage[] {
    return [...this.outbox];
  }

  cleanup(): void {
    if (this.aCoeffs) {
      zeroizeBigIntArray(this.aCoeffs);
      this.aCoeffs = null;
    }
    if (this.dealerPoly) {
      zeroizeBigIntMatrix(this.dealerPoly.coeffs);
      this.dealerPoly = null;
    }
  }
}
