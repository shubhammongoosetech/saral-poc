/**
 * dkgRelay.ts
 *
 * Distributed Key Generation IPC Relay Coordinator for Containerized Nodes.
 *
 * Architecture & Security Invariants:
 *   - The coordinator acts purely as an asynchronous message switch (relay).
 *   - The coordinator never samples polynomials, computes secret shares, or handles private keys.
 *   - Node shares are generated and stored exclusively within each node container's /vault.
 *   - The coordinator returns only public commitments and domain public keys.
 *   - Cryptographic adherence: Kate, Huang, Goldberg (2012).
 */

import { DomainType } from '../thresholdEcdsa';
import { AuthenticatedParticipantClient } from '../../participant/participantClient';
import { deriveHybridParams } from './hybridDkg';
import type { DkgResult } from './types';

export interface DkgRelayOptions {
  t?: number;
  f?: number;
  userId?: string;
  maxRounds?: number;
  pollIntervalMs?: number;
}

export async function runContainerDkgRelay(
  clients: AuthenticatedParticipantClient[],
  domain: DomainType,
  sessionId: string,
  options: DkgRelayOptions = {}
): Promise<DkgResult> {
  const n = clients.length;
  if (n < 3) {
    throw new Error(`[DKG Relay] Domain ${domain} requires at least 3 nodes (got ${n})`);
  }

  const params = deriveHybridParams(n, options.t, options.f);
  const maxRounds = options.maxRounds ?? 120;
  const pollIntervalMs = options.pollIntervalMs ?? 15;

  // 1. DKG_START across all participant node daemons
  const peerPublicKeys: Record<number, string> = {};
  for (const client of clients) {
    peerPublicKeys[client.nodeIndex] = client.identityPublicKeyHex;
  }

  const allNodeIds = clients.map((c) => c.id);

  await Promise.all(
    clients.map((c) =>
      c.dkgStart(sessionId, {
        n,
        t: params.t,
        f: params.f,
        allNodeIds,
        peerPublicKeys,
      })
    )
  );

  // 2. Relay message exchange loop until completion
  let round = 0;
  const completedNodes = new Set<number>();

  while (round < maxRounds && completedNodes.size < n) {
    round++;
    let messagesRoutedThisRound = 0;

    // Poll outgoing messages from all nodes
    for (const sender of clients) {
      const pollRes = await sender.dkgPoll(sessionId);
      if (pollRes.isComplete) {
        completedNodes.add(sender.nodeIndex);
      }

      if (pollRes.messages.length > 0) {
        messagesRoutedThisRound += pollRes.messages.length;

        for (const outMsg of pollRes.messages) {
          if (outMsg.targetIndex === 'broadcast') {
            // Deliver to all other peers
            await Promise.all(
              clients
                .filter((recipient) => recipient.nodeIndex !== sender.nodeIndex)
                .map((recipient) => recipient.dkgDeliver(sessionId, outMsg.message))
            );
          } else {
            const targetIdx = outMsg.targetIndex;
            const recipient = clients.find((c) => c.nodeIndex === targetIdx);
            if (recipient) {
              await recipient.dkgDeliver(sessionId, outMsg.message);
            }
          }
        }
      }
    }

    if (completedNodes.size >= n) {
      break;
    }

    if (messagesRoutedThisRound === 0) {
      await new Promise((r) => setTimeout(r, pollIntervalMs));
    }
  }

  if (completedNodes.size < n - params.f) {
    throw new Error(
      `[DKG Relay] Timeout: only ${completedNodes.size}/${n} nodes completed DKG in session ${sessionId} (required >= ${n - params.f})`
    );
  }

  // 3. Finalize all nodes: nodes save shares in /vault and emit public metadata
  const finalizeResults = await Promise.all(
    clients.map((c) => c.dkgFinalize(sessionId, options.userId))
  );

  // 4. Verify public agreement across all completed nodes
  const expectedDomainPubkey = finalizeResults[0].domainPublicKeyHex;
  for (let i = 1; i < finalizeResults.length; i++) {
    if (finalizeResults[i].domainPublicKeyHex !== expectedDomainPubkey) {
      throw new Error(
        `[DKG Relay] Cryptographic agreement breach: node ${clients[i].id} output pubkey ${finalizeResults[i].domainPublicKeyHex} !== ${expectedDomainPubkey}`
      );
    }
  }

  const allCommitments = new Map<string, string[]>();
  for (let i = 0; i < clients.length; i++) {
    allCommitments.set(clients[i].id, finalizeResults[i].commitments);
  }

  return {
    domain,
    domainPublicKeyHex: expectedDomainPubkey,
    nodeShares: new Map(), // Secure invariant: coordinator possesses ZERO node shares!
    allCommitments,
    threshold: params.threshold,
    totalNodes: n,
  };
}
