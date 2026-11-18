/**
 * dkgValidation.ts
 *
 * Zod validation schemas for DKG and MPC REST API endpoints.
 */

import { z } from 'zod';

export const createDkgSessionSchema = z.object({
  domain: z.enum(['FOUNDATION', 'PUBLIC', 'PRIVATE']),
  n: z.number().int().min(3).max(255),
  t: z.number().int().min(1).optional(),
  f: z.number().int().min(0).optional(),
  timeoutMs: z.number().int().min(5000).max(300000).optional(),
});

export const registerDkgParticipantSchema = z.object({
  id: z.string().min(1).max(255),
  nodeIndex: z.number().int().min(1).max(255),
  domain: z.enum(['FOUNDATION', 'PUBLIC', 'PRIVATE']),
  identityPublicKeyHex: z.string().regex(/^(02|03)[0-9a-fA-F]{64}$/, 'Must be compressed 33-byte secp256k1 public key'),
});

export const submitEncryptedShareSchema = z.object({
  dealerIndex: z.number().int().min(1).max(255),
  targetIndex: z.number().int().min(1).max(255),
  commitmentMatrix: z.array(z.array(z.string())),
  encryptedPayload: z.string().min(1),
  ivHex: z.string().length(24),
  authTagHex: z.string().length(32),
  senderPublicKeyHex: z.string().regex(/^(02|03)[0-9a-fA-F]{64}$/),
  signatureHex: z.string().length(128),
  timestamp: z.number().int().positive(),
});

export const submitProtocolMessageSchema = z.object({
  fromIndex: z.number().int().min(1).max(255),
  targetIndex: z.union([z.number().int().min(1).max(255), z.literal('broadcast')]),
  payload: z.any(),
  senderPublicKeyHex: z.string().regex(/^(02|03)[0-9a-fA-F]{64}$/),
  signatureHex: z.string().length(128),
  timestamp: z.number().int().positive(),
});

export const submitDkgFinalConfirmationSchema = z.object({
  nodeIndex: z.number().int().min(1).max(255),
  domainPublicKeyHex: z.string().min(66).max(130),
  commitments: z.array(z.string().min(66)),
  agreedQ: z.array(z.number().int().min(1)),
});

export const createSigningSessionSchema = z.object({
  unsignedTxSerialized: z.string().min(2),
  chainId: z.union([z.number().int().positive(), z.string().regex(/^\d+$/)]),
  expectedAggregatedPublicKeyHex: z.string().min(66).max(130),
  thresholds: z.object({
    foundation: z.number().int().min(1),
    public: z.number().int().min(1),
    private: z.number().int().min(1),
  }),
  participants: z.array(
    z.object({
      id: z.string().min(1),
      domain: z.enum(['FOUNDATION', 'PUBLIC', 'PRIVATE']),
      nodeIndex: z.number().int().min(1),
      shareIndex: z.number().int().min(1),
      identityPublicKeyHex: z.string().min(66).max(130),
    })
  ).min(3),
  timeoutMs: z.number().int().min(5000).max(300000).optional(),
});
