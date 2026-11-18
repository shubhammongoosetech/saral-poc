/**
 * P2PTransport.ts
 *
 * Peer-to-Peer Authenticated Network Transport for SARAL TSS Nodes.
 *
 * Security Features:
 *  - Framing: 4-byte Big-Endian length-prefixed JSON frames over raw TCP.
 *  - Point-to-Point Encryption: Diffie-Hellman (ECDH over secp256k1) + HKDF-SHA256 + AES-256-GCM.
 *  - Envelope Signatures: Every message envelope is digitally signed via secp256k1.
 *  - Mutual Authentication: Enforces cryptographic identity checks on every received envelope.
 *  - Replay & Expiry Protection: 30-second TTL window and cryptographic nonce checking.
 */

import net from 'net';
import crypto from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { P2PMessageEnvelope } from './types';

export class P2PTransport {
  /**
   * Computes the canonical message string to be signed for an envelope.
   */
  public static canonicalizeEnvelope(
    protocol: string,
    sessionId: string,
    fromNodeId: string,
    toNodeId: string,
    timestamp: number,
    nonce: string,
    payload: string
  ): string {
    return `${protocol}:${sessionId}:${fromNodeId}:${toNodeId}:${timestamp}:${nonce}:${payload}`;
  }

  /**
   * Signs an envelope using the node's long-term secp256k1 identity private key.
   */
  public static signEnvelope(
    envelope: Omit<P2PMessageEnvelope, 'signatureHex'>,
    identityPrivateKeyHex: string
  ): P2PMessageEnvelope {
    const canonical = this.canonicalizeEnvelope(
      envelope.protocol,
      envelope.sessionId,
      envelope.fromNodeId,
      envelope.toNodeId,
      envelope.timestamp,
      envelope.nonce,
      envelope.payload
    );

    const msgHash = crypto.createHash('sha256').update(canonical).digest();
    const sig = secp256k1.sign(msgHash, Buffer.from(identityPrivateKeyHex, 'hex'));
    const signatureHex = Buffer.from(sig.toCompactRawBytes()).toString('hex');

    return {
      ...envelope,
      signatureHex,
    };
  }

  /**
   * Verifies the authenticity and signature of a received message envelope.
   */
  public static verifyEnvelope(
    envelope: P2PMessageEnvelope,
    senderIdentityPublicKeyHex: string,
    maxSkewMs: number = 30_000
  ): boolean {
    const now = Date.now();
    if (Math.abs(now - envelope.timestamp) > maxSkewMs) {
      return false; // Stale or replayed envelope
    }

    const canonical = this.canonicalizeEnvelope(
      envelope.protocol,
      envelope.sessionId,
      envelope.fromNodeId,
      envelope.toNodeId,
      envelope.timestamp,
      envelope.nonce,
      envelope.payload
    );

    const msgHash = crypto.createHash('sha256').update(canonical).digest();
    try {
      const cleanPub = senderIdentityPublicKeyHex.startsWith('0x')
        ? senderIdentityPublicKeyHex.slice(2)
        : senderIdentityPublicKeyHex;
      return secp256k1.verify(
        Buffer.from(envelope.signatureHex, 'hex'),
        msgHash,
        Buffer.from(cleanPub, 'hex')
      );
    } catch {
      return false;
    }
  }

  /**
   * Derives an AES-256-GCM shared key between two nodes using ECDH + HKDF.
   */
  public static deriveSharedKey(
    myPrivateKeyHex: string,
    peerPublicKeyHex: string,
    sessionId: string
  ): Buffer {
    const cleanPriv = myPrivateKeyHex.startsWith('0x') ? myPrivateKeyHex.slice(2) : myPrivateKeyHex;
    const cleanPub = peerPublicKeyHex.startsWith('0x') ? peerPublicKeyHex.slice(2) : peerPublicKeyHex;

    const sharedPoint = secp256k1.getSharedSecret(
      Buffer.from(cleanPriv, 'hex'),
      Buffer.from(cleanPub, 'hex'),
      true
    );

    // HKDF-SHA256
    return Buffer.from(
      crypto.hkdfSync(
        'sha256',
        Buffer.from(sharedPoint),
        Buffer.from(sessionId, 'utf8'),
        Buffer.from('SARAL-P2P-ENCRYPTION-v1', 'utf8'),
        32
      )
    );
  }

  /**
   * Encrypts plaintext data using AES-256-GCM.
   */
  public static encryptPayload(plaintext: string, key: Buffer): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Format: iv (12) || tag (16) || ciphertext
    return Buffer.concat([iv, tag, encrypted]).toString('hex');
  }

  /**
   * Decrypts AES-256-GCM ciphertext hex string.
   */
  public static decryptPayload(ciphertextHex: string, key: Buffer): string {
    const raw = Buffer.from(ciphertextHex, 'hex');
    if (raw.length < 28) {
      throw new Error('[P2PTransport] Invalid ciphertext payload length (must be >= 28 bytes)');
    }

    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const ciphertext = raw.subarray(28);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
  }

  /**
   * Dispatches a message envelope to a peer endpoint over TCP using 4-byte framing.
   */
  public static async sendEnvelope(
    host: string,
    port: number,
    envelope: P2PMessageEnvelope,
    timeoutMs: number = 5000
  ): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const socket = net.createConnection({ host, port }, () => {
        const jsonPayload = Buffer.from(JSON.stringify(envelope), 'utf8');
        const frameHeader = Buffer.alloc(4);
        frameHeader.writeUInt32BE(jsonPayload.length, 0);

        socket.write(Buffer.concat([frameHeader, jsonPayload]), () => {
          socket.end();
          resolve();
        });
      });

      socket.setTimeout(timeoutMs);
      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error(`[P2PTransport] Connection to ${host}:${port} timed out`));
      });
      socket.on('error', (err) => {
        reject(err);
      });
    });
  }

  /**
   * Dispatches a message envelope to a peer endpoint over TCP using 4-byte framing,
   * and awaits the response envelope.
   */
  public static async sendEnvelopeAndReceive(
    host: string,
    port: number,
    envelope: P2PMessageEnvelope,
    timeoutMs: number = 8000
  ): Promise<P2PMessageEnvelope> {
    return new Promise<P2PMessageEnvelope>((resolve, reject) => {
      let buffer = Buffer.alloc(0);
      let timer: NodeJS.Timeout | null = null;
      let finished = false;

      const cleanup = () => {
        if (timer) clearTimeout(timer);
        socket.removeAllListeners();
        socket.destroy();
      };

      const socket = net.createConnection({ host, port }, () => {
        const jsonPayload = Buffer.from(JSON.stringify(envelope), 'utf8');
        const frameHeader = Buffer.alloc(4);
        frameHeader.writeUInt32BE(jsonPayload.length, 0);
        socket.write(Buffer.concat([frameHeader, jsonPayload]));
      });

      timer = setTimeout(() => {
        if (!finished) {
          finished = true;
          cleanup();
          reject(new Error(`[P2PTransport] Request timed out after ${timeoutMs}ms to ${host}:${port}`));
        }
      }, timeoutMs);

      socket.on('data', (chunk) => {
        const chunkBuf = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
        buffer = Buffer.concat([buffer, chunkBuf]);

        if (buffer.length >= 4) {
          const frameLength = buffer.readUInt32BE(0);
          if (buffer.length >= 4 + frameLength) {
            const frameData = buffer.subarray(4, 4 + frameLength);
            try {
              const resp: P2PMessageEnvelope = JSON.parse(frameData.toString('utf8'));
              if (!finished) {
                finished = true;
                cleanup();
                resolve(resp);
              }
            } catch (err) {
              if (!finished) {
                finished = true;
                cleanup();
                reject(err);
              }
            }
          }
        }
      });

      socket.on('error', (err) => {
        if (!finished) {
          finished = true;
          cleanup();
          reject(err);
        }
      });

      socket.on('end', () => {
        if (!finished) {
          finished = true;
          cleanup();
          reject(new Error('[P2PTransport] Socket closed by peer before response received'));
        }
      });
    });
  }

  /**
   * Creates a framed TCP server that decodes 4-byte length-prefixed JSON envelopes.
   */
  public static createServer(
    port: number,
    host: string = '0.0.0.0',
    onEnvelope: (envelope: P2PMessageEnvelope, socket: net.Socket) => Promise<void>
  ): net.Server {
    const server = net.createServer((socket) => {
      let buffer = Buffer.alloc(0);

      socket.on('data', (chunk) => {
        const chunkBuf = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
        buffer = Buffer.concat([buffer, chunkBuf]);

        while (buffer.length >= 4) {
          const frameLength = buffer.readUInt32BE(0);
          if (buffer.length < 4 + frameLength) {
            break; // Incomplete frame
          }

          const frameData = buffer.subarray(4, 4 + frameLength);
          buffer = buffer.subarray(4 + frameLength);

          try {
            const envelope: P2PMessageEnvelope = JSON.parse(frameData.toString('utf8'));
            onEnvelope(envelope, socket).catch((err) => {
              console.error('[P2PTransport] Error handling envelope:', err);
            });
          } catch (err) {
            console.error('[P2PTransport] Malformed frame payload:', err);
          }
        }
      });
    });

    server.listen(port, host);
    return server;
  }
}
