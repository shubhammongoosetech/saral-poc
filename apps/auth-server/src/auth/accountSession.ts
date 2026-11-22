import { KeyManager, TokenClaims } from './token';
import { prisma } from '../database/prisma';

const keyManager = KeyManager.getInstance();

export class InvalidAccountSession extends Error {
  constructor() {
    super('Invalid account session');
  }
}

export async function createAccountSession(userId: string, mfaVerified: boolean, replacedSessionId?: string): Promise<string> {
  const token = keyManager.issueAccountToken(userId, mfaVerified);
  const claims = keyManager.verifyAccountToken(token);
  const data = {
    userId,
    tokenJti: claims.nonce!,
    mfaVerified,
    expiresAt: new Date(claims.exp * 1000),
  };

  if (!replacedSessionId) {
    await prisma.authSession.create({ data });
    return token;
  }

  await prisma.$transaction(async (tx) => {
    const previousSession = await tx.authSession.updateMany({
      where: { userId, tokenJti: replacedSessionId, revoked: false, expiresAt: { gt: new Date() } },
      data: { revoked: true },
    });
    if (previousSession.count !== 1) throw new InvalidAccountSession();
    await tx.authSession.create({ data });
  });
  return token;
}

export async function validateAccountSession(token: string): Promise<TokenClaims> {
  let claims: TokenClaims;
  try {
    claims = keyManager.verifyAccountToken(token);
  } catch {
    throw new InvalidAccountSession();
  }
  const session = await prisma.authSession.findUnique({ where: { tokenJti: claims.nonce! } });
  if (!session || session.revoked || session.userId !== claims.sub ||
      session.mfaVerified !== claims.mfaVerified || session.expiresAt.getTime() <= Date.now()) {
    throw new InvalidAccountSession();
  }
  return claims;
}

export async function revokeAccountSession(userId: string, sessionId: string): Promise<void> {
  await prisma.authSession.updateMany({
    where: { userId, tokenJti: sessionId },
    data: { revoked: true },
  });
}
