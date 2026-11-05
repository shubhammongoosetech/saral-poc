/**
 * activityController.ts
 *
 * Tamper-Evident Access & Security Audit Log Controller.
 */

import { Request, Response, NextFunction } from 'express';
import { prisma } from '../config/db';

export async function handleGetActivityLogs(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;

    const [accessLogs, securityLogs] = await Promise.all([
      prisma.accessLog.findMany({
        where: { userId },
        orderBy: { attemptedAt: 'desc' },
        take: 50,
      }),
      prisma.securityEventLog.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        take: 50,
      }),
    ]);

    res.json({
      accessLogs: accessLogs.map((l) => ({
        id: l.id,
        attemptedAt: l.attemptedAt.toISOString(),
        allowed: l.allowed,
        reason: l.reason,
        lat: l.lat,
        lng: l.lng,
      })),
      securityLogs: securityLogs.map((s) => ({
        id: s.id,
        eventType: s.eventType,
        severity: s.severity,
        details: s.details,
        entryHash: s.entryHash,
        previousHash: s.previousHash,
        createdAt: s.createdAt.toISOString(),
      })),
    });
  } catch (err) {
    next(err);
  }
}

