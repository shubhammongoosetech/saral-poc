/**
 * activityController.ts
 *
 * Tamper-Evident Access & Security Audit Log Controller.
 */

import { Request, Response, NextFunction } from 'express';
import { prisma } from '../config/db';

interface AccessLogDto {
  id: string;
  attemptedAt: string;
  allowed: boolean;
  reason: string;
  lat: number | null;
  lng: number | null;
}

interface SecurityLogDto {
  id: string;
  eventType: string;
  severity: string;
  details: string | null;
  entryHash: string | null;
  previousHash: string | null;
  createdAt: string;
}

type MergedActivityEntry =
  | { kind: 'access'; sortMs: number; data: AccessLogDto }
  | { kind: 'security'; sortMs: number; data: SecurityLogDto };

export async function handleGetActivityLogs(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;

    const rawPage = Number(req.query.page);
    const rawLimit = Number(req.query.limit);
    const limit =
      Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(Math.floor(rawLimit), 100) : 10;
    const requestedPage =
      Number.isFinite(rawPage) && rawPage > 0 ? Math.floor(rawPage) : 1;

    const [accessTotal, securityTotal] = await Promise.all([
      prisma.accessLog.count({ where: { userId } }),
      prisma.securityEventLog.count({ where: { userId } }),
    ]);

    const total = accessTotal + securityTotal;
    const totalPages = Math.max(1, Math.ceil(total / limit));
    const page = Math.min(requestedPage, totalPages);
    const skip = (page - 1) * limit;
    const takeWindow = skip + limit;

    const [accessRows, securityRows] =
      total === 0
        ? [[], []]
        : await Promise.all([
            prisma.accessLog.findMany({
              where: { userId },
              orderBy: { attemptedAt: 'desc' },
              take: takeWindow,
            }),
            prisma.securityEventLog.findMany({
              where: { userId },
              orderBy: { createdAt: 'desc' },
              take: takeWindow,
            }),
          ]);

    const merged: MergedActivityEntry[] = [
      ...accessRows.map((l): MergedActivityEntry => ({
        kind: 'access',
        sortMs: l.attemptedAt.getTime(),
        data: {
          id: l.id,
          attemptedAt: l.attemptedAt.toISOString(),
          allowed: l.allowed,
          reason: l.reason,
          lat: l.lat,
          lng: l.lng,
        },
      })),
      ...securityRows.map((s): MergedActivityEntry => ({
        kind: 'security',
        sortMs: s.createdAt.getTime(),
        data: {
          id: s.id,
          eventType: s.eventType,
          severity: s.severity,
          details: s.details,
          entryHash: s.entryHash,
          previousHash: s.previousHash,
          createdAt: s.createdAt.toISOString(),
        },
      })),
    ].sort((a, b) => b.sortMs - a.sortMs || a.data.id.localeCompare(b.data.id));

    const pageSlice = merged.slice(skip, skip + limit);

    res.json({
      items: pageSlice.map((entry) => ({
        kind: entry.kind,
        timestamp: new Date(entry.sortMs).toISOString(),
        ...entry.data,
      })),
      accessLogs: pageSlice
        .filter((e): e is { kind: 'access'; sortMs: number; data: AccessLogDto } => e.kind === 'access')
        .map((e) => e.data),
      securityLogs: pageSlice
        .filter((e): e is { kind: 'security'; sortMs: number; data: SecurityLogDto } => e.kind === 'security')
        .map((e) => e.data),
      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1,
      },
    });
  } catch (err) {
    next(err);
  }
}

