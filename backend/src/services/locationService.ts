import { prisma } from '../config/db';
import { env } from '../config/env';
import { logSecurityEvent } from './auditLogService';

export interface PolicyCheckResult {
  allowed: boolean;
  reason: string;
  details?: {
    currentTime?: string;
    allowedWindow?: string;
    currentDistanceKm?: number;
    maxRadiusKm?: number;
    anomalyDetected?: boolean;
  };
}

export function calculateDistanceKm(
  lat1: number, lon1: number,
  lat2: number, lon2: number
): number {
  const R = 6371;
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  return Math.round(6371 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)) * 100) / 100;
}

export function getCurrentTimeInTimezone(timezone: string): {
  hour: number; minute: number; timeStr: string;
} {
  try {
    const formatter = new Intl.DateTimeFormat('en-GB', {
      timeZone: timezone || 'Asia/Kolkata',
      hour: '2-digit', minute: '2-digit', hour12: false,
    });
    const parts = formatter.formatToParts(new Date());
    const hour = parseInt(parts.find((p) => p.type === 'hour')?.value || '0', 10);
    const minute = parseInt(parts.find((p) => p.type === 'minute')?.value || '0', 10);
    return { hour, minute, timeStr: `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}` };
  } catch {
    const now = new Date();
    return {
      hour: now.getUTCHours(),
      minute: now.getUTCMinutes(),
      timeStr: `${String(now.getUTCHours()).padStart(2, '0')}:${String(now.getUTCMinutes()).padStart(2, '0')}`,
    };
  }
}

function toMinutes(timeStr: string): number {
  const [h, m] = timeStr.split(':').map((v) => parseInt(v, 10));
  return h * 60 + m;
}

export async function evaluateAccessPolicy(
  userId: string,
  userLoginMethod: 'google' | 'mobile',
  mfaVerified: boolean,
  currentLat?: number,
  currentLng?: number
): Promise<PolicyCheckResult> {
  const logAccess = async (allowed: boolean, reason: string) => {
    try {
      await prisma.accessLog.create({
        data: {
          userId,
          lat: currentLat ?? null,
          lng: currentLng ?? null,
          allowed,
          reason,
        },
      });
    } catch (err) {
      console.error('[AccessLog] Error writing audit log:', err);
    }
  };

  // 1. MFA check
  if (!mfaVerified) {
    const reason = 'MFA verification required before accessing wallet';
    await logAccess(false, reason);
    return { allowed: false, reason };
  }

  // 2. User existence + login-method check
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { loginMethod: true },
  });
  if (!user) {
    const reason = 'User not found';
    await logAccess(false, reason);
    return { allowed: false, reason };
  }
  if (user.loginMethod !== userLoginMethod) {
    const reason = `Login method mismatch: session used ${userLoginMethod}, original was ${user.loginMethod}`;
    await logAccess(false, reason);
    return { allowed: false, reason };
  }

  // 3. Work policy check
  const policy = await prisma.workPolicy.findUnique({ where: { userId } });
  if (!policy) {
    const reason = 'Working policy has not been configured yet';
    await logAccess(false, reason);
    return { allowed: false, reason };
  }

  // 4. Time check
  const timezone = policy.timezone || 'Asia/Kolkata';
  const { hour, minute, timeStr } = getCurrentTimeInTimezone(timezone);
  const currentMins = hour * 60 + minute;
  const startMins = toMinutes(policy.startTime);
  const endMins = toMinutes(policy.endTime);
  const tolerance = env.TIME_TOLERANCE_MINUTES;

  const isTimeAllowed =
    startMins <= endMins
      ? currentMins >= startMins - tolerance && currentMins <= endMins + tolerance
      : currentMins >= startMins - tolerance || currentMins <= endMins + tolerance;

  if (!isTimeAllowed) {
    const reason = `Access outside permitted working hours. Current time is ${timeStr} in ${timezone}, permitted window is ${policy.startTime} - ${policy.endTime}`;
    await logAccess(false, reason);
    return {
      allowed: false,
      reason,
      details: { currentTime: timeStr, allowedWindow: `${policy.startTime} - ${policy.endTime}` },
    };
  }

  // 5. Zero-Trust Location & Geofencing check
  if (currentLat === undefined || currentLng === undefined || isNaN(currentLat) || isNaN(currentLng)) {
    const reason = 'Geographic location coordinates are required for access verification';
    await logAccess(false, reason);
    return { allowed: false, reason };
  }

  if (currentLat < -90 || currentLat > 90 || currentLng < -180 || currentLng > 180) {
    const reason = 'Invalid geographic coordinates provided (out of bounds)';
    await logAccess(false, reason);
    return { allowed: false, reason };
  }

  // Check for impossible travel speed anomalies (Zero-trust telemetry verification)
  try {
    const lastLog = await prisma.accessLog.findFirst({
      where: { userId, allowed: true, lat: { not: null }, lng: { not: null } },
      orderBy: { attemptedAt: 'desc' },
    });

    if (lastLog && lastLog.lat !== null && lastLog.lng !== null) {
      const timeDiffMinutes = (Date.now() - new Date(lastLog.attemptedAt).getTime()) / (1000 * 60);

      // 24-Hour Sliding-Window Velocity Evaluation (Patent: Zero-Trust Telemetry Context Gate)
      // Note: Browser GPS coordinates are client-asserted telemetry, not hardware-attested.
      // Physical plausibility is verified across a 24-hour window (1,440 minutes).
      if (timeDiffMinutes >= 0 && timeDiffMinutes <= 1440) {
        const jumpDistanceKm = calculateDistanceKm(lastLog.lat, lastLog.lng, currentLat, currentLng);
        const effectiveHours = Math.max(timeDiffMinutes / 60, 0.00833); // baseline 30 seconds
        const speedKmH = jumpDistanceKm / effectiveHours;

        // Flag impossible speeds exceeding 1,200 km/h (airline maximum cruise velocity)
        if (speedKmH > 1200 && jumpDistanceKm > 5.0) {
          const reason = `Security anomaly: Impossible velocity detected (${Math.round(speedKmH)} km/h over ${jumpDistanceKm.toFixed(1)} km in ${Math.round(timeDiffMinutes)} minutes). Telemetry spoofing suspected.`;
          await logAccess(false, reason);
          await logSecurityEvent({
            userId,
            eventType: 'LOCATION_VELOCITY_ANOMALY',
            severity: 'SECURITY_ALERT',
            details: { speedKmH: Math.round(speedKmH), jumpDistanceKm, timeDiffMinutes },
          }).catch(() => null);
          return { allowed: false, reason, details: { anomalyDetected: true } };
        }
      }
    }
  } catch {}

  const maxRadius = policy.radiusKm || env.LOCATION_RADIUS_KM;
  const distanceKm = calculateDistanceKm(policy.lat, policy.lng, currentLat, currentLng);

  if (distanceKm > maxRadius) {
    const reason = `Access outside permitted location. Distance is ${distanceKm} km from ${policy.city}, allowed radius is ${maxRadius} km`;
    await logAccess(false, reason);
    return {
      allowed: false,
      reason,
      details: { currentDistanceKm: distanceKm, maxRadiusKm: maxRadius },
    };
  }

  const successReason = `Access granted: within working hours (${timeStr}) and location (${distanceKm} km from ${policy.city})`;
  await logAccess(true, successReason);
  return {
    allowed: true,
    reason: successReason,
    details: {
      currentTime: timeStr,
      allowedWindow: `${policy.startTime} - ${policy.endTime}`,
      currentDistanceKm: distanceKm,
      maxRadiusKm: maxRadius,
    },
  };
}
