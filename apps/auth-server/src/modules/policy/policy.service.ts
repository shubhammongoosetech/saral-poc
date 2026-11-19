import { policyRepository } from './policy.repository';
import { WorkingPolicy } from '@prisma/client';

export interface PolicyEvaluationResult {
  allowed: boolean;
  reason?: string;
  timeAllowed: boolean;
  locationAllowed: boolean;
  evaluatedAt: string;
  serverTime: string;
}

export function calculateHaversineDistanceMeters(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number
): number {
  const R = 6371000;
  const toRad = (deg: number) => (deg * Math.PI) / 180;

  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

export function evaluateTimeRestriction(
  policy: WorkingPolicy,
  serverDate: Date = new Date()
): { allowed: boolean; reason?: string } {
  if (!policy.timeRestrictionEnabled) {
    return { allowed: true };
  }

  try {
    const tz = policy.timezone || 'Asia/Kolkata';
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });
    const parts = formatter.formatToParts(serverDate);
    const hour = parseInt(parts.find((p) => p.type === 'hour')?.value || '0', 10);
    const minute = parseInt(parts.find((p) => p.type === 'minute')?.value || '0', 10);
    const currentMins = hour * 60 + minute;

    const [startH, startM] = policy.startTime.split(':').map((v) => parseInt(v, 10));
    const [endH, endM] = policy.endTime.split(':').map((v) => parseInt(v, 10));
    const startMins = startH * 60 + startM;
    const endMins = endH * 60 + endM;

    let inWindow = false;
    if (startMins <= endMins) {
      inWindow = currentMins >= startMins && currentMins <= endMins;
    } else {
      // Overnight span
      inWindow = currentMins >= startMins || currentMins <= endMins;
    }

    if (!inWindow) {
      return {
        allowed: false,
        reason: `Current time (${String(hour).padStart(2, '0')}:${String(minute).padStart(
          2,
          '0'
        )} ${tz}) is outside authorized operating window (${policy.startTime} - ${policy.endTime}).`,
      };
    }

    return { allowed: true };
  } catch (err: any) {
    return { allowed: false, reason: `Time evaluation error: ${err.message}` };
  }
}

export function evaluateLocationRestriction(
  policy: WorkingPolicy,
  lat?: number,
  lng?: number
): { allowed: boolean; reason?: string } {
  if (!policy.locationRestrictionEnabled && !policy.geofenceEnabled) {
    return { allowed: true };
  }

  if (lat === undefined || lng === undefined) {
    return {
      allowed: false,
      reason: 'Location restriction is active, but client coordinates were not provided (Fail-Closed).',
    };
  }

  const distanceMeters = calculateHaversineDistanceMeters(policy.lat, policy.lng, lat, lng);
  const maxDistanceMeters = (policy.radiusKm || 25) * 1000;

  if (distanceMeters > maxDistanceMeters) {
    return {
      allowed: false,
      reason: `Client coordinates are ${(distanceMeters / 1000).toFixed(
        1
      )}km away from authorized center (${policy.city}), exceeding max allowed radius of ${
        policy.radiusKm
      }km.`,
    };
  }

  return { allowed: true };
}

export class PolicyService {
  public async getPolicy(userId: string): Promise<WorkingPolicy | null> {
    return policyRepository.getPolicyByUserId(userId);
  }

  public async upsertPolicy(data: {
    userId: string;
    startTime: string;
    endTime: string;
    timezone?: string;
    city: string;
    lat: number;
    lng: number;
    radiusKm?: number;
    timeRestrictionEnabled?: boolean;
    locationRestrictionEnabled?: boolean;
    geofenceEnabled?: boolean;
  }): Promise<WorkingPolicy> {
    return policyRepository.upsertPolicy(data);
  }

  public async evaluateWorkingPolicy(
    userId: string,
    lat?: number,
    lng?: number
  ): Promise<PolicyEvaluationResult> {
    const serverDate = new Date();
    const policy = await policyRepository.getPolicyByUserId(userId);

    if (!policy) {
      return {
        allowed: true,
        timeAllowed: true,
        locationAllowed: true,
        evaluatedAt: serverDate.toISOString(),
        serverTime: serverDate.toISOString(),
      };
    }

    const timeRes = evaluateTimeRestriction(policy, serverDate);
    const locRes = evaluateLocationRestriction(policy, lat, lng);
    const allowed = timeRes.allowed && locRes.allowed;
    const reason = !timeRes.allowed ? timeRes.reason : !locRes.allowed ? locRes.reason : undefined;

    await policyRepository.logAccessAttempt({
      userId,
      lat,
      lng,
      allowed,
      reason: reason || 'Access granted by Working Policy',
    });

    return {
      allowed,
      reason,
      timeAllowed: timeRes.allowed,
      locationAllowed: locRes.allowed,
      evaluatedAt: serverDate.toISOString(),
      serverTime: serverDate.toISOString(),
    };
  }
}

export const policyService = new PolicyService();

