/**
 * SARAL Protocol V3 — Working Policy Engine (Time & Location Access)
 *
 * Implements:
 * 1. Authoritative server-side time evaluation using IANA timezones.
 * 2. Overnight time window support (e.g., 22:00 to 06:00).
 * 3. Permitted weekday validation (MON-SUN).
 * 4. Haversine distance geofence evaluation for location restrictions.
 * 5. Fail-closed access control when required location proof is missing.
 * 6. Audit logging of all access evaluations.
 */

import crypto from 'crypto';
import { DataStore, WorkingPolicyRecord } from '../storage/store';

const store = DataStore.getInstance();

export interface PolicyEvaluationResult {
  allowed: boolean;
  reason?: string;
  timeAllowed: boolean;
  locationAllowed: boolean;
  evaluatedAt: string;
  serverTime: string;
}

/**
 * Calculates great-circle distance between two points in meters using Haversine formula.
 */
export function calculateHaversineDistanceMeters(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number
): number {
  const R = 6371000; // Earth radius in meters
  const toRad = (deg: number) => (deg * Math.PI) / 180;

  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

/**
 * Evaluates time restrictions using authoritative server time in user's timezone.
 */
export function evaluateTimeRestriction(
  policy: WorkingPolicyRecord,
  serverDate: Date = new Date()
): { allowed: boolean; reason?: string } {
  if (!policy.timeRestrictionEnabled) {
    return { allowed: true };
  }

  // 1. Check expiration date if configured
  if (policy.expiresAt) {
    const expDate = new Date(policy.expiresAt);
    if (serverDate.getTime() > expDate.getTime()) {
      return { allowed: false, reason: `Working policy expired on ${policy.expiresAt}` };
    }
  }

  const tz = policy.timezone || 'Asia/Kolkata';

  // 2. Format server time into target timezone
  let parts: Intl.DateTimeFormatPart[];
  try {
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      weekday: 'short',
      hour: 'numeric',
      minute: 'numeric',
      hour12: false,
    });
    parts = formatter.formatToParts(serverDate);
  } catch (_) {
    // Fallback if timezone invalid
    return { allowed: false, reason: `Invalid timezone specified in policy: ${tz}` };
  }

  let weekday = '';
  let hour = 0;
  let minute = 0;

  for (const part of parts) {
    if (part.type === 'weekday') weekday = part.value.toUpperCase();
    if (part.type === 'hour') hour = parseInt(part.value, 10);
    if (part.type === 'minute') minute = parseInt(part.value, 10);
  }

  // Map 3-letter weekday
  const normalizedDay = weekday.substring(0, 3);

  // 3. Check allowed days
  if (policy.days && policy.days.length > 0) {
    const allowedDays = policy.days.map((d) => d.toUpperCase().substring(0, 3));
    if (!allowedDays.includes(normalizedDay)) {
      return {
        allowed: false,
        reason: `Access restricted on ${normalizedDay}. Allowed days: ${policy.days.join(', ')} (${tz})`,
      };
    }
  }

  // 4. Check time window
  const [startH, startM] = policy.startTime.split(':').map((v) => parseInt(v, 10));
  const [endH, endM] = policy.endTime.split(':').map((v) => parseInt(v, 10));

  const currentMinutes = hour * 60 + minute;
  const startMinutes = startH * 60 + startM;
  const endMinutes = endH * 60 + endM;

  let inWindow = false;
  if (startMinutes <= endMinutes) {
    // Normal window within single day (e.g. 09:00 to 18:00)
    inWindow = currentMinutes >= startMinutes && currentMinutes <= endMinutes;
  } else {
    // Overnight window crossing midnight (e.g. 22:00 to 06:00)
    inWindow = currentMinutes >= startMinutes || currentMinutes <= endMinutes;
  }

  if (!inWindow) {
    const formattedCurrent = `${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}`;
    return {
      allowed: false,
      reason: `Outside allowed working hours (${policy.startTime} - ${policy.endTime} ${tz}). Current time: ${formattedCurrent}`,
    };
  }

  return { allowed: true };
}

/**
 * Evaluates location restrictions using Haversine geofence calculation.
 */
export function evaluateLocationRestriction(
  policy: WorkingPolicyRecord,
  clientLat?: number,
  clientLng?: number
): { allowed: boolean; reason?: string } {
  if (!policy.locationRestrictionEnabled) {
    return { allowed: true };
  }

  if (clientLat === undefined || clientLng === undefined) {
    return {
      allowed: false,
      reason: 'Location coordinates required by active security policy but were not provided.',
    };
  }

  if (policy.geofenceEnabled && policy.lat !== undefined && policy.lng !== undefined) {
    const radiusMeters = policy.radiusMeters || 25000; // default 25km
    const distance = calculateHaversineDistanceMeters(policy.lat, policy.lng, clientLat, clientLng);

    if (distance > radiusMeters) {
      const distanceKm = (distance / 1000).toFixed(1);
      const radiusKm = (radiusMeters / 1000).toFixed(1);
      return {
        allowed: false,
        reason: `Location verification failed: You are ${distanceKm} km away from approved area '${policy.allowedRegion || 'Work'}' (Maximum allowed radius: ${radiusKm} km).`,
      };
    }
  }

  return { allowed: true };
}

/**
 * Evaluates full Working Policy (both time and location).
 */
export function evaluateWorkingPolicy(
  userId: string,
  clientLat?: number,
  clientLng?: number
): PolicyEvaluationResult {
  const policy = store.getPolicy(userId);
  const evaluatedAt = new Date().toISOString();

  // If no policy exists, user needs to complete onboarding
  if (!policy) {
    return {
      allowed: false,
      reason: 'Working policy not configured for user. Please complete onboarding.',
      timeAllowed: false,
      locationAllowed: false,
      evaluatedAt,
      serverTime: evaluatedAt,
    };
  }

  const timeCheck = evaluateTimeRestriction(policy);
  const locationCheck = evaluateLocationRestriction(policy, clientLat, clientLng);

  const allowed = timeCheck.allowed && locationCheck.allowed;
  const reason = !timeCheck.allowed
    ? timeCheck.reason
    : !locationCheck.allowed
    ? locationCheck.reason
    : undefined;

  // Log access decision
  store.logAccess({
    id: crypto.randomUUID(),
    userId,
    attemptedAt: evaluatedAt,
    lat: clientLat,
    lng: clientLng,
    allowed,
    reason: reason || 'Access Granted: Time and location policies satisfied.',
  });

  return {
    allowed,
    reason,
    timeAllowed: timeCheck.allowed,
    locationAllowed: locationCheck.allowed,
    evaluatedAt,
    serverTime: evaluatedAt,
  };
}
