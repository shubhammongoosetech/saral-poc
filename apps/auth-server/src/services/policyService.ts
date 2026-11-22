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
  code?: 'LOCATION_REQUIRED' | 'LOCATION_INVALID' | 'POLICY_DENIED';
  timeAllowed: boolean;
  locationAllowed: boolean;
  evaluatedAt: string;
  serverTime: string;
}

export const ALL_WORKING_DAYS = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];
const VALID_TIME = /^(?:[01]\d|2[0-3]):[0-5]\d$/;

export class InvalidWorkingPolicy extends Error {}

export function parseCoordinate(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value === 'number') return value;
  return typeof value === 'string' && value.trim() ? Number(value) : NaN;
}

function validCoordinates(lat?: number, lng?: number): boolean {
  return lat !== undefined && lng !== undefined && Number.isFinite(lat) && Number.isFinite(lng)
    && Math.abs(lat) <= 90 && Math.abs(lng) <= 180;
}

export function parseWorkingPolicy(
  userId: string,
  body: Record<string, unknown>,
  defaultDays = ALL_WORKING_DAYS.slice(0, 5),
): WorkingPolicyRecord {
  const {
    timeRestrictionEnabled = true, startTime = '09:00', endTime = '18:00',
    days = defaultDays, timezone = 'Asia/Kolkata', expiresAt,
    locationRestrictionEnabled = false, geofenceEnabled = locationRestrictionEnabled,
  } = body;
  const allowedRegion = body.allowedRegion ?? body.city ?? 'Primary Workspace';
  const lat = parseCoordinate(body.lat);
  const lng = parseCoordinate(body.lng);
  const radiusMeters = parseCoordinate(body.radiusMeters ?? (body.radiusKm === undefined
    ? 25000 : Number(parseCoordinate(body.radiusKm)) * 1000));

  if (typeof timeRestrictionEnabled !== 'boolean' || typeof locationRestrictionEnabled !== 'boolean'
    || typeof geofenceEnabled !== 'boolean') throw new InvalidWorkingPolicy('Policy switches must be boolean.');
  if (typeof startTime !== 'string' || typeof endTime !== 'string'
    || !VALID_TIME.test(startTime) || !VALID_TIME.test(endTime)) {
    throw new InvalidWorkingPolicy('Working hours must use HH:mm format.');
  }
  if (!Array.isArray(days) || !days.length || days.some((day) => !ALL_WORKING_DAYS.includes(day))) {
    throw new InvalidWorkingPolicy('Select at least one valid working day.');
  }
  if (typeof timezone !== 'string' || !timezone || timezone.length > 100) {
    throw new InvalidWorkingPolicy('A valid time zone is required.');
  }
  try {
    new Intl.DateTimeFormat('en', { timeZone: timezone });
  } catch {
    throw new InvalidWorkingPolicy('A valid time zone is required.');
  }
  if (expiresAt !== undefined && (typeof expiresAt !== 'string' || !Number.isFinite(Date.parse(expiresAt)))) {
    throw new InvalidWorkingPolicy('The policy expiration is invalid.');
  }
  if (typeof allowedRegion !== 'string' || !allowedRegion.trim() || allowedRegion.length > 255) {
    throw new InvalidWorkingPolicy('A valid workspace name is required.');
  }
  if ((geofenceEnabled || lat !== undefined || lng !== undefined) && !validCoordinates(lat, lng)) {
    throw new InvalidWorkingPolicy('Valid workspace coordinates are required.');
  }
  if (radiusMeters === undefined || !Number.isFinite(radiusMeters) || radiusMeters <= 0) {
    throw new InvalidWorkingPolicy('The geofence radius must be a positive number.');
  }
  return {
    userId, timeRestrictionEnabled, startTime, endTime, days: [...new Set(days)], timezone, expiresAt,
    locationRestrictionEnabled: locationRestrictionEnabled || geofenceEnabled,
    geofenceEnabled, allowedRegion: allowedRegion.trim(), lat, lng, radiusMeters,
    updatedAt: new Date().toISOString(),
  };
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

  const clamped = Math.min(Math.max(a, 0), 1);
  const c = 2 * Math.atan2(Math.sqrt(clamped), Math.sqrt(1 - clamped));
  return R * c;
}

/**
 * Evaluates time restrictions using authoritative server time in user's timezone.
 */
export function evaluateTimeRestriction(
  policy: WorkingPolicyRecord,
  serverDate: Date = new Date()
): { allowed: boolean; reason?: string } {
  // 1. Check expiration date if configured
  if (policy.expiresAt) {
    const expDate = new Date(policy.expiresAt);
    if (!Number.isFinite(expDate.getTime()) || serverDate.getTime() >= expDate.getTime()) {
      return { allowed: false, reason: `Working policy expired on ${policy.expiresAt}` };
    }
  }
  if (!policy.timeRestrictionEnabled) return { allowed: true };

  const tz = policy.timezone || 'Asia/Kolkata';

  // 2. Format server time into target timezone
  let parts: Intl.DateTimeFormatPart[];
  try {
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      weekday: 'short',
      hour: 'numeric',
      minute: 'numeric',
      hourCycle: 'h23',
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
): { allowed: boolean; reason?: string; code?: PolicyEvaluationResult['code'] } {
  if (!policy.locationRestrictionEnabled && !policy.geofenceEnabled) {
    return { allowed: true };
  }

  if (clientLat === undefined || clientLng === undefined) {
    return {
      allowed: false,
      code: 'LOCATION_REQUIRED',
      reason: 'Location coordinates required by active security policy but were not provided.',
    };
  }
  if (!validCoordinates(clientLat, clientLng)) {
    return { allowed: false, code: 'LOCATION_INVALID', reason: 'The supplied location coordinates are invalid.' };
  }

  if (policy.geofenceEnabled) {
    if (policy.lat === undefined || policy.lng === undefined || !validCoordinates(policy.lat, policy.lng)) {
      return { allowed: false, code: 'POLICY_DENIED', reason: 'The geofence has no valid workspace location.' };
    }
    const radiusMeters = policy.radiusMeters ?? 25000;
    if (!Number.isFinite(radiusMeters) || radiusMeters <= 0) {
      return { allowed: false, code: 'POLICY_DENIED', reason: 'The geofence has no valid radius.' };
    }
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
      code: 'POLICY_DENIED',
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
    lat: Number.isFinite(clientLat) ? clientLat : undefined,
    lng: Number.isFinite(clientLng) ? clientLng : undefined,
    allowed,
    reason: reason || 'Access Granted: Time and location policies satisfied.',
  });

  return {
    allowed,
    reason,
    code: allowed ? undefined : (timeCheck.allowed ? locationCheck.code : undefined) ?? 'POLICY_DENIED',
    timeAllowed: timeCheck.allowed,
    locationAllowed: locationCheck.allowed,
    evaluatedAt,
    serverTime: evaluatedAt,
  };
}
