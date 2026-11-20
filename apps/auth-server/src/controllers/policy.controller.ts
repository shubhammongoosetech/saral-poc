import { Request, Response } from 'express';
import { DataStore, WorkingPolicyRecord } from '../storage/store';
import { evaluateWorkingPolicy } from '../services/policyService';

const store = DataStore.getInstance();

/**
 * PolicyController
 * Feature: Working Policy Engine (Time restriction & Geofencing)
 * 
 * Handles:
 * - User Profile & Policy retrieval
 * - Working Policy creation & modification (Time window, Days, City, Lat/Lng, Radius)
 * - Authoritative Time & Geofence evaluation
 * - Policy Access Check
 */
export class PolicyController {
  /**
   * GET /profile
   * Hinglish: Logged-in user ki profile info, wallet status aur active working policy fetch karta hai.
   */
  public static getProfile(req: Request, res: Response): void {
    const userId = req.user!.userId;
    const user = store.findUserById(userId);
    const mfa = store.getMfa(userId);
    const policy = store.getPolicy(userId);
    const wallet = store.getWalletByUserId(userId);

    res.json({
      user: user || { id: userId, login_method: 'mobile', created_at: new Date().toISOString() },
      hasPolicy: !!policy,
      policy: policy
        ? {
          startTime: policy.startTime,
          endTime: policy.endTime,
          start_time: policy.startTime,
          end_time: policy.endTime,
          timezone: policy.timezone,
          city: policy.allowedRegion,
          lat: policy.lat,
          lng: policy.lng,
          radiusKm: policy.radiusMeters ? policy.radiusMeters / 1000 : 25,
          radius_km: policy.radiusMeters ? policy.radiusMeters / 1000 : 25,
          setAt: policy.updatedAt,
          set_at: policy.updatedAt,
        }
        : null,
      hasWallet: !!wallet && wallet.status === 'READY',
      mfaVerified: !!mfa?.verifiedAt,
      mfa: mfa ? { type: mfa.type, verifiedAt: mfa.verifiedAt, verified_at: mfa.verifiedAt } : null,
    });
  }

  /**
   * POST /profile/policy
   * Hinglish: User onboarding par apni working hours aur location geofence save karta hai.
   */
  public static savePolicy(req: Request, res: Response): void {
    try {
      const userId = req.user!.userId;
      const {
        startTime,
        endTime,
        timezone,
        city,
        lat,
        lng,
        radiusKm,
        timeRestrictionEnabled,
        locationRestrictionEnabled,
      } = req.body;

      const record: WorkingPolicyRecord = {
        userId,
        timeRestrictionEnabled: timeRestrictionEnabled !== undefined ? Boolean(timeRestrictionEnabled) : true,
        startTime: startTime || '09:00',
        endTime: endTime || '18:00',
        days: ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'],
        timezone: timezone || 'Asia/Kolkata',
        locationRestrictionEnabled: Boolean(locationRestrictionEnabled),
        allowedRegion: city || 'Indore',
        geofenceEnabled: Boolean(locationRestrictionEnabled),
        lat: lat !== undefined ? Number(lat) : 22.7196,
        lng: lng !== undefined ? Number(lng) : 75.8577,
        radiusMeters: (Number(radiusKm) || 25) * 1000,
        updatedAt: new Date().toISOString(),
      };

      store.savePolicy(record);

      res.json({
        message: 'Policy saved successfully',
        policy: {
          startTime: record.startTime,
          endTime: record.endTime,
          timezone: record.timezone,
          city: record.allowedRegion,
          lat: record.lat,
          lng: record.lng,
          radiusKm: Number(radiusKm) || 25,
        },
      });
    } catch (err: any) {
      res.status(400).json({ error: err.message || 'Failed to save policy' });
    }
  }

  /**
   * GET /wallet/policy & GET /policy
   * Hinglish: Specific user ki existing Working Policy details return karta hai.
   */
  public static getPolicy(req: Request, res: Response): void {
    const userId = req.user!.userId;
    const policy = store.getPolicy(userId);
    res.json({
      success: true,
      policy: policy || null,
    });
  }

  /**
   * PUT /wallet/policy & PUT /policy
   * Hinglish: MFA verify hone ke baad working policy modify/update karta hai.
   */
  public static updatePolicy(req: Request, res: Response): void {
    try {
      const userId = req.user!.userId;
      const {
        timeRestrictionEnabled = true,
        startTime = '09:00',
        endTime = '18:00',
        days = ['MON', 'TUE', 'WED', 'THU', 'FRI'],
        timezone = 'Asia/Kolkata',
        expiresAt,
        locationRestrictionEnabled = false,
        allowedRegion = 'Primary Workspace',
        geofenceEnabled = false,
        lat,
        lng,
        radiusMeters = 25000,
      } = req.body;

      const record: WorkingPolicyRecord = {
        userId,
        timeRestrictionEnabled: Boolean(timeRestrictionEnabled),
        startTime,
        endTime,
        days: Array.isArray(days) ? days : ['MON', 'TUE', 'WED', 'THU', 'FRI'],
        timezone,
        expiresAt,
        locationRestrictionEnabled: Boolean(locationRestrictionEnabled),
        allowedRegion,
        geofenceEnabled: Boolean(geofenceEnabled),
        lat: lat !== undefined ? Number(lat) : undefined,
        lng: lng !== undefined ? Number(lng) : undefined,
        radiusMeters: radiusMeters !== undefined ? Number(radiusMeters) : 25000,
        updatedAt: new Date().toISOString(),
      };

      store.savePolicy(record);

      res.json({
        success: true,
        message: 'Working policy saved successfully',
        policy: record,
      });
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message || 'Failed to save policy' });
    }
  }

  /**
   * POST /wallet/policy/evaluate & POST /policy/evaluate
   * Hinglish: Current time aur user ke latitude/longitude coordinates ke basis par policy evaluate karta hai.
   */
  public static evaluatePolicy(req: Request, res: Response): void {
    const userId = req.user!.userId;
    const lat = req.body?.lat !== undefined ? Number(req.body.lat) : undefined;
    const lng = req.body?.lng !== undefined ? Number(req.body.lng) : undefined;

    const result = evaluateWorkingPolicy(userId, lat, lng);
    res.json({
      success: true,
      ...result,
    });
  }

  /**
   * POST /wallet/check-access & POST /check-access
   * Hinglish: Frontend quick check karta hai ki user allowed time/location window me hai ya nahi.
   */
  public static checkAccess(req: Request, res: Response): void {
    const userId = req.user!.userId;
    const lat = req.body?.lat !== undefined ? Number(req.body.lat) : undefined;
    const lng = req.body?.lng !== undefined ? Number(req.body.lng) : undefined;

    const result = evaluateWorkingPolicy(userId, lat, lng);
    res.json({
      allowed: result.allowed,
      reason: result.reason,
      policyResult: result,
    });
  }
}

