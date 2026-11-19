import { prisma } from '../../database/prisma';
import { WorkingPolicy, AccessLog } from '@prisma/client';

export class PolicyRepository {
  public async getPolicyByUserId(userId: string): Promise<WorkingPolicy | null> {
    return prisma.workingPolicy.findUnique({
      where: { userId },
    });
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
    return prisma.workingPolicy.upsert({
      where: { userId: data.userId },
      create: {
        userId: data.userId,
        startTime: data.startTime,
        endTime: data.endTime,
        timezone: data.timezone || 'Asia/Kolkata',
        city: data.city,
        lat: data.lat,
        lng: data.lng,
        radiusKm: data.radiusKm ?? 25.0,
        timeRestrictionEnabled: data.timeRestrictionEnabled ?? true,
        locationRestrictionEnabled: data.locationRestrictionEnabled ?? false,
        geofenceEnabled: data.geofenceEnabled ?? false,
      },
      update: {
        startTime: data.startTime,
        endTime: data.endTime,
        timezone: data.timezone || 'Asia/Kolkata',
        city: data.city,
        lat: data.lat,
        lng: data.lng,
        radiusKm: data.radiusKm ?? 25.0,
        timeRestrictionEnabled: data.timeRestrictionEnabled ?? true,
        locationRestrictionEnabled: data.locationRestrictionEnabled ?? false,
        geofenceEnabled: data.geofenceEnabled ?? false,
        setAt: new Date(),
      },
    });
  }

  public async logAccessAttempt(data: {
    userId: string;
    lat?: number;
    lng?: number;
    allowed: boolean;
    reason: string;
  }): Promise<AccessLog> {
    return prisma.accessLog.create({
      data: {
        userId: data.userId,
        lat: data.lat,
        lng: data.lng,
        allowed: data.allowed,
        reason: data.reason,
      },
    });
  }
}

export const policyRepository = new PolicyRepository();

