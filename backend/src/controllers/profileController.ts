import { Request, Response, NextFunction } from 'express';
import { prisma } from '../config/db';
import { workingPolicySchema } from '../utils/validation';

export async function handleGetProfile(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;

    const user = await prisma.user.findUnique({
      where:  { id: userId },
      select: {
        id:          true,
        googleId:    true,
        email:       true,
        mobile:      true,
        loginMethod: true,
        createdAt:   true,
        mfa: {
          select: { type: true, verifiedAt: true },
        },
        workPolicy: {
          select: {
            startTime: true, endTime: true, timezone: true,
            city: true, lat: true, lng: true, radiusKm: true, setAt: true,
          },
        },
      },
    });

    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    const hasWallet = (await prisma.keyShare.count({ where: { userId } })) > 0;

    const formattedMfa = user.mfa ? {
      type: user.mfa.type,
      verified_at: user.mfa.verifiedAt ? user.mfa.verifiedAt.toISOString() : null,
      verifiedAt:  user.mfa.verifiedAt ? user.mfa.verifiedAt.toISOString() : null,
    } : null;

    const formattedPolicy = user.workPolicy ? {
      start_time: user.workPolicy.startTime,
      end_time:   user.workPolicy.endTime,
      startTime:  user.workPolicy.startTime,
      endTime:    user.workPolicy.endTime,
      timezone:   user.workPolicy.timezone,
      city:       user.workPolicy.city,
      lat:        user.workPolicy.lat,
      lng:        user.workPolicy.lng,
      radius_km:  user.workPolicy.radiusKm,
      radiusKm:   user.workPolicy.radiusKm,
      set_at:     user.workPolicy.setAt.toISOString(),
      setAt:      user.workPolicy.setAt.toISOString(),
    } : null;

    res.json({
      user: {
        id:           user.id,
        google_id:    user.googleId,
        email:        user.email,
        mobile:       user.mobile,
        login_method: user.loginMethod,
        created_at:   user.createdAt,
      },
      mfa:         formattedMfa,
      policy:      formattedPolicy,
      wallet:      null,
      mfaVerified: !!user.mfa?.verifiedAt,
      hasPolicy:   !!user.workPolicy,
      hasWallet,
    });
  } catch (err) {
    next(err);
  }
}

export async function handleSetPolicy(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId    = req.user!.userId;
    const validated = workingPolicySchema.parse(req.body);
    const radiusKm  = validated.radiusKm ?? 25;

    const policy = await prisma.workPolicy.upsert({
      where:  { userId },
      update: {
        startTime: validated.startTime,
        endTime:   validated.endTime,
        timezone:  validated.timezone,
        city:      validated.city,
        lat:       validated.lat,
        lng:       validated.lng,
        radiusKm,
        setAt:     new Date(),
      },
      create: {
        userId,
        startTime: validated.startTime,
        endTime:   validated.endTime,
        timezone:  validated.timezone,
        city:      validated.city,
        lat:       validated.lat,
        lng:       validated.lng,
        radiusKm,
      },
    });

    res.json({
      success: true,
      policy,
      message: 'Working policy saved successfully',
    });
  } catch (err) {
    next(err);
  }
}
