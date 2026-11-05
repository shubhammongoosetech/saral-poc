/**
 * deviceController.ts
 *
 * Controller for Private Domain Devices and Guardians (Patent Paragraph [0017]).
 */

import { Request, Response, NextFunction } from 'express';
import {
  getDevicesForUser,
  enrollDevice,
  enrollGuardian,
  revokeDevice,
} from '../services/deviceService';

export async function handleGetDevices(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;
    const devices = getDevicesForUser(userId);
    res.json({ devices });
  } catch (err) {
    next(err);
  }
}

export async function handleEnrollDevice(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;
    const { name, deviceType, publicKeyHex, notes } = req.body;
    if (!name || typeof name !== 'string') {
      res.status(400).json({ error: 'Device name is required' });
      return;
    }

    const device = enrollDevice(userId, {
      name,
      deviceType: deviceType || 'DESKTOP',
      publicKeyHex,
      notes,
    });
    res.status(201).json({ success: true, device });
  } catch (err) {
    next(err);
  }
}

export async function handleEnrollGuardian(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;
    const { name, guardianEmail, notes } = req.body;
    if (!name || !guardianEmail) {
      res.status(400).json({ error: 'Guardian name and email are required' });
      return;
    }

    const guardian = enrollGuardian(userId, {
      name,
      guardianEmail,
      notes,
    });
    res.status(201).json({ success: true, guardian });
  } catch (err) {
    next(err);
  }
}

export async function handleRevokeDevice(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;
    const id = String(req.params.id);
    const success = revokeDevice(userId, id);
    if (!success) {
      res.status(404).json({ error: 'Device not found' });
      return;
    }
    res.json({ success: true, message: 'Device revoked successfully' });
  } catch (err) {
    next(err);
  }
}
