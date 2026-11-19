import { prisma } from '../../database/prisma';
import { User, AuthIdentity } from '@prisma/client';

export class AuthRepository {
  public async findUserById(id: string): Promise<User | null> {
    return prisma.user.findUnique({
      where: { id },
      include: {
        mfa: true,
        workPolicy: true,
        wallet: true,
      },
    });
  }

  public async findUserByEmail(email: string): Promise<User | null> {
    return prisma.user.findUnique({
      where: { email: email.toLowerCase().trim() },
    });
  }

  public async findUserByGoogleId(googleId: string): Promise<User | null> {
    return prisma.user.findUnique({
      where: { googleId },
    });
  }

  public async findUserByMobile(mobile: string): Promise<User | null> {
    return prisma.user.findUnique({
      where: { mobile: mobile.trim() },
    });
  }

  public async createUser(data: {
    id?: string;
    name?: string;
    email?: string;
    googleId?: string;
    mobile?: string;
    loginMethod: string;
  }): Promise<User> {
    return prisma.user.create({
      data: {
        id: data.id,
        name: data.name,
        email: data.email?.toLowerCase().trim(),
        googleId: data.googleId,
        mobile: data.mobile?.trim(),
        loginMethod: data.loginMethod,
      },
    });
  }

  public async updateUser(
    id: string,
    data: Partial<{
      name: string;
      email: string;
      googleId: string;
      mobile: string;
    }>
  ): Promise<User> {
    return prisma.user.update({
      where: { id },
      data,
    });
  }

  public async linkIdentity(
    userId: string,
    provider: string,
    providerId: string,
    metadata: Record<string, any> = {}
  ): Promise<AuthIdentity> {
    return prisma.authIdentity.upsert({
      where: {
        provider_providerId: {
          provider,
          providerId,
        },
      },
      create: {
        userId,
        provider,
        providerId,
        metadata,
      },
      update: {
        userId,
        metadata,
      },
    });
  }
}

export const authRepository = new AuthRepository();
