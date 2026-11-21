import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('[Seed] Seeding default operator user and key references...');

  const operatorId = 'b79f86f3-44a6-48f9-be43-a1abb6456172';
  const walletId = 'wal-aa583bf2-9e66-415b-90c6-d8eda93bd540';

  // 1. User
  await prisma.user.upsert({
    where: { id: operatorId },
    update: {
      name: 'SARAL Operator',
      mobile: '+919825669385',
      loginMethod: 'mobile',
    },
    create: {
      id: operatorId,
      name: 'SARAL Operator',
      mobile: '+919825669385',
      loginMethod: 'mobile',
      createdAt: new Date('2026-11-18T21:12:58.163Z'),
    },
  });

  // 2. Wallet Identity (Zero addresses stored)
  await prisma.walletIdentity.upsert({
    where: { userId: operatorId },
    update: {
      status: 'READY',
      keyReferences: {
        mst: 'key-mst-7d57a501e008f36f',
        solana: 'key-sol-b06a5d5b49696a4f',
        bitcoin: 'key-btc-48ea9f6ba5a7de2a',
      },
    },
    create: {
      id: '3d2e140d-dd97-403e-9ed4-da6f17669b55',
      userId: operatorId,
      walletId,
      status: 'READY',
      keyReferences: {
        mst: 'key-mst-7d57a501e008f36f',
        solana: 'key-sol-b06a5d5b49696a4f',
        bitcoin: 'key-btc-48ea9f6ba5a7de2a',
      },
      createdAt: new Date('2026-11-18T21:12:58.294Z'),
    },
  });

  // 3. Working Policy
  await prisma.workingPolicy.upsert({
    where: { userId: operatorId },
    update: {},
    create: {
      id: '66336ce6-4ec7-40c6-a3de-3019061e6d7b',
      userId: operatorId,
      startTime: '00:00',
      endTime: '23:59',
      timezone: 'Asia/Kolkata',
      city: 'Indore',
      lat: 22.7196,
      lng: 75.8577,
      radiusKm: 50.0,
      timeRestrictionEnabled: true,
      locationRestrictionEnabled: false,
      geofenceEnabled: false,
      setAt: new Date('2026-11-18T21:12:58.360Z'),
    },
  });

  // 4. Wallet Key References
  const chains = [
    { chain: 'mst', keyRef: 'key-mst-7d57a501e008f36f' },
    { chain: 'solana', keyRef: 'key-sol-b06a5d5b49696a4f' },
    { chain: 'bitcoin', keyRef: 'key-btc-48ea9f6ba5a7de2a' },
  ];
  for (const c of chains) {
    await prisma.walletKeyReference.upsert({
      where: {
        walletId_chain: {
          walletId,
          chain: c.chain,
        },
      },
      update: {
        keyRef: c.keyRef,
        status: 'ACTIVE',
      },
      create: {
        walletId,
        chain: c.chain,
        keyRef: c.keyRef,
        status: 'ACTIVE',
      },
    });
  }

  console.log('[Seed] Database successfully seeded with default operator and policies.');
}

main()
  .catch((e) => {
    console.error('[Seed Error]', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

