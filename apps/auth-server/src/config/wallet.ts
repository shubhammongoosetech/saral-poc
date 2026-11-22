export const walletDomains = ['foundation', 'public', 'private'] as const;
export type WalletDomain = typeof walletDomains[number];

export const walletChains = [
  { chain: 'mst', curve: 'secp256k1', legacySession: 'mstSessionId' },
  { chain: 'solana', curve: 'ed25519', legacySession: 'solanaSessionId' },
  { chain: 'bitcoin', curve: 'secp256k1', legacySession: 'bitcoinSessionId' },
] as const;

export type WalletChain = typeof walletChains[number]['chain'];
export type WalletCurve = typeof walletChains[number]['curve'];
export type WalletCommittee = `committee-${WalletDomain}`;

export type WalletSessionReference = { keyId: string; sessionId: string };
export type WalletMeshReferences = Record<WalletDomain, Record<WalletChain, WalletSessionReference>>;

export function walletCommittee(domain: WalletDomain): WalletCommittee {
  return `committee-${domain}`;
}

export function walletCommitteeNodes(domain: WalletDomain): string[] {
  return Array.from({ length: 5 }, (_, index) => `saral-${domain}-${index + 1}`);
}
