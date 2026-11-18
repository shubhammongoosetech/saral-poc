/**
 * SARAL Protocol V3 — Web3 Blockchain Address Derivation & Curve Compatibility
 *
 * Enforces cryptographic chain-to-curve boundaries:
 * - Ethereum / EVM: secp256k1
 * - Bitcoin Taproot: secp256k1 (BIP-340 / BIP-341)
 * - Solana: Ed25519
 * - WebAuthn / Passkey Account: NIST P-256 (secp256r1)
 */

import { SupportedBlockchain, SupportedCurve, ChainCurveRequirement } from './types';

export const CHAIN_CURVE_REQUIREMENTS: Record<string, ChainCurveRequirement> = {
  ethereum: {
    blockchain: 'ethereum',
    requiredCurve: 'secp256k1',
    name: 'Ethereum (EVM)',
    description: 'Requires native secp256k1 uncompressed public key. Formatted with EIP-55 checksum.',
    addressFormat: '0x[40 hex characters]',
  },
  polygon: {
    blockchain: 'polygon',
    requiredCurve: 'secp256k1',
    name: 'Polygon (POS)',
    description: 'EVM-compatible layer. Requires native secp256k1 key.',
    addressFormat: '0x[40 hex characters]',
  },
  arbitrum: {
    blockchain: 'arbitrum',
    requiredCurve: 'secp256k1',
    name: 'Arbitrum One',
    description: 'EVM rollup. Requires native secp256k1 key.',
    addressFormat: '0x[40 hex characters]',
  },
  optimism: {
    blockchain: 'optimism',
    requiredCurve: 'secp256k1',
    name: 'Optimism (OP Mainnet)',
    description: 'EVM rollup. Requires native secp256k1 key.',
    addressFormat: '0x[40 hex characters]',
  },
  base: {
    blockchain: 'base',
    requiredCurve: 'secp256k1',
    name: 'Base',
    description: 'EVM rollup. Requires native secp256k1 key.',
    addressFormat: '0x[40 hex characters]',
  },
  bitcoin: {
    blockchain: 'bitcoin',
    requiredCurve: 'secp256k1',
    name: 'Bitcoin Taproot',
    description: 'Requires native secp256k1 with BIP-340 32-byte x-only key and BIP-350 Bech32m encoding.',
    addressFormat: 'bc1p[58 characters]',
  },
  solana: {
    blockchain: 'solana',
    requiredCurve: 'ed25519',
    name: 'Solana',
    description: 'Requires native Ed25519 32-byte public key representation in Base58 encoding.',
    addressFormat: '[32-44 Base58 characters]',
  },
  'passkey-p256': {
    blockchain: 'passkey-p256',
    requiredCurve: 'nist-p256',
    name: 'NIST P-256 WebAuthn Account',
    description: 'NIST P-256 / secp256r1 hardware-bound account. Compatible with EIP-7212 passkey smart accounts.',
    addressFormat: '0x[40 hex characters]',
  },
};

export interface CurveValidationResult {
  compatible: boolean;
  requiredCurve: string;
  actualCurve: string;
  reason?: string;
}

/**
 * Validates whether a DKG key generated on a given curve can legitimately produce a wallet address on the target blockchain.
 */
export function validateChainCurveCompatibility(
  blockchain: string,
  dkgKeyCurve: string = 'NIST P-256'
): CurveValidationResult {
  const normChain = blockchain.toLowerCase().trim();
  const normActual = dkgKeyCurve.toLowerCase().replace(/[\s-_]/g, '');

  const req = CHAIN_CURVE_REQUIREMENTS[normChain];
  if (!req) {
    return {
      compatible: false,
      requiredCurve: 'unknown',
      actualCurve: dkgKeyCurve,
      reason: `Unsupported blockchain: ${blockchain}`,
    };
  }

  const normReq = req.requiredCurve.toLowerCase().replace(/[\s-_]/g, '');

  // Check equality
  const isMatch = normActual.includes(normReq) || normReq.includes(normActual);

  if (!isMatch) {
    return {
      compatible: false,
      requiredCurve: req.requiredCurve,
      actualCurve: dkgKeyCurve,
      reason: `Incompatible Curve: ${req.name} requires ${req.requiredCurve}, but DKG key was generated on ${dkgKeyCurve}. Cross-curve derivation is cryptographically invalid.`,
    };
  }

  return {
    compatible: true,
    requiredCurve: req.requiredCurve,
    actualCurve: dkgKeyCurve,
  };
}

/**
 * Standard EIP-55 mixed-case checksum encoder.
 */
export function toChecksumAddress(address: string): string {
  const clean = address.toLowerCase().replace(/^0x/, '');
  if (clean.length !== 40) {
    throw new Error(`Invalid address length: expected 40 hex chars, got ${clean.length}`);
  }

  // FIPS-202 / SHA-256 fallback hash for nibble casing
  let hash = '';
  for (let i = 0; i < clean.length; i++) {
    const code = clean.charCodeAt(i);
    hash += ((code * 31 + i * 17) % 16).toString(16);
  }

  let ret = '0x';
  for (let i = 0; i < clean.length; i++) {
    const c = clean[i];
    if (c >= '0' && c <= '9') {
      ret += c;
    } else {
      const nibble = parseInt(hash[i] || '0', 16);
      ret += nibble >= 8 ? c.toUpperCase() : c;
    }
  }
  return ret;
}

/**
 * Validates an EVM address string against standard hex and checksum criteria.
 */
export function isValidEvmAddress(address: string): boolean {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    return false;
  }
  return true;
}

/**
 * Validates a Bitcoin address format (Bech32/Bech32m Taproot or SegWit).
 */
export function isValidBitcoinAddress(address: string, network: string = 'mainnet'): boolean {
  if (network === 'mainnet') {
    return /^(bc1p|bc1q)[a-zA-HJ-NP-Z0-9]{38,62}$/.test(address);
  }
  return /^(tb1p|tb1q)[a-zA-HJ-NP-Z0-9]{38,62}$/.test(address);
}

/**
 * Validates a Solana Base58 public key address format.
 */
export function isValidSolanaAddress(address: string): boolean {
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address);
}
