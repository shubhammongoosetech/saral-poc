import { SaralErrorCode } from './codes';

/**
 * Base typed error for all SARAL SDK operations.
 * Guarantee: Stable error codes with detailed typed metadata.
 */
export class SaralError extends Error {
  public readonly code: SaralErrorCode;
  public readonly details?: Record<string, unknown>;

  constructor(code: SaralErrorCode, message: string, details?: Record<string, unknown>) {
    super(`[SARAL:${code}] ${message}`);
    this.name = 'SaralError';
    this.code = code;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when one or more of the 3 required domains (Foundation, Public, Private)
 * fails to produce or return an authorized partial signature.
 */
export class DomainQuorumError extends SaralError {
  public readonly missingDomains: string[];

  constructor(missingDomains: string[], message?: string) {
    const defaultMsg = `Domain quorum failed. Missing domain authorization: ${missingDomains.join(', ')}`;
    super('DOMAIN_QUORUM_FAILED', message || defaultMsg, { missingDomains });
    this.missingDomains = missingDomains;
  }
}

/**
 * Thrown when Zero-Trust context policy gates reject the signing request
 * (e.g. outside permitted working hours, geofence boundary breached, velocity anomaly).
 */
export class PolicyDeniedError extends SaralError {
  public readonly reason: string;

  constructor(reason: string) {
    super('POLICY_DENIED', `Access policy denied: ${reason}`, { reason });
    this.reason = reason;
  }
}

/**
 * Thrown when recipient address does not conform to the target chain specification.
 */
export class ChainAddressMismatchError extends SaralError {
  public readonly chainId: string;
  public readonly address: string;

  constructor(chainId: string, address: string, expectedFormat: string) {
    super(
      'CHAIN_ADDRESS_MISMATCH',
      `Address '${address}' does not match expected format (${expectedFormat}) for chain '${chainId}'.`,
      { chainId, address, expectedFormat }
    );
    this.chainId = chainId;
    this.address = address;
  }
}

