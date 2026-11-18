/**
 * domain.ts
 *
 * SARAL 3-Domain Separation of Powers Type Definitions
 *
 * Defines the canonical access structure:
 *  - FOUNDATION: Institutional / Administrative quorum
 *  - PUBLIC:     Independent Public Validator quorum
 *  - PRIVATE:    Sovereign User quorum
 */

export type DomainType = 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';
export type DomainName = DomainType;

export interface DomainMetadata {
  domain: DomainType;
  role: string;
  defaultNodes: number;
  defaultThreshold: number;
}
