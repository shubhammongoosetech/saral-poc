/**
 * index.ts
 *
 * Verifiable Secret Sharing (VSS) Module Barrel Export.
 * Unified API for Feldman VSS, Pedersen VSS, and HybridVSS.
 */

export * from './types';
export * from './feldmanVss';
export * from './pedersenVss';
export { HybridVssNode } from '../crypto/hybriddkg/hybridVss';
