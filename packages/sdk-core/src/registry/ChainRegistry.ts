import { ChainConfig, CurveType, SignatureScheme } from '../types/chain';
import { BUILT_IN_CHAINS } from './chains';
import { validateChainConfig, assertValidChainAddress, isValidChainAddress } from './validation';
import { SaralError } from '../errors/SaralError';

export class ChainRegistry {
  private readonly chains = new Map<string, ChainConfig>();

  constructor(initialChains?: Record<string, ChainConfig> | ChainConfig[]) {
    // Populate built-in defaults
    for (const [id, config] of Object.entries(BUILT_IN_CHAINS)) {
      this.chains.set(id, config);
    }

    // Populate user-supplied or custom chains
    if (initialChains) {
      if (Array.isArray(initialChains)) {
        for (const chain of initialChains) {
          this.registerChain(chain);
        }
      } else {
        for (const chain of Object.values(initialChains)) {
          this.registerChain(chain);
        }
      }
    }
  }

  /**
   * Registers a new custom chain after validating it with Zod schema.
   */
  public registerChain(candidateConfig: unknown): ChainConfig {
    const validated = validateChainConfig(candidateConfig);
    this.chains.set(validated.id, validated);
    return validated;
  }

  /**
   * Looks up a chain by ID. Throws CHAIN_NOT_FOUND if not registered.
   */
  public getChain(chainId: string): ChainConfig {
    const cleanId = chainId.trim().toLowerCase();
    const found = this.chains.get(cleanId);
    if (!found) {
      const available = Array.from(this.chains.keys()).join(', ');
      throw new SaralError(
        'CHAIN_NOT_FOUND',
        `Unsupported or unregistered chain: '${chainId}'. Available chains: [${available}]`,
        { chainId, availableChains: Array.from(this.chains.keys()) }
      );
    }
    return found;
  }

  /**
   * Checks if a chain ID is registered.
   */
  public hasChain(chainId: string): boolean {
    return this.chains.has(chainId.trim().toLowerCase());
  }

  /**
   * Returns all currently registered chains.
   */
  public getAllChains(): ChainConfig[] {
    return Array.from(this.chains.values());
  }

  /**
   * Detects and returns chain entry from an ID or throws CHAIN_NOT_FOUND.
   * From the returned entry, curve and signing scheme are strictly determined.
   */
  public detectChain(chainId: string): {
    chain: ChainConfig;
    curve: CurveType;
    scheme: SignatureScheme;
  } {
    const chain = this.getChain(chainId);
    return {
      chain,
      curve: chain.curve,
      scheme: chain.signatureScheme,
    };
  }

  /**
   * Validates a recipient address against the designated chain.
   * Throws CHAIN_ADDRESS_MISMATCH if invalid.
   */
  public assertValidAddress(chainId: string, address: string): void {
    const chain = this.getChain(chainId);
    assertValidChainAddress(chain, address);
  }

  /**
   * Returns boolean whether address matches chain format.
   */
  public isValidAddress(chainId: string, address: string): boolean {
    const chain = this.chains.get(chainId.trim().toLowerCase());
    if (!chain) return false;
    return isValidChainAddress(chain, address);
  }
}

/** Default singleton instance of ChainRegistry */
export const defaultChainRegistry = new ChainRegistry();

