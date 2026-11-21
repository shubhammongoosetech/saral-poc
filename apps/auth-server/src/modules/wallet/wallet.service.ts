import { walletRepository } from './wallet.repository';
import {
  deriveAddressFromDkgPublicKey,
  deriveMultiChainAddresses,
  createOrGetWallet as coreCreateOrGetWallet,
  recomputeWalletAddressesFromShares,
  MultiChainAddressesResponse,
  ChainAddressInfo,
} from '../../services/walletService';

export {
  MultiChainAddressesResponse,
  ChainAddressInfo,
  deriveAddressFromDkgPublicKey,
  deriveMultiChainAddresses,
};

export class WalletService {
  public async getWalletByUserId(userId: string) {
    return walletRepository.getWalletByUserId(userId);
  }

  public async createOrGetWallet(userId: string): Promise<{
    wallet: any;
    addresses: MultiChainAddressesResponse['addresses'];
    isNew: boolean;
  }> {
    return coreCreateOrGetWallet(userId);
  }

  public async recomputeAddresses(userId: string): Promise<MultiChainAddressesResponse> {
    return recomputeWalletAddressesFromShares(userId);
  }
}

export const walletService = new WalletService();
