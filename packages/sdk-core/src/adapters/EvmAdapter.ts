import { ethers } from 'ethers';
import { EvmChainConfig } from '../types/chain';
import {
  ChainAdapter,
  PaymentRequest,
  UnsignedTx,
  SignatureResult,
  SignedTx,
  ConfirmationResult,
  FeeEstimate,
} from '../types/adapter';
import { SaralError } from '../errors/SaralError';

export class EvmAdapter implements ChainAdapter {
  public readonly chain: EvmChainConfig;
  private readonly provider: ethers.JsonRpcProvider;

  constructor(chain: EvmChainConfig, provider?: ethers.JsonRpcProvider) {
    this.chain = chain;
    if (provider) {
      this.provider = provider;
    } else {
      const network = ethers.Network.from({
        chainId: chain.chainId,
        name: chain.id,
      });
      this.provider = new ethers.JsonRpcProvider(chain.rpcUrl, network, {
        staticNetwork: network,
      });
    }
  }

  public getProvider(): ethers.JsonRpcProvider {
    return this.provider;
  }

  public deriveAddress(publicKey: Uint8Array | string): string {
    try {
      const pkHex =
        typeof publicKey === 'string'
          ? publicKey.startsWith('0x')
            ? publicKey
            : '0x' + publicKey
          : ethers.hexlify(publicKey);
      return ethers.computeAddress(pkHex);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new SaralError('INVALID_CONFIG', `Failed to derive EVM address: ${msg}`);
    }
  }

  public validateAddress(address: string): boolean {
    return ethers.isAddress(address.trim());
  }

  public async getBalance(address: string): Promise<bigint> {
    const cleanAddr = ethers.getAddress(address.trim());
    try {
      return await this.provider.getBalance(cleanAddr);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new SaralError(
        'RPC_ERROR',
        `Failed to fetch live balance for ${cleanAddr} on ${this.chain.id}: ${msg}`
      );
    }
  }

  public async estimateFee(req: PaymentRequest, fromAddress: string): Promise<FeeEstimate> {
    const cleanFrom = ethers.getAddress(fromAddress.trim());
    const cleanTo = ethers.getAddress(req.to.trim());
    const value = typeof req.amount === 'bigint' ? req.amount : ethers.parseEther(req.amount.toString().trim());

    const feeData = await this.provider.getFeeData().catch((err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      throw new SaralError('RPC_ERROR', `Failed to fetch gas fee data on ${this.chain.id}: ${msg}`);
    });

    let gasLimit: bigint;
    try {
      gasLimit = await this.provider.estimateGas({
        from: cleanFrom,
        to: cleanTo,
        value,
        data: req.memo ? ethers.hexlify(ethers.toUtf8Bytes(req.memo)) : undefined,
      });
      // Safety buffer of 10%
      gasLimit = (gasLimit * 110n) / 100n;
    } catch {
      gasLimit = req.gasLimit ?? 21000n;
    }

    const gasPrice = feeData.gasPrice ?? feeData.maxFeePerGas ?? ethers.parseUnits('1', 'gwei');
    const totalFee = gasLimit * gasPrice;

    return {
      feeAtomic: totalFee,
      feeFormatted: ethers.formatEther(totalFee),
      gasPrice,
      gasLimit,
    };
  }

  public async buildUnsignedTx(req: PaymentRequest, fromAddress: string): Promise<UnsignedTx> {
    const cleanFrom = ethers.getAddress(fromAddress.trim());
    const cleanTo = ethers.getAddress(req.to.trim());
    const value = typeof req.amount === 'bigint' ? req.amount : ethers.parseEther(req.amount.toString().trim());

    // 1. Fetch Nonce — MUST THROW if RPC fails, NEVER default to 0
    let nonce: number;
    try {
      nonce = await this.provider.getTransactionCount(cleanFrom, 'pending');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new SaralError(
        'NONCE_FETCH_FAILED',
        `Failed to retrieve account nonce from RPC for ${cleanFrom}: ${msg}`
      );
    }

    // 2. Fetch Balance — MUST THROW if balance < amount + gas, NEVER skip check
    const balance = await this.getBalance(cleanFrom);
    const feeEstimate = await this.estimateFee(req, fromAddress);
    const totalRequired = value + feeEstimate.feeAtomic;

    if (balance < totalRequired) {
      const shortBy = totalRequired - balance;
      throw new SaralError(
        'INSUFFICIENT_FUNDS',
        `Insufficient funds on ${this.chain.id}. Balance: ${ethers.formatEther(balance)} ${this.chain.symbol}, required: ${ethers.formatEther(totalRequired)} ${this.chain.symbol} (short by ${ethers.formatEther(shortBy)}).`,
        {
          balance: balance.toString(),
          required: totalRequired.toString(),
          shortBy: shortBy.toString(),
          symbol: this.chain.symbol,
        }
      );
    }

    // 3. Determine Transaction Type (Type 0 Legacy or Type 2 EIP-1559)
    const txType = this.chain.defaultTxType ?? 0;
    const chainId = BigInt(this.chain.chainId);

    let unsignedTx: ethers.Transaction;
    if (txType === 2) {
      const feeData = await this.provider.getFeeData();
      unsignedTx = ethers.Transaction.from({
        type: 2,
        to: cleanTo,
        value,
        nonce,
        gasLimit: feeEstimate.gasLimit,
        maxFeePerGas: req.maxFeePerGas ?? feeData.maxFeePerGas ?? ethers.parseUnits('2', 'gwei'),
        maxPriorityFeePerGas:
          req.maxPriorityFeePerGas ?? feeData.maxPriorityFeePerGas ?? ethers.parseUnits('1', 'gwei'),
        chainId,
        data: req.memo ? ethers.hexlify(ethers.toUtf8Bytes(req.memo)) : undefined,
      });
    } else {
      unsignedTx = ethers.Transaction.from({
        type: 0,
        to: cleanTo,
        value,
        nonce,
        gasLimit: feeEstimate.gasLimit,
        gasPrice: feeEstimate.gasPrice,
        chainId,
        data: req.memo ? ethers.hexlify(ethers.toUtf8Bytes(req.memo)) : undefined,
      });
    }

    const unsignedSerialized = unsignedTx.unsignedSerialized;
    const hashToSign = ethers.getBytes(ethers.keccak256(unsignedSerialized));
    const rawBytes = ethers.getBytes(unsignedSerialized);

    return {
      chainId: this.chain.id,
      curve: 'secp256k1',
      rawBytes,
      hashToSign,
      metadata: {
        to: cleanTo,
        from: cleanFrom,
        value: value.toString(),
        nonce,
        gasLimit: (feeEstimate.gasLimit ?? 21000n).toString(),
        gasPrice: (feeEstimate.gasPrice ?? 0n).toString(),
        type: txType,
        chainId: this.chain.chainId,
      },
      expiresAt: Date.now() + 300_000, // 5 minute validity window
    };
  }

  public attachSignature(unsignedTx: UnsignedTx, signature: SignatureResult): SignedTx {
    const rawHex = ethers.hexlify(unsignedTx.rawBytes);
    const baseTx = ethers.Transaction.from(rawHex);

    const yParity: 0 | 1 = signature.yParity === 1 ? 1 : 0;
    const sig = ethers.Signature.from({
      r: signature.r,
      s: signature.s,
      yParity,
    });

    const chainId = BigInt(this.chain.chainId);
    const signedTx = ethers.Transaction.from({
      to: baseTx.to,
      nonce: baseTx.nonce,
      gasLimit: baseTx.gasLimit,
      gasPrice: baseTx.gasPrice,
      maxFeePerGas: baseTx.maxFeePerGas,
      maxPriorityFeePerGas: baseTx.maxPriorityFeePerGas,
      data: baseTx.data,
      value: baseTx.value,
      chainId,
      type: baseTx.type,
      signature: sig,
    });

    const serialized = signedTx.serialized;
    const txHash = signedTx.hash || ethers.keccak256(serialized);

    return {
      chainId: this.chain.id,
      rawTx: serialized,
      txHash,
    };
  }

  public async broadcast(signedTx: SignedTx): Promise<{ txHash: string; status: string }> {
    try {
      const response = await this.provider.broadcastTransaction(signedTx.rawTx);
      return {
        txHash: response.hash,
        status: 'BROADCASTED',
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new SaralError(
        'RPC_ERROR',
        `RPC broadcast failed on ${this.chain.id}: ${msg}`,
        { txHash: signedTx.txHash }
      );
    }
  }

  public async waitForConfirmation(
    txHash: string,
    opts?: { timeoutMs?: number; confirmations?: number }
  ): Promise<ConfirmationResult> {
    const confirmations = opts?.confirmations ?? 1;
    const timeout = opts?.timeoutMs ?? 60_000;

    try {
      const receipt = await this.provider.waitForTransaction(txHash, confirmations, timeout);
      if (!receipt) {
        return { confirmed: false };
      }
      return {
        confirmed: receipt.status === 1,
        blockNumber: receipt.blockNumber,
        confirmations,
      };
    } catch {
      return { confirmed: false };
    }
  }

  public explorerUrl(txHash: string): string {
    const base = this.chain.explorerUrl.replace(/\/+$/, '');
    return `${base}/tx/${txHash}`;
  }
}
