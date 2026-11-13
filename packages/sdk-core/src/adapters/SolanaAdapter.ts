import {
  Connection,
  PublicKey,
  SystemProgram,
  TransactionMessage,
  VersionedTransaction,
} from '@solana/web3.js';
import { sha256 } from '@noble/hashes/sha256';
import { SolanaChainConfig } from '../types/chain';
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

const LAMPORTS_PER_SOL = 1_000_000_000n;
const ESTIMATED_SOL_FEE = 5000n; // 5000 lamports standard signature fee

export class SolanaAdapter implements ChainAdapter {
  public readonly chain: SolanaChainConfig;
  private readonly connection: Connection;

  constructor(chain: SolanaChainConfig, connection?: Connection) {
    this.chain = chain;
    this.connection = connection || new Connection(chain.rpcUrl, 'confirmed');
  }

  public getConnection(): Connection {
    return this.connection;
  }

  public deriveAddress(publicKey: Uint8Array | string): string {
    try {
      if (typeof publicKey === 'string') {
        // If already base58 string
        if (!publicKey.startsWith('0x') && publicKey.length >= 32 && publicKey.length <= 44) {
          return new PublicKey(publicKey).toBase58();
        }
        const hex = publicKey.startsWith('0x') ? publicKey.slice(2) : publicKey;
        const bytes = Buffer.from(hex, 'hex');
        return new PublicKey(bytes).toBase58();
      }
      return new PublicKey(publicKey).toBase58();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new SaralError('INVALID_CONFIG', `Failed to derive Solana address: ${msg}`);
    }
  }

  public validateAddress(address: string): boolean {
    try {
      const pubkey = new PublicKey(address.trim());
      return pubkey.toBytes().length === 32;
    } catch {
      return false;
    }
  }

  public async getBalance(address: string): Promise<bigint> {
    try {
      const pubkey = new PublicKey(address.trim());
      const balance = await this.connection.getBalance(pubkey);
      return BigInt(balance);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new SaralError(
        'RPC_ERROR',
        `Failed to fetch live balance for ${address} on Solana (${this.chain.id}): ${msg}`
      );
    }
  }

  public async estimateFee(_req: PaymentRequest, _fromAddress: string): Promise<FeeEstimate> {
    const feeAtomic = ESTIMATED_SOL_FEE;
    const solDecimal = (Number(feeAtomic) / 1e9).toFixed(9);
    return {
      feeAtomic,
      feeFormatted: solDecimal,
    };
  }

  public async buildUnsignedTx(req: PaymentRequest, fromAddress: string): Promise<UnsignedTx> {
    const fromPubkey = new PublicKey(fromAddress.trim());
    const toPubkey = new PublicKey(req.to.trim());

    // Amount parsing (SOL decimal string or raw lamports bigint)
    let lamports: bigint;
    if (typeof req.amount === 'bigint') {
      lamports = req.amount;
    } else {
      const parsedFloat = parseFloat(req.amount.toString().trim());
      if (isNaN(parsedFloat) || parsedFloat <= 0) {
        throw new SaralError('INVALID_CONFIG', `Invalid SOL amount: ${req.amount}`);
      }
      lamports = BigInt(Math.round(parsedFloat * 1e9));
    }

    // 1. Balance verification
    const balance = await this.getBalance(fromAddress);
    const totalRequired = lamports + ESTIMATED_SOL_FEE;
    if (balance < totalRequired) {
      const shortBy = totalRequired - balance;
      throw new SaralError(
        'INSUFFICIENT_FUNDS',
        `Insufficient funds on Solana. Balance: ${Number(balance) / 1e9} SOL, required: ${Number(totalRequired) / 1e9} SOL (short by ${Number(shortBy) / 1e9} SOL).`,
        {
          balance: balance.toString(),
          required: totalRequired.toString(),
          shortBy: shortBy.toString(),
          symbol: 'SOL',
        }
      );
    }

    // 2. Fetch Latest Blockhash & Track lastValidBlockHeight
    let latestBlockhash;
    try {
      latestBlockhash = await this.connection.getLatestBlockhash('confirmed');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new SaralError('RPC_ERROR', `Failed to fetch latest blockhash from Solana RPC: ${msg}`);
    }

    const { blockhash, lastValidBlockHeight } = latestBlockhash;

    // 3. Build Versioned Transaction Message
    const transferIx = SystemProgram.transfer({
      fromPubkey,
      toPubkey,
      lamports,
    });

    const v0Message = new TransactionMessage({
      payerKey: fromPubkey,
      recentBlockhash: blockhash,
      instructions: [transferIx],
    }).compileToV0Message();

    const serializedMessage = v0Message.serialize();
    const hashToSign = sha256(serializedMessage);

    return {
      chainId: this.chain.id,
      curve: 'ed25519',
      rawBytes: serializedMessage,
      hashToSign,
      metadata: {
        from: fromPubkey.toBase58(),
        to: toPubkey.toBase58(),
        lamports: lamports.toString(),
        blockhash,
        lastValidBlockHeight,
        memo: req.memo,
        req,
      },
      // Solana blockhashes are valid for ~150 slots (~60-90 seconds)
      expiresAt: Date.now() + 60_000,
    };
  }

  /**
   * Rebuilds transaction automatically if blockhash has expired before signing completes.
   */
  public async rebuildIfExpired(unsignedTx: UnsignedTx, fromAddress: string): Promise<UnsignedTx> {
    const lastValidBlockHeight = unsignedTx.metadata?.lastValidBlockHeight as number | undefined;
    if (lastValidBlockHeight) {
      try {
        const currentHeight = await this.connection.getBlockHeight('confirmed');
        if (currentHeight > lastValidBlockHeight) {
          const req = unsignedTx.metadata.req as PaymentRequest;
          return await this.buildUnsignedTx(req, fromAddress);
        }
      } catch {
        // Fall back to timestamp expiration
      }
    }

    if (unsignedTx.expiresAt && Date.now() > unsignedTx.expiresAt) {
      const req = unsignedTx.metadata.req as PaymentRequest;
      return await this.buildUnsignedTx(req, fromAddress);
    }

    return unsignedTx;
  }

  public attachSignature(unsignedTx: UnsignedTx, signature: SignatureResult): SignedTx {
    const fromPubkey = new PublicKey(unsignedTx.metadata.from as string);
    const v0Message = TransactionMessage.decompile(
      VersionedTransaction.deserialize(unsignedTx.rawBytes).message
    ).compileToV0Message();

    const tx = new VersionedTransaction(v0Message);
    tx.addSignature(fromPubkey, signature.rawBytes);

    const serialized = tx.serialize();
    const rawTxBase64 = Buffer.from(serialized).toString('base64');
    const txHash = Buffer.from(signature.rawBytes).toString('hex');

    return {
      chainId: this.chain.id,
      rawTx: rawTxBase64,
      txHash,
    };
  }

  public async broadcast(signedTx: SignedTx): Promise<{ txHash: string; status: string }> {
    try {
      const rawBytes = Buffer.from(signedTx.rawTx, 'base64');
      const txSignature = await this.connection.sendRawTransaction(rawBytes, {
        skipPreflight: false,
        preflightCommitment: 'confirmed',
      });

      return {
        txHash: txSignature,
        status: 'BROADCASTED',
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new SaralError(
        'RPC_ERROR',
        `Solana RPC broadcast failed on ${this.chain.id}: ${msg}`,
        { txHash: signedTx.txHash }
      );
    }
  }

  public async waitForConfirmation(
    txHash: string,
    opts?: { timeoutMs?: number; confirmations?: number }
  ): Promise<ConfirmationResult> {
    try {
      const confirmation = await this.connection.confirmTransaction(
        txHash,
        'confirmed'
      );
      if (confirmation.value.err) {
        return { confirmed: false };
      }
      return { confirmed: true };
    } catch {
      return { confirmed: false };
    }
  }

  public explorerUrl(txHash: string): string {
    const clusterParam = this.chain.cluster === 'mainnet-beta' ? '' : `?cluster=${this.chain.cluster}`;
    return `${this.chain.explorerUrl}/tx/${txHash}${clusterParam}`;
  }
}

