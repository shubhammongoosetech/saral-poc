/**
 * chainService.ts
 *
 * Real Read-Only Multi-Chain Blockchain Integration for SARAL Protocol V3.
 *
 * Supported Networks:
 *   1. MST Testnet (EVM / Chain ID 91562037 / RPC: https://testnetrpc.mstblockchain.com)
 *   2. Solana Devnet (RPC: https://api.devnet.solana.com)
 *   3. Bitcoin Testnet (Taproot / API: https://blockstream.info/testnet/api)
 *
 * Features:
 *   - Live balance retrieval (native token units).
 *   - Live inbound and transaction activity observation.
 *   - Strictly READ-ONLY: accepts only public receive addresses.
 *   - Zero private keys or TSS signing.
 */

export interface InboundTransaction {
  tx_hash: string;
  txHash: string;
  to_address: string;
  toAddress: string;
  amount: string;
  status: 'CONFIRMED' | 'PENDING' | 'FAILED';
  chain: 'mst-testnet' | 'solana-devnet' | 'bitcoin-testnet';
  direction: 'received' | 'sent';
  created_at: string;
  createdAt: string;
  explorerUrl: string;
}

export interface MultiChainBalances {
  mst: string | null;
  solana: string | null;
  bitcoin: string | null;
  lastRefreshedAt: string;
}

// -------------------------------------------------------------
// 1. MST TESTNET (EVM)
// -------------------------------------------------------------
const MST_RPC_URL = process.env.MST_RPC_URL || 'https://testnetrpc.mstblockchain.com';
const MST_EXPLORER_API = 'https://testnet.mstscan.com/api';
const MST_EXPLORER_TX = 'https://testnet.mstscan.com/tx';

export async function getMstBalance(address: string): Promise<string | null> {
  if (!/^0x[0-9a-f]{40}$/i.test(address)) return null;
  try {
    const res = await fetch(MST_RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(5000),
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'eth_getBalance',
        params: [address.trim(), 'latest'],
      }),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as any;
    if (typeof data?.result === 'string' && /^0x[0-9a-f]+$/i.test(data.result)) {
      const wei = BigInt(data.result);
      // Format 18 decimals into human readable ether
      const divisor = 10n ** 18n;
      const whole = wei / divisor;
      const rem = wei % divisor;
      const remStr = rem.toString().padStart(18, '0').replace(/0+$/, '') || '0';
      return `${whole}.${remStr}`;
    }
    return null;
  } catch {
    return null;
  }
}

export async function getMstTransactions(address: string): Promise<InboundTransaction[]> {
  if (!address || !address.startsWith('0x')) return [];
  const results: InboundTransaction[] = [];
  try {
    const url = `${MST_EXPLORER_API}?module=account&action=txlist&address=${encodeURIComponent(address.trim())}&page=1&offset=25&sort=desc`;
    const res = await fetch(url, { signal: AbortSignal.timeout(6000) });
    const data = (await res.json()) as any;
    if (data?.result && Array.isArray(data.result)) {
      const lower = address.trim().toLowerCase();
      for (const tx of data.result) {
        const isReceived = tx.to && tx.to.toLowerCase() === lower;
        const timeSec = Number(tx.timeStamp);
        const iso = !isNaN(timeSec) && timeSec > 0 ? new Date(timeSec * 1000).toISOString() : new Date().toISOString();
        const wei = tx.value ? BigInt(tx.value) : 0n;
        const whole = wei / 10n ** 18n;
        const rem = (wei % 10n ** 18n).toString().padStart(18, '0').slice(0, 4);

        results.push({
          tx_hash: tx.hash,
          txHash: tx.hash,
          to_address: tx.from || address,
          toAddress: tx.from || address,
          amount: `${whole}.${rem}`,
          status: tx.isError === '0' ? 'CONFIRMED' : 'FAILED',
          chain: 'mst-testnet',
          direction: isReceived ? 'received' : 'sent',
          created_at: iso,
          createdAt: iso,
          explorerUrl: `${MST_EXPLORER_TX}/${tx.hash}`,
        });
      }
    }
  } catch (err: any) {
    console.warn('[chainService] MST tx query warning:', err.message);
  }
  return results;
}

// -------------------------------------------------------------
// 2. SOLANA DEVNET
// -------------------------------------------------------------
const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || 'https://api.devnet.solana.com';

export async function getSolanaBalance(address: string): Promise<string | null> {
  if (!address || address.length < 32) return null;
  try {
    const res = await fetch(SOLANA_RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(5000),
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getBalance',
        params: [address.trim()],
      }),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as any;
    const lamports = data?.result?.value;
    if (Number.isSafeInteger(lamports) && lamports >= 0) {
      const units = BigInt(lamports);
      const divisor = 1_000_000_000n;
      return `${units / divisor}.${(units % divisor).toString().padStart(9, '0')}`;
    }
    return null;
  } catch {
    return null;
  }
}

export async function getSolanaTransactions(address: string): Promise<InboundTransaction[]> {
  if (!address || address.length < 32) return [];
  const results: InboundTransaction[] = [];
  try {
    const clean = address.trim();
    const res = await fetch(SOLANA_RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(6000),
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getSignaturesForAddress',
        params: [clean, { limit: 10 }],
      }),
    });
    const data = (await res.json()) as any;
    const sigs: string[] = Array.isArray(data?.result) ? data.result.map((s: any) => s.signature) : [];

    for (const sig of sigs.slice(0, 5)) {
      try {
        const txRes = await fetch(SOLANA_RPC_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          signal: AbortSignal.timeout(4000),
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 2,
            method: 'getTransaction',
            params: [sig, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }],
          }),
        });
        const txData = (await txRes.json()) as any;
        const blockTime = txData?.result?.blockTime;
        const iso = blockTime ? new Date(blockTime * 1000).toISOString() : new Date().toISOString();
        const instructions = txData?.result?.transaction?.message?.instructions || [];

        let amount = '0.0000';
        let fromAddress = 'External';
        for (const ix of instructions) {
          if (ix?.parsed?.type === 'transfer') {
            const info = ix.parsed.info;
            if (info?.destination === clean) {
              const lamports = Number(info.lamports) || 0;
              amount = (lamports / 1e9).toFixed(4);
              fromAddress = info.source || 'External';
              break;
            }
          }
        }

        results.push({
          tx_hash: sig,
          txHash: sig,
          to_address: fromAddress,
          toAddress: fromAddress,
          amount,
          status: 'CONFIRMED',
          chain: 'solana-devnet',
          direction: 'received',
          created_at: iso,
          createdAt: iso,
          explorerUrl: `https://explorer.solana.com/tx/${sig}?cluster=devnet`,
        });
      } catch {}
    }
  } catch (err: any) {
    console.warn('[chainService] Solana tx query warning:', err.message);
  }
  return results;
}

// -------------------------------------------------------------
// 3. BITCOIN TESTNET (Taproot / Bech32m)
// -------------------------------------------------------------
const BTC_TESTNET_API = 'https://blockstream.info/testnet/api';
const BTC_MEMPOOL_API = 'https://mempool.space/testnet/api';

export async function getBitcoinBalance(address: string): Promise<string | null> {
  if (!address || (!address.startsWith('tb1') && !address.startsWith('bc1') && !address.startsWith('m') && !address.startsWith('2'))) {
    return null;
  }
  try {
    let res = await fetch(`${BTC_TESTNET_API}/address/${encodeURIComponent(address.trim())}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      res = await fetch(`${BTC_MEMPOOL_API}/address/${encodeURIComponent(address.trim())}`, {
        signal: AbortSignal.timeout(5000),
      });
    }
    if (res.ok) {
      const data = (await res.json()) as any;
      const chain = data.chain_stats;
      const mempool = data.mempool_stats;
      const values = [chain?.funded_txo_sum, chain?.spent_txo_sum, mempool?.funded_txo_sum, mempool?.spent_txo_sum];
      if (!values.every((value) => Number.isSafeInteger(value) && value >= 0)) return null;
      const [funded, spent, pendingFunded, pendingSpent] = values.map(BigInt);
      const satoshis = funded + pendingFunded - spent - pendingSpent;
      if (satoshis < 0n) return null;
      const divisor = 100_000_000n;
      return `${satoshis / divisor}.${(satoshis % divisor).toString().padStart(8, '0')}`;
    }
    return null;
  } catch {
    return null;
  }
}

export async function getBitcoinTransactions(address: string): Promise<InboundTransaction[]> {
  if (!address || (!address.startsWith('tb1') && !address.startsWith('bc1') && !address.startsWith('m') && !address.startsWith('2'))) {
    return [];
  }
  const results: InboundTransaction[] = [];
  try {
    let res = await fetch(`${BTC_TESTNET_API}/address/${encodeURIComponent(address.trim())}/txs`, {
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) {
      res = await fetch(`${BTC_MEMPOOL_API}/address/${encodeURIComponent(address.trim())}/txs`, {
        signal: AbortSignal.timeout(6000),
      });
    }
    if (res.ok) {
      const txs = (await res.json()) as any[];
      if (Array.isArray(txs)) {
        for (const tx of txs.slice(0, 10)) {
          const status = tx.status?.confirmed ? 'CONFIRMED' : 'PENDING';
          const blockTime = tx.status?.block_time;
          const iso = blockTime ? new Date(blockTime * 1000).toISOString() : new Date().toISOString();

          // Calculate incoming value to this address
          let receivedSat = 0;
          for (const vout of tx.vout || []) {
            if (vout.scriptpubkey_address === address.trim()) {
              receivedSat += Number(vout.value) || 0;
            }
          }

          if (receivedSat > 0) {
            results.push({
              tx_hash: tx.txid,
              txHash: tx.txid,
              to_address: tx.vin?.[0]?.prevout?.scriptpubkey_address || 'Bitcoin Network',
              toAddress: tx.vin?.[0]?.prevout?.scriptpubkey_address || 'Bitcoin Network',
              amount: (receivedSat / 1e8).toFixed(8),
              status,
              chain: 'bitcoin-testnet',
              direction: 'received',
              created_at: iso,
              createdAt: iso,
              explorerUrl: `https://blockstream.info/testnet/tx/${tx.txid}`,
            });
          }
        }
      }
    }
  } catch (err: any) {
    console.warn('[chainService] Bitcoin tx query warning:', err.message);
  }
  return results;
}

// -------------------------------------------------------------
// Combined Live Balances & Activity
// -------------------------------------------------------------
export async function getLiveBalances(addresses: {
  mst?: string;
  solana?: string;
  bitcoin?: string;
}): Promise<MultiChainBalances> {
  const [mst, solana, bitcoin] = await Promise.all([
    addresses.mst ? getMstBalance(addresses.mst) : null,
    addresses.solana ? getSolanaBalance(addresses.solana) : null,
    addresses.bitcoin ? getBitcoinBalance(addresses.bitcoin) : null,
  ]);

  return {
    mst,
    solana,
    bitcoin,
    lastRefreshedAt: new Date().toISOString(),
  };
}

export async function getLiveActivity(addresses: {
  mst?: string;
  solana?: string;
  bitcoin?: string;
}): Promise<InboundTransaction[]> {
  const [mstTxs, solTxs, btcTxs] = await Promise.all([
    addresses.mst ? getMstTransactions(addresses.mst) : Promise.resolve([]),
    addresses.solana ? getSolanaTransactions(addresses.solana) : Promise.resolve([]),
    addresses.bitcoin ? getBitcoinTransactions(addresses.bitcoin) : Promise.resolve([]),
  ]);

  const all = [...mstTxs, ...solTxs, ...btcTxs];
  all.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  return all;
}
