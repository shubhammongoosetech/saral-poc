import React, { useState } from 'react';
import { useSession } from '../../context/SessionContext';
import { AuthLayout } from '../layout/AuthLayout';
import { QrModal } from '../modals/QrModal';

export const WalletCreatedSuccessView: React.FC<{ onComplete: () => void }> = ({ onComplete }) => {
  const { wallet } = useSession();

  const [activeQr, setActiveQr] = useState<{ chain: string; address: string; network: string } | null>(
    null
  );
  const [copiedChain, setCopiedChain] = useState<string | null>(null);

  const copyAddress = (chainKey: string, address: string) => {
    navigator.clipboard.writeText(address);
    setCopiedChain(chainKey);
    setTimeout(() => setCopiedChain(null), 2000);
  };

  const chains = [
    {
      key: 'mst',
      name: 'MST Blockchain',
      network: 'mst-testnet',
      badge: 'EVM Sovereign',
      curve: 'secp256k1',
      address: wallet?.addresses?.mst?.address || '0x...',
      explorerUrl: wallet?.addresses?.mst?.explorerUrl,
    },
    {
      key: 'solana',
      name: 'Solana Devnet',
      network: 'solana-devnet',
      badge: 'Ed25519',
      curve: 'ed25519',
      address: wallet?.addresses?.solana?.address || '5eykt4UsF...',
      explorerUrl: wallet?.addresses?.solana?.explorerUrl,
    },
    {
      key: 'bitcoin',
      name: 'Bitcoin Testnet',
      network: 'bitcoin-testnet',
      badge: 'BIP-340/350',
      curve: 'secp256k1',
      address: wallet?.addresses?.bitcoin?.address || 'tb1p...',
      explorerUrl: wallet?.addresses?.bitcoin?.explorerUrl,
    },
  ];

  return (
    <AuthLayout subtitle="Institutional-Grade Distributed Security with Zero Complete Private Key Stored in Database">
      <div className="flex flex-col gap-5">
        <div className="flex flex-col items-center text-center gap-1.5">
          <div className="w-12 h-12 rounded-full bg-success/10 text-success flex items-center justify-center font-bold text-2xl mb-1">
            ✓
          </div>
          <h1 className="text-xl font-bold text-text tracking-tight">
            Your SARAL Wallet Is Ready
          </h1>
          <p className="text-xs text-muted">
            Three independent blockchain addresses derived from distributed threshold key material.
          </p>
        </div>

        {/* 3 Chain Address Cards */}
        <div className="flex flex-col gap-3">
          {chains.map((c) => (
            <div
              key={c.key}
              className="p-3.5 rounded-xl bg-surface-2 border border-border flex flex-col gap-2"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-text">{c.name}</span>
                  <span className="text-[10px] font-semibold bg-surface text-muted px-1.5 py-0.5 rounded border border-border">
                    {c.badge}
                  </span>
                </div>
                <span className="text-[10px] text-success font-semibold flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-success" />
                  Verified
                </span>
              </div>

              <div className="p-2 rounded-lg bg-surface border border-border font-mono text-xs text-text break-all select-all">
                {c.address}
              </div>

              <div className="flex items-center justify-between pt-1">
                <button
                  type="button"
                  onClick={() => setActiveQr({ chain: c.name, address: c.address, network: c.network })}
                  className="text-xs text-muted hover:text-text font-medium cursor-pointer"
                >
                  View QR ➔
                </button>
                <button
                  type="button"
                  onClick={() => copyAddress(c.key, c.address)}
                  className="text-xs font-semibold text-accent hover:underline cursor-pointer"
                >
                  {copiedChain === c.key ? 'Copied!' : 'Copy Address'}
                </button>
              </div>
            </div>
          ))}
        </div>

        <button
          type="button"
          onClick={onComplete}
          className="w-full h-11 bg-accent text-accent-contrast rounded-xl text-sm font-semibold hover:bg-accent-hover transition-colors shadow-xs cursor-pointer flex items-center justify-center"
        >
          Go to SARAL Wallet Home ➔
        </button>
      </div>

      {activeQr && (
        <QrModal
          chainName={activeQr.chain}
          address={activeQr.address}
          network={activeQr.network}
          onClose={() => setActiveQr(null)}
        />
      )}
    </AuthLayout>
  );
};
