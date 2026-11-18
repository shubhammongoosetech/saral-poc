import React, { useState } from 'react';
import { useSession } from '../../context/SessionContext';
import { AppLayout } from '../layout/AppLayout';
import { QrModal } from '../modals/QrModal';

export const WalletHomeView: React.FC<{ onNavigateToSettings: () => void }> = ({
  onNavigateToSettings,
}) => {
  const { user, wallet, policy } = useSession();

  const [activeQr, setActiveQr] = useState<{ chain: string; address: string; network: string } | null>(
    null
  );
  const [copiedChain, setCopiedChain] = useState<string | null>(null);

  const copyAddress = (chainKey: string, address: string) => {
    navigator.clipboard.writeText(address);
    setCopiedChain(chainKey);
    setTimeout(() => setCopiedChain(null), 2000);
  };

  const displayName = user?.name || user?.email || user?.mobile || 'SARAL Operator';

  const chainCards = [
    {
      key: 'mst',
      name: 'MST Blockchain',
      network: 'mst-testnet',
      badge: 'EVM Sovereign',
      curve: 'secp256k1',
      description: 'EVM-compatible sovereign chain with Keccak-256 and EIP-55 checksum',
      address: wallet?.addresses?.mst?.address || '0x71C...3aF',
      status: wallet?.addresses?.mst?.status || 'ACTIVE_VERIFIED',
    },
    {
      key: 'solana',
      name: 'Solana Devnet',
      network: 'solana-devnet',
      badge: 'Ed25519',
      curve: 'ed25519',
      description: 'High-speed layer 1 using native 32-byte Ed25519 public key and Base58 encoding',
      address: wallet?.addresses?.solana?.address || '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d',
      status: wallet?.addresses?.solana?.status || 'ACTIVE_VERIFIED',
    },
    {
      key: 'bitcoin',
      name: 'Bitcoin Taproot',
      network: 'bitcoin-mainnet',
      badge: 'BIP-340/350',
      curve: 'secp256k1',
      description: 'BIP-340 even-Y x-only key with BIP-341 output tweak and BIP-350 Bech32m prefix (bc1p...)',
      address:
        wallet?.addresses?.bitcoin?.address ||
        'bc1p5d7rjq7g6rd22kyveejm9cfr0nvyt0d47lqwh8crds3w6pdcqugq8nxq0v',
      status: wallet?.addresses?.bitcoin?.status || 'ACTIVE_VERIFIED',
    },
  ];

  return (
    <AppLayout activeTab="wallet" onTabChange={(t) => t === 'settings' && onNavigateToSettings()}>
      <div className="flex flex-col gap-6">
        {/* User Identity & Security Summary Header */}
        <div className="p-6 rounded-2xl bg-surface border border-border shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-2xl bg-accent/10 border border-accent/20 flex items-center justify-center text-accent font-bold text-xl select-none">
              {displayName.charAt(0).toUpperCase()}
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold text-text tracking-tight">{displayName}</h1>
                <span className="text-[10px] font-semibold bg-success/10 text-success border border-success/30 px-2 py-0.5 rounded-full">
                  Wallet Ready
                </span>
              </div>
              <div className="flex items-center gap-3 text-xs text-muted font-mono mt-0.5">
                <span>User: {user?.id.slice(0, 12)}...</span>
                <span>•</span>
                <span>Method: {user?.loginMethod}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onNavigateToSettings}
              className="px-3.5 py-2 rounded-xl bg-surface-2 border border-border text-xs font-semibold text-text hover:bg-border/60 transition-colors cursor-pointer flex items-center gap-1.5"
            >
              ⚙️ Security & Policy Settings
            </button>
          </div>
        </div>

        {/* Working Policy Status Banner */}
        {policy?.timeRestrictionEnabled && (
          <div className="p-4 rounded-xl bg-surface-2 border border-border flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="w-2.5 h-2.5 rounded-full bg-success animate-pulse" />
              <div className="flex flex-col">
                <span className="text-xs font-bold text-text">
                  Working Policy Active: {policy.startTime} - {policy.endTime} ({policy.timezone})
                </span>
                <span className="text-[11px] text-muted">
                  Allowed Days: {policy.days.join(', ')}
                  {policy.locationRestrictionEnabled ? ` • Geofence: ${policy.allowedRegion}` : ''}
                </span>
              </div>
            </div>
            <button
              type="button"
              onClick={onNavigateToSettings}
              className="text-xs font-semibold text-accent hover:underline cursor-pointer"
            >
              Modify
            </button>
          </div>
        )}

        {/* Multi-Chain Address Cards */}
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-text tracking-tight uppercase tracking-wider text-muted text-xs">
              Supported Blockchain Addresses
            </h2>
            <span className="text-xs text-muted">
              Zero private keys stored in central database
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4">
            {chainCards.map((c) => (
              <div
                key={c.key}
                className="p-5 rounded-2xl bg-surface border border-border shadow-xs flex flex-col gap-3.5 hover:border-accent/40 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className="text-base font-bold text-text">{c.name}</span>
                    <span className="text-[10px] font-semibold bg-surface-2 text-muted px-2 py-0.5 rounded-full border border-border">
                      {c.badge}
                    </span>
                    <span className="text-[10px] font-mono text-muted">({c.curve})</span>
                  </div>
                  <span className="text-xs font-semibold text-success flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-success" />
                    Receiving Ready
                  </span>
                </div>

                <p className="text-xs text-muted leading-relaxed">{c.description}</p>

                {/* Address Box */}
                <div className="p-3 rounded-xl bg-surface-2 border border-border flex items-center justify-between gap-3">
                  <span className="font-mono text-xs text-text break-all select-all font-medium">
                    {c.address}
                  </span>
                </div>

                {/* Actions */}
                <div className="flex items-center justify-between pt-1 border-t border-border/60">
                  <button
                    type="button"
                    onClick={() => setActiveQr({ chain: c.name, address: c.address, network: c.network })}
                    className="text-xs font-semibold text-text hover:text-accent transition-colors cursor-pointer flex items-center gap-1"
                  >
                    View QR Code ➔
                  </button>
                  <button
                    type="button"
                    onClick={() => copyAddress(c.key, c.address)}
                    className="px-3 py-1.5 rounded-lg bg-surface border border-border text-xs font-semibold text-accent hover:bg-accent/10 transition-colors cursor-pointer"
                  >
                    {copiedChain === c.key ? 'Copied to Clipboard! ✓' : 'Copy Address'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Cryptographic Security Invariants Notice */}
        <div className="p-4 rounded-xl bg-surface-2 border border-border text-xs text-muted flex flex-col gap-1.5">
          <span className="font-bold text-text text-xs">SARAL Separation-of-Powers Guarantee:</span>
          <p className="leading-relaxed text-[11px]">
            Your private keys are never stored on this device, the coordinator, or the application database.
            They are generated via Asynchronous Verifiable Secret Sharing (AVSS) and Dealerless Distributed Key Generation (DKG) across 15 independent Go node processes in Foundation, Public, and Private domains.
          </p>
        </div>
      </div>

      {activeQr && (
        <QrModal
          chainName={activeQr.chain}
          address={activeQr.address}
          network={activeQr.network}
          onClose={() => setActiveQr(null)}
        />
      )}
    </AppLayout>
  );
};
