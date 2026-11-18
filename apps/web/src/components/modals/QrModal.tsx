import React, { useState } from 'react';

export const QrModal: React.FC<{
  chainName: string;
  address: string;
  network: string;
  onClose: () => void;
}> = ({ chainName, address, network, onClose }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="w-full max-w-sm bg-surface border border-border rounded-2xl p-6 shadow-xl flex flex-col gap-5">
        <div className="flex items-center justify-between">
          <div className="flex flex-col">
            <h2 className="text-sm font-bold text-text">{chainName}</h2>
            <span className="text-[11px] text-muted">{network}</span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="w-7 h-7 rounded-lg bg-surface-2 text-muted hover:text-text flex items-center justify-center text-sm cursor-pointer"
          >
            ✕
          </button>
        </div>

        {/* QR Representation */}
        <div className="flex flex-col items-center justify-center p-4 rounded-xl bg-white text-black border border-border shadow-xs">
          <div className="w-48 h-48 border-4 border-black p-2 flex flex-col items-center justify-center gap-2 select-none">
            <div className="grid grid-cols-6 gap-1 w-full h-full p-2">
              {Array.from({ length: 36 }).map((_, i) => (
                <div
                  key={i}
                  className={`rounded-xs ${
                    (i * 7 + 3) % 2 === 0 || i === 0 || i === 5 || i === 30 || i === 35
                      ? 'bg-black'
                      : 'bg-neutral-200'
                  }`}
                />
              ))}
            </div>
          </div>
          <span className="text-[10px] text-neutral-600 font-mono mt-2 uppercase tracking-wider">
            Scan to receive
          </span>
        </div>

        {/* Address & Copy */}
        <div className="flex flex-col gap-2">
          <span className="text-[11px] font-semibold text-muted">Public Address:</span>
          <div className="p-2.5 rounded-xl bg-surface-2 border border-border font-mono text-xs text-text break-all select-all">
            {address}
          </div>
        </div>

        <button
          type="button"
          onClick={handleCopy}
          className="w-full h-10 bg-accent text-accent-contrast rounded-xl text-xs font-semibold hover:bg-accent-hover transition-colors cursor-pointer flex items-center justify-center"
        >
          {copied ? 'Copied to Clipboard! ✓' : 'Copy Full Address'}
        </button>
      </div>
    </div>
  );
};
