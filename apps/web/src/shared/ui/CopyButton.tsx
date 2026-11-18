import React, { useState } from 'react';
import { cn } from '../lib/cn';
import { CopyIcon, CheckIcon } from './icons';

export interface CopyButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  text: string;
  variant?: 'icon' | 'pill' | 'button';
  label?: string;
  copiedLabel?: string;
}

export const CopyButton: React.FC<CopyButtonProps> = ({
  text,
  variant = 'icon',
  label = 'Copy',
  copiedLabel = 'Copied',
  className,
  ...props
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async (e: React.MouseEvent<HTMLButtonElement>) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // fallback if clipboard api fails
    }
  };

  if (variant === 'pill') {
    return (
      <button
        type="button"
        onClick={handleCopy}
        aria-label={copied ? copiedLabel : label}
        className={cn(
          'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium border transition-colors select-none',
          copied
            ? 'bg-success/15 border-success/30 text-success'
            : 'bg-surface-2 border-border text-muted hover:text-text hover:bg-surface-2/80',
          className
        )}
        {...props}
      >
        {copied ? (
          <>
            <CheckIcon className="w-3.5 h-3.5 text-success" />
            <span>{copiedLabel}</span>
          </>
        ) : (
          <>
            <CopyIcon className="w-3.5 h-3.5" />
            <span>{label}</span>
          </>
        )}
      </button>
    );
  }

  if (variant === 'button') {
    return (
      <button
        type="button"
        onClick={handleCopy}
        className={cn(
          'inline-flex items-center justify-center gap-2 h-9 px-3 rounded-lg text-xs font-medium border border-border bg-surface-2 text-text hover:bg-surface-2/80 transition-colors',
          className
        )}
        {...props}
      >
        {copied ? (
          <>
            <CheckIcon className="w-4 h-4 text-success" />
            <span>{copiedLabel}</span>
          </>
        ) : (
          <>
            <CopyIcon className="w-4 h-4 text-muted" />
            <span>{label}</span>
          </>
        )}
      </button>
    );
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label={copied ? copiedLabel : label}
      title={copied ? copiedLabel : label}
      className={cn(
        'inline-flex items-center justify-center w-7 h-7 rounded-md text-muted hover:text-text hover:bg-surface-2 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent',
        copied && 'text-success hover:text-success',
        className
      )}
      {...props}
    >
      {copied ? <CheckIcon className="w-3.5 h-3.5 text-success" /> : <CopyIcon className="w-3.5 h-3.5" />}
    </button>
  );
};
