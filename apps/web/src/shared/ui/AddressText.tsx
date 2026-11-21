import React from 'react';
import { cn } from '../lib/cn';
import { truncateAddress } from '../lib/format';
import { CopyButton } from './CopyButton';

export interface AddressTextProps {
  address: string;
  startChars?: number;
  endChars?: number;
  copyable?: boolean;
  className?: string;
}

export const AddressText: React.FC<AddressTextProps> = ({
  address,
  startChars = 6,
  endChars = 4,
  copyable = false,
  className,
}) => {
  if (!address) {
    return (
      <span className={cn('inline-flex items-center font-mono text-xs text-muted/60 italic', className)}>
        Unavailable
      </span>
    );
  }

  const truncated = truncateAddress(address, startChars, endChars);

  return (
    <span className={cn('inline-flex items-center gap-1.5 font-mono text-xs', className)}>
      <span title={address} className="select-all">
        {truncated}
      </span>
      {copyable && <CopyButton text={address} />}
    </span>
  );
};
