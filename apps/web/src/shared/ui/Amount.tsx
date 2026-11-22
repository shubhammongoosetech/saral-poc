import React from 'react';
import { cn } from '../lib/cn';
import { formatAmount } from '../lib/format';

export interface AmountProps {
  value: string | number | null;
  symbol?: string;
  decimals?: number;
  className?: string;
  valueClassName?: string;
  symbolClassName?: string;
}

export const Amount: React.FC<AmountProps> = ({
  value,
  symbol,
  decimals = 4,
  className,
  valueClassName,
  symbolClassName,
}) => {
  const formatted = value === null ? 'Unavailable' : formatAmount(value, decimals);

  return (
    <span className={cn('inline-flex items-baseline gap-1 font-mono tabular-nums', className)}>
      <span className={cn('min-w-0 break-all font-semibold', valueClassName)}>{formatted}</span>
      {symbol && value !== null && (
        <span className={cn('text-xs font-normal text-muted tracking-wide', symbolClassName)}>
          {symbol}
        </span>
      )}
    </span>
  );
};
