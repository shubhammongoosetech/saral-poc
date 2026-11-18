import React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../lib/cn';

const badgeVariants = cva(
  'inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium tracking-wide uppercase select-none',
  {
    variants: {
      variant: {
        neutral: 'bg-surface-2 text-muted border border-border',
        testnet: 'bg-accent/10 text-accent border border-accent/20',
        confirmed: 'bg-success/10 text-success border border-success/20',
        pending: 'bg-warning/10 text-warning border border-warning/20',
        failed: 'bg-danger/10 text-danger border border-danger/20',
      },
      size: {
        sm: 'text-[10px] px-1.5 py-0.25',
        md: 'text-xs px-2 py-0.5',
      },
    },
    defaultVariants: {
      variant: 'neutral',
      size: 'md',
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {
  dot?: boolean;
}

export const Badge: React.FC<BadgeProps> = ({
  className,
  variant,
  size,
  dot = false,
  children,
  ...props
}) => {
  return (
    <span className={cn(badgeVariants({ variant, size }), className)} {...props}>
      {dot && (
        <span
          className={cn(
            'w-1.5 h-1.5 rounded-full flex-shrink-0',
            variant === 'confirmed' && 'bg-success',
            variant === 'pending' && 'bg-warning animate-pulse motion-reduce:animate-none',
            variant === 'failed' && 'bg-danger',
            variant === 'testnet' && 'bg-accent',
            (!variant || variant === 'neutral') && 'bg-muted'
          )}
          aria-hidden="true"
        />
      )}
      <span>{children}</span>
    </span>
  );
};
