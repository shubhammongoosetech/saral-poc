import React from 'react';
import { cn } from '../lib/cn';

export interface IconButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  label: string;
}

export const IconButton: React.FC<IconButtonProps> = ({
  className,
  label,
  children,
  ...props
}) => {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={cn(
        'inline-flex items-center justify-center w-8 h-8 rounded-lg text-muted hover:text-text hover:bg-surface-2 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
};
