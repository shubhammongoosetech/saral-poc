import React from 'react';
import { cn } from '../lib/cn';
import { AlertCircleIcon, CheckIcon } from './icons';

export interface AlertProps {
  variant?: 'error' | 'warning' | 'info' | 'success';
  title?: string;
  children: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}

export const Alert: React.FC<AlertProps> = ({
  variant = 'info',
  title,
  children,
  action,
  className,
}) => {
  return (
    <div
      role={variant === 'error' ? 'alert' : 'status'}
      className={cn(
        'flex items-start gap-3 p-3.5 rounded-lg border text-sm',
        variant === 'error' && 'bg-danger/10 border-danger/25 text-danger',
        variant === 'warning' && 'bg-warning/10 border-warning/25 text-warning',
        variant === 'info' && 'bg-accent/10 border-accent/25 text-text',
        variant === 'success' && 'bg-success/10 border-success/25 text-success',
        className
      )}
    >
      <div className="flex-shrink-0 mt-0.5">
        {variant === 'success' ? (
          <CheckIcon className="w-4 h-4 text-success" />
        ) : (
          <AlertCircleIcon
            className={cn(
              'w-4 h-4',
              variant === 'error' && 'text-danger',
              variant === 'warning' && 'text-warning',
              variant === 'info' && 'text-accent'
            )}
          />
        )}
      </div>
      <div className="flex-1 min-w-0">
        {title && <h5 className="font-medium text-xs uppercase tracking-wider mb-0.5">{title}</h5>}
        <div className="text-xs leading-relaxed opacity-90 break-words">{children}</div>
      </div>
      {action && <div className="flex-shrink-0 self-center">{action}</div>}
    </div>
  );
};
