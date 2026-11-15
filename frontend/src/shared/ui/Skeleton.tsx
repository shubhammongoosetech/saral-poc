import React from 'react';
import { cn } from '../lib/cn';

export type SkeletonProps = React.HTMLAttributes<HTMLDivElement>;

export const Skeleton: React.FC<SkeletonProps> = ({ className, ...props }) => {
  return (
    <div
      className={cn('animate-pulse rounded-md bg-surface-2', className)}
      aria-hidden="true"
      {...props}
    />
  );
};

export interface SpinnerProps extends React.SVGAttributes<SVGSVGElement> {
  size?: 'sm' | 'md' | 'lg';
}

export const Spinner: React.FC<SpinnerProps> = ({ size = 'md', className, ...props }) => {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-5 h-5',
    lg: 'w-8 h-8',
  };

  return (
    <svg
      className={cn('animate-spin text-accent', sizeClasses[size], className)}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      aria-label="Loading"
      role="status"
      {...props}
    >
      <circle cx="12" cy="12" r="10" strokeOpacity="0.2" />
      <path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round" />
    </svg>
  );
};
