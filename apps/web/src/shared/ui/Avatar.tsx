import React from 'react';
import { cn } from '../lib/cn';

export interface AvatarProps {
  seed: string;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

function hashCode(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

// Flat colors derived strictly from theme accent and neutral tokens (no purple, no pink)
const FLAT_COLORS = [
  '#0c7a66', // accent
  '#0f766e', // teal-700
  '#115e59', // teal-800
  '#1e293b', // slate-800
  '#334155', // slate-700
  '#0369a1', // sky-700
];

export const Avatar: React.FC<AvatarProps> = ({ seed, size = 'md', className }) => {
  const hash = hashCode(seed || 'saral');
  const bgColor = FLAT_COLORS[hash % FLAT_COLORS.length];

  const sizeClasses = {
    sm: 'w-6 h-6 text-[10px]',
    md: 'w-8 h-8 text-xs',
    lg: 'w-10 h-10 text-sm',
  };

  const initial = (seed.slice(0, 2).replace(/^0x/i, '') || 'S').toUpperCase().slice(0, 1);

  return (
    <div
      role="img"
      aria-label={`Avatar for ${seed}`}
      className={cn(
        'rounded-full flex items-center justify-center font-bold text-white select-none flex-shrink-0',
        sizeClasses[size],
        className
      )}
      style={{ backgroundColor: bgColor }}
    >
      <span>{initial}</span>
    </div>
  );
};
