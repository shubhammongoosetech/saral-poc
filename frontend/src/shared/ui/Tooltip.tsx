import React, { useState } from 'react';
import { cn } from '../lib/cn';

export interface TooltipProps {
  content: React.ReactNode;
  children: React.ReactElement<{
    onMouseEnter?: (e: React.MouseEvent) => void;
    onMouseLeave?: (e: React.MouseEvent) => void;
    onFocus?: (e: React.FocusEvent) => void;
    onBlur?: (e: React.FocusEvent) => void;
    'aria-describedby'?: string;
  }>;
  className?: string;
}

export const Tooltip: React.FC<TooltipProps> = ({ content, children, className }) => {
  const [visible, setVisible] = useState(false);

  const trigger = React.cloneElement(children, {
    onMouseEnter: (e: React.MouseEvent) => {
      children.props.onMouseEnter?.(e);
      setVisible(true);
    },
    onMouseLeave: (e: React.MouseEvent) => {
      children.props.onMouseLeave?.(e);
      setVisible(false);
    },
    onFocus: (e: React.FocusEvent) => {
      children.props.onFocus?.(e);
      setVisible(true);
    },
    onBlur: (e: React.FocusEvent) => {
      children.props.onBlur?.(e);
      setVisible(false);
    },
    'aria-describedby': visible ? 'tooltip-content' : undefined,
  });

  return (
    <span className="relative inline-flex">
      {trigger}
      {visible && (
        <span
          id="tooltip-content"
          role="tooltip"
          className={cn(
            'absolute bottom-full left-1/2 -translate-x-1/2 mb-1.5 px-2 py-1 bg-surface-2 border border-border text-text text-[11px] rounded shadow-md whitespace-nowrap z-50 pointer-events-none',
            className
          )}
        >
          {content}
        </span>
      )}
    </span>
  );
};
