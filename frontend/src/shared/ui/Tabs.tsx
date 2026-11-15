import React from 'react';
import { cn } from '../lib/cn';

export interface TabItem {
  id: string;
  label: string;
  count?: number;
}

export interface TabsProps {
  tabs: TabItem[];
  activeTab: string;
  onChange: (id: string) => void;
  className?: string;
}

export const Tabs: React.FC<TabsProps> = ({ tabs, activeTab, onChange, className }) => {
  return (
    <div
      role="tablist"
      className={cn(
        'inline-flex items-center gap-1 p-1 bg-surface-2 rounded-lg border border-border select-none',
        className
      )}
    >
      {tabs.map((tab) => {
        const isActive = tab.id === activeTab;
        return (
          <button
            key={tab.id}
            role="tab"
            type="button"
            aria-selected={isActive}
            onClick={() => onChange(tab.id)}
            className={cn(
              'flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-all',
              isActive
                ? 'bg-surface text-text shadow-xs font-semibold'
                : 'text-muted hover:text-text'
            )}
          >
            <span>{tab.label}</span>
            {typeof tab.count === 'number' && (
              <span
                className={cn(
                  'px-1.5 py-0.25 text-[10px] rounded-full',
                  isActive ? 'bg-accent/15 text-accent' : 'bg-surface border border-border text-muted'
                )}
              >
                {tab.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
};
