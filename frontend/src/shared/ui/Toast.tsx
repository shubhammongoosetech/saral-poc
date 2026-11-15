import React, { createContext, useContext, useState, useCallback } from 'react';
import { cn } from '../lib/cn';
import { CheckIcon, AlertCircleIcon, XIcon } from './icons';

export interface ToastItem {
  id: string;
  message: string;
  variant?: 'info' | 'success' | 'error' | 'warning';
}

interface ToastContextValue {
  showToast: (message: string, variant?: ToastItem['variant']) => void;
  dismissToast: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const showToast = useCallback(
    (message: string, variant: ToastItem['variant'] = 'info') => {
      const id = Math.random().toString(36).substring(2, 9);
      setToasts((prev) => [...prev, { id, message, variant }]);
      setTimeout(() => {
        dismissToast(id);
      }, 3500);
    },
    [dismissToast]
  );

  return (
    <ToastContext.Provider value={{ showToast, dismissToast }}>
      {children}
      <div
        aria-live="polite"
        className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none px-4 sm:px-0"
      >
        {toasts.map((toast) => (
          <div
            key={toast.id}
            role="status"
            className={cn(
              'pointer-events-auto flex items-center justify-between gap-3 p-3.5 rounded-xl border shadow-lg text-sm bg-surface animate-in fade-in slide-in-from-bottom-2 duration-200',
              toast.variant === 'error' && 'border-danger/30 text-danger',
              toast.variant === 'success' && 'border-success/30 text-success',
              toast.variant === 'warning' && 'border-warning/30 text-warning',
              (!toast.variant || toast.variant === 'info') && 'border-border text-text'
            )}
          >
            <div className="flex items-center gap-2 min-w-0">
              {toast.variant === 'success' && <CheckIcon className="w-4 h-4 flex-shrink-0" />}
              {toast.variant === 'error' && <AlertCircleIcon className="w-4 h-4 flex-shrink-0" />}
              <span className="truncate text-xs font-medium text-text">{toast.message}</span>
            </div>
            <button
              type="button"
              onClick={() => dismissToast(toast.id)}
              className="text-muted hover:text-text p-1 -mr-1"
              aria-label="Dismiss"
            >
              <XIcon className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};

export const useToast = () => {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error('useToast must be used within ToastProvider');
  }
  return ctx;
};
