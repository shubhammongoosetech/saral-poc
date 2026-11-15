import React, { useRef, useEffect } from 'react';
import { cn } from '../lib/cn';

export interface OtpInputProps {
  length?: number;
  value: string;
  onChange: (value: string) => void;
  onComplete?: (value: string) => void;
  error?: boolean;
  disabled?: boolean;
  autoFocus?: boolean;
  className?: string;
}

export const OtpInput: React.FC<OtpInputProps> = ({
  length = 6,
  value,
  onChange,
  onComplete,
  error = false,
  disabled = false,
  autoFocus = false,
  className,
}) => {
  const inputsRef = useRef<(HTMLInputElement | null)[]>([]);

  // Split value into an array of characters padded to length
  const digits = Array.from({ length }, (_, i) => value[i] || '');

  useEffect(() => {
    if (autoFocus && inputsRef.current[0]) {
      inputsRef.current[0].focus();
    }
  }, [autoFocus]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>, index: number) => {
    const val = e.target.value.replace(/\D/g, '');
    if (!val) {
      // Deletion handled in onKeyDown, but if cleared here:
      const newDigits = [...digits];
      newDigits[index] = '';
      const updated = newDigits.join('');
      onChange(updated);
      return;
    }

    // If single digit entered:
    const digit = val[val.length - 1]; // take last entered digit
    const newDigits = [...digits];
    newDigits[index] = digit;
    const updated = newDigits.join('');
    onChange(updated);

    if (index < length - 1) {
      inputsRef.current[index + 1]?.focus();
    }

    if (updated.length === length && onComplete) {
      onComplete(updated);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>, index: number) => {
    if (e.key === 'Backspace') {
      if (!digits[index] && index > 0) {
        // Move back and clear previous
        inputsRef.current[index - 1]?.focus();
        const newDigits = [...digits];
        newDigits[index - 1] = '';
        onChange(newDigits.join(''));
        e.preventDefault();
      } else {
        const newDigits = [...digits];
        newDigits[index] = '';
        onChange(newDigits.join(''));
        e.preventDefault();
      }
    } else if (e.key === 'ArrowLeft' && index > 0) {
      inputsRef.current[index - 1]?.focus();
      e.preventDefault();
    } else if (e.key === 'ArrowRight' && index < length - 1) {
      inputsRef.current[index + 1]?.focus();
      e.preventDefault();
    }
  };

  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, length);
    if (!pasted) return;

    onChange(pasted);
    const nextIndex = Math.min(pasted.length, length - 1);
    inputsRef.current[nextIndex]?.focus();

    if (pasted.length === length && onComplete) {
      onComplete(pasted);
    }
  };

  return (
    <div
      role="group"
      aria-label="One-time code"
      className={cn('flex items-center justify-between gap-2', className)}
    >
      {Array.from({ length }, (_, i) => (
        <input
          key={i}
          ref={(el) => {
            inputsRef.current[i] = el;
          }}
          type="text"
          inputMode="numeric"
          autoComplete={i === 0 ? 'one-time-code' : 'off'}
          pattern="[0-9]*"
          maxLength={1}
          value={digits[i]}
          disabled={disabled}
          onChange={(e) => handleChange(e, i)}
          onKeyDown={(e) => handleKeyDown(e, i)}
          onPaste={handlePaste}
          aria-label={`Digit ${i + 1}`}
          className={cn(
            'w-11 h-12 text-center text-xl font-mono font-medium rounded-lg bg-surface-2 border transition-colors select-none',
            'focus:outline-none focus:ring-2 focus:ring-accent focus:border-accent',
            'disabled:opacity-50 disabled:cursor-not-allowed',
            error ? 'border-danger text-danger focus:ring-danger' : 'border-border text-text'
          )}
        />
      ))}
    </div>
  );
};
