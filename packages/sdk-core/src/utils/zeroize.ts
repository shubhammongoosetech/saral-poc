/**
 * Securely overwrites a byte buffer with zeroes in memory.
 */
export function zeroize(buf: Uint8Array | null | undefined): void {
  if (buf && typeof buf.fill === 'function') {
    buf.fill(0);
  }
}

