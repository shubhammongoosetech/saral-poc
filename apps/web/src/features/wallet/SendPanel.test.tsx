import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { walletApi } from '@/shared/api/endpoints';
import { HttpError } from '@/services/httpClient';
import { SendPanel } from './SendPanel';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function submitTransaction(onSent: () => void) {
  render(<SendPanel balance="5" onSent={onSent} />);
  fireEvent.change(screen.getByLabelText('To'), { target: { value: `0x${'1'.repeat(40)}` } });
  fireEvent.change(screen.getByLabelText('Amount'), { target: { value: '1' } });
  fireEvent.click(screen.getByRole('button', { name: 'Review' }));
  fireEvent.click(screen.getByRole('button', { name: 'Confirm & Send' }));
}

describe('transaction confirmation', () => {
  it('shows the unavailable signing status without reporting a transaction as sent', async () => {
    vi.spyOn(walletApi, 'signTransaction').mockRejectedValue(new HttpError(501, 'Not Implemented', {
      code: 'SIGNING_UNAVAILABLE',
    }));
    const onSent = vi.fn();

    submitTransaction(onSent);

    await screen.findByText('Transaction signing is unavailable');
    expect(onSent).not.toHaveBeenCalled();
    expect(screen.queryByText('Transaction sent')).toBeNull();
  });

  it('requires broadcast confirmation even if a response includes a hash', async () => {
    vi.spyOn(walletApi, 'signTransaction').mockResolvedValue({ txHash: 'unconfirmed', broadcasted: false });
    const onSent = vi.fn();

    submitTransaction(onSent);

    await screen.findByText('Unable to confirm transaction broadcast.');
    expect(onSent).not.toHaveBeenCalled();
  });

  it('renders sent confirmation and triggers onSent when transaction broadcast succeeds', async () => {
    const fakeTxHash = '0x' + 'a'.repeat(64);
    vi.spyOn(walletApi, 'signTransaction').mockResolvedValue({
      txHash: fakeTxHash,
      broadcasted: true,
      chain: 'mst-testnet',
      toAddress: `0x${'1'.repeat(40)}`,
      amount: '1',
    });
    const onSent = vi.fn();

    submitTransaction(onSent);

    await screen.findByText('Transaction sent');
    expect(screen.getByText('Transaction broadcasted successfully.')).toBeDefined();
    expect(screen.getByText(fakeTxHash)).toBeDefined();
    expect(onSent).toHaveBeenCalledTimes(1);
  });
});
