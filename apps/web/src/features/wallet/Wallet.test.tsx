import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { walletApi } from '@/shared/api/endpoints';
import { HttpError } from '@/services/httpClient';
import { Wallet } from './Wallet';

vi.mock('@/features/auth/useSession', () => ({
  useSession: () => ({ token: `header.${btoa(JSON.stringify({ userId: 'wallet-user' }))}.signature` }),
}));

vi.mock('@/shared/api/endpoints', () => ({
  walletApi: { getWallet: vi.fn(), getTransactions: vi.fn(), generateWallet: vi.fn() },
}));

const readyWallet = {
  hasWallet: true,
  wallet: { status: 'READY' as const, address: 'mst', solanaAddress: 'solana', bitcoinAddress: 'bitcoin' },
};

function renderWallet() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Wallet />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('wallet lifecycle', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(walletApi.getTransactions).mockResolvedValue({ transactions: [] });
  });

  it('reloads an unavailable wallet without offering creation', async () => {
    vi.mocked(walletApi.getWallet)
      .mockRejectedValueOnce(new HttpError(503, 'Unavailable', { error: 'Unable to derive addresses' }))
      .mockResolvedValue(readyWallet);

    renderWallet();
    fireEvent.click(await screen.findByRole('button', { name: 'Reload Wallet' }));

    expect(screen.queryByRole('button', { name: 'Create Wallet' })).toBeNull();
    await screen.findByRole('button', { name: 'Receive / QR' });
    expect(walletApi.generateWallet).not.toHaveBeenCalled();
  });

  it('shows the setup in progress without generating a second wallet', async () => {
    vi.mocked(walletApi.getWallet).mockResolvedValue({
      hasWallet: true,
      wallet: { walletId: 'wallet-1', status: 'DKG_IN_PROGRESS' },
    });

    renderWallet();
    expect(await screen.findByRole('status')).toHaveProperty('textContent', 'Wallet setup is in progress.');
    expect(screen.queryByRole('button', { name: 'Create Wallet' })).toBeNull();
    expect(walletApi.getTransactions).not.toHaveBeenCalled();
  });

  it('shows the migration message for an unavailable wallet without an action to replace it', async () => {
    vi.mocked(walletApi.getWallet).mockResolvedValue({
      hasWallet: true,
      wallet: { status: 'UNAVAILABLE', error: 'Existing wallet requires migration.' },
    });

    renderWallet();
    await screen.findByText('Existing wallet requires migration.');
    expect(screen.queryByRole('button')).toBeNull();
    expect(walletApi.getTransactions).not.toHaveBeenCalled();
  });

  it('reloads the server state after a lost create response', async () => {
    vi.mocked(walletApi.getWallet)
      .mockResolvedValueOnce({ hasWallet: false, wallet: null })
      .mockResolvedValue(readyWallet);
    vi.mocked(walletApi.generateWallet).mockRejectedValue(new DOMException('Timed out', 'AbortError'));

    renderWallet();
    fireEvent.click(await screen.findByRole('button', { name: 'Create Wallet' }));

    await screen.findByRole('button', { name: 'Receive / QR' });
    await waitFor(() => expect(walletApi.getWallet).toHaveBeenCalledTimes(2));
    expect(walletApi.generateWallet).toHaveBeenCalledTimes(1);
  });
});
