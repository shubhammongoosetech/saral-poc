import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { QrCode } from './QrCode';

describe('local QR generation', () => {
  it('encodes the authenticator setup URI into an inline image', async () => {
    const uri = 'otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&issuer=Test';
    render(<QrCode value={uri} label="Setup code" size={180} />);

    const source = (await screen.findByRole('img', { name: 'Setup code' })).getAttribute('src');
    expect(source).toMatch(/^data:image\/svg\+xml,/);
    expect(decodeURIComponent(source ?? '')).toContain('<svg');
    expect(decodeURIComponent(source ?? '')).not.toContain(uri);
  });
});
