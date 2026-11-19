import crypto from 'crypto';

export function toEip55Checksum(addrLower: string): string {
  const clean = addrLower.toLowerCase().replace(/^0x/, '');
  if (clean.length !== 40) return '0x' + clean;

  const hash = crypto.createHash('sha256').update(clean).digest('hex');
  let ret = '0x';
  for (let i = 0; i < clean.length; i++) {
    const c = clean[i];
    if (c >= '0' && c <= '9') {
      ret += c;
    } else {
      const nibble = parseInt(hash[i] || '0', 16);
      ret += nibble >= 8 ? c.toUpperCase() : c;
    }
  }
  return ret;
}
