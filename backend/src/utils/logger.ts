/**
 * Structured Logger with Automatic Redaction Filter
 *
 * Provides standardized log formats with timestamp, log level, and component tag.
 * Automatically masks any Ethereum addresses (0x[a-fA-F0-9]{40}) and public key hex strings
 * to prevent leakage into logs or disk.
 */

type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

const isTest = process.env.NODE_ENV === 'test';

const ETH_ADDRESS_REGEX = /0x[a-fA-F0-9]{40}/g;
const UNCOMPRESSED_PUBKEY_REGEX = /(?:0x)?04[a-fA-F0-9]{128}/gi;
const COMPRESSED_PUBKEY_REGEX = /(?:0x)?0[23][a-fA-F0-9]{64}/gi;

export function redactSensitive(input: string): string {
  if (!input || typeof input !== 'string') return input;
  return input
    .replace(ETH_ADDRESS_REGEX, '[REDACTED_ADDRESS]')
    .replace(UNCOMPRESSED_PUBKEY_REGEX, '[REDACTED_PUBKEY]')
    .replace(COMPRESSED_PUBKEY_REGEX, '[REDACTED_PUBKEY]');
}

function formatMessage(level: LogLevel, tag: string, message: string, meta?: any): string {
  const timestamp = new Date().toISOString();
  const metaStr = meta
    ? meta instanceof Error
      ? `\n${meta.stack || meta.message}`
      : ` ${JSON.stringify(meta)}`
    : '';
  const raw = `[${timestamp}] [${level}] [${tag}] ${message}${metaStr}`;
  return redactSensitive(raw);
}

export const logger = {
  debug(tag: string, message: string, meta?: any): void {
    if (!isTest && process.env.DEBUG) {
      console.debug(formatMessage('DEBUG', tag, message, meta));
    }
  },

  info(tag: string, message: string, meta?: any): void {
    if (!isTest) {
      console.log(formatMessage('INFO', tag, message, meta));
    }
  },

  warn(tag: string, message: string, meta?: any): void {
    console.warn(formatMessage('WARN', tag, message, meta));
  },

  error(tag: string, message: string, meta?: any): void {
    console.error(formatMessage('ERROR', tag, message, meta));
  },
};


