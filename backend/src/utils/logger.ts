/**
 * Structured Logger
 *
 * Provides standardized log formats with timestamp, log level, and component tag.
 * Automatically avoids verbose logging during automated test runs.
 */

type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

const isTest = process.env.NODE_ENV === 'test';

function formatMessage(level: LogLevel, tag: string, message: string, meta?: any): string {
  const timestamp = new Date().toISOString();
  const metaStr = meta ? (meta instanceof Error ? `\n${meta.stack || meta.message}` : ` ${JSON.stringify(meta)}`) : '';
  return `[${timestamp}] [${level}] [${tag}] ${message}${metaStr}`;
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

