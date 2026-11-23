import { defineConfig } from 'vitest/config';

const dbUrl = process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('@postgres:')
  ? process.env.DATABASE_URL
  : 'postgresql://saral:saral_secret@localhost:5432/saral';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.{ts,tsx}'],
    env: {
      DATABASE_URL: dbUrl,
    },
  },
});
