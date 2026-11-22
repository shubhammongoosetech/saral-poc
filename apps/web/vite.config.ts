import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';

function productionCspPlugin(apiUrl = ''): Plugin {
  return {
    name: 'production-csp',
    transformIndexHtml(html, ctx) {
      // Only inject strict CSP meta tag in production bundle output
      if (!ctx.bundle) return html;

      const extraConnect = apiUrl.trim() ? ` ${apiUrl.trim()}` : '';
      const cspPolicy = [
        "default-src 'self'",
        "script-src 'self' https://accounts.google.com/gsi/client",
        `connect-src 'self' https://accounts.google.com https://nominatim.openstreetmap.org${extraConnect}`,
        "frame-src 'self' https://accounts.google.com",
        "style-src 'self' 'unsafe-inline' https://accounts.google.com",
        "font-src 'self' data:",
        "img-src 'self' data: https://lh3.googleusercontent.com https://*.googleusercontent.com",
        "object-src 'none'",
        "base-uri 'self'",
      ].join('; ');

      const metaTag = `<meta http-equiv="Content-Security-Policy" content="${cspPolicy};" />`;
      return html.replace('</head>', `  ${metaTag}\n  </head>`);
    },
  };
}

export default defineConfig(() => {
  const apiUrl = process.env.VITE_API_URL || '';

  return {
    plugins: [
      react(),
      tailwindcss(),
      productionCspPlugin(apiUrl),
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },
    server: {
      port: 5173,
      proxy: {
        '/api': {
          target: 'http://localhost:3001',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, ''),
        },
        '/auth': {
          target: 'http://localhost:3001',
          changeOrigin: true,
        },
      },
    },
    esbuild: {
      target: 'es2022',
    },
    optimizeDeps: {
      esbuildOptions: {
        target: 'es2022',
      },
    },
    build: {
      target: 'es2022',
      sourcemap: false,
    },
  };
});
