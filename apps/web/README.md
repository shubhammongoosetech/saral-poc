# SARAL MPC Wallet — Frontend

A non-custodial 3-domain MPC wallet with threshold co-signing on MST Testnet (EVM), Solana Devnet (SOL), and Polygon Amoy (MATIC).

## Tooling & TypeScript Note
In `package.json`:
- `@typescript/native`: `npm:typescript@^7.0.2` (runs `npx tsc`)
- `typescript`: `npm:@typescript/typescript6@^6.0.2` (runs `npx tsc6` and provides the TS API for `typescript-eslint`)

> **Note**: This side-by-side alias exists because TypeScript 7.0 does not expose a public programmatic API until TS 7.1. Remove this alias once `typescript-eslint` provides official support for TypeScript >=7.1.

## Production Content Security Policy & Security Headers

### Configurable API URL for Deployment
When building for production, set the `VITE_API_URL` environment variable if your backend API is hosted on a separate domain:
```bash
VITE_API_URL="https://api.yourdomain.com" npm run build
```
Vite's production build plugin (`productionCspPlugin` in `vite.config.ts`) injects `VITE_API_URL` directly into the `connect-src` directive of the generated `dist/index.html`. In local development (`npm run dev`), the strict CSP meta tag is omitted so Vite's dev server (`ws://localhost:5173`, inline scripts, HMR) operates cleanly.

### Production CSP Specification
```http
default-src 'self';
script-src 'self' https://accounts.google.com/gsi/client;
connect-src 'self' https://accounts.google.com https://nominatim.openstreetmap.org [VITE_API_URL];
frame-src https://accounts.google.com;
style-src 'self' 'unsafe-inline' https://accounts.google.com;
font-src 'self';
img-src 'self' data: https://lh3.googleusercontent.com https://*.googleusercontent.com;
object-src 'none';
base-uri 'self';
```

### Trade-off & Justifications
- **`style-src 'unsafe-inline'`**: Required solely because Google Identity Services (GSI) dynamically injects `<style>` blocks into the DOM when rendering the Google Sign-In button and iframe elements. Google GSI generates dynamic styles that change across client environments and does not support nonces or static hashes.
- **`img-src`**: Strictly limited to `'self'`, `data:`, and Google user content hosts (`https://lh3.googleusercontent.com`, `https://*.googleusercontent.com`) for rendering Google account avatars. The wildcard `https:` has been eliminated.
- **Referrer Policy**: The application sets `<meta name="referrer" content="no-referrer" />` globally. Only the OpenStreetMap Nominatim reverse lookup fetch in `useLocation.ts` and `WorkingPolicy.tsx` specifies `{ referrerPolicy: 'origin' }` per OSM usage policy, while all other outgoing requests leak zero referrer data.

### Recommended Reverse Proxy Headers (Nginx / Cloudflare)
```http
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Permissions-Policy: geolocation=(self), camera=(), microphone=()
```

## Backend Follow-ups (Architecture)
1. **Refresh Token Endpoint**: Introduce a dedicated `POST /auth/refresh` endpoint with token rotation so client access tokens can have short lifespans (5–15 minutes).
2. **HttpOnly Cookie Sessions**: Migrate token storage from client `sessionStorage` to `__Host-` prefixed `HttpOnly`, `SameSite=Strict`, `Secure` cookies to fully eliminate XSS token exfiltration risks.
3. **MFA Send Rate Limiting**: Enforce IP/account-level rate limits on `POST /mfa/send` (e.g. maximum 5 requests per hour) on the server to prevent SMS/OTP abuse.
4. **Server-side Session Revocation**: Maintain active session IDs in Redis / DB so that calling `POST /auth/logout` invalidates the token across all backend services immediately.
5. **Reverse Proxy Security Headers**: Ensure the production ingress proxy enforces HSTS, nosniff, and frame-ancestors headers.
