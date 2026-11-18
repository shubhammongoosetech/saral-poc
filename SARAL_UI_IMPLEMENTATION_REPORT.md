# SARAL PROTOCOL V3 — MINIMAL SECURE WALLET UI IMPLEMENTATION REPORT

**Document ID:** `SARAL-UI-V3-FRONTEND-006`  
**Classification:** Frontend Engineering & User Experience Design  
**Branch:** `saral-dkg`  
**Status:** Formally Verified  
**Date:** November 19, 2026  

---

## 1. DESIGN PHILOSOPHY & VISUAL LANGUAGE

Following the visual design language of `saral-ui-rebuild`, the SARAL Wallet UI implements an institutional-grade, minimalist Web3 user experience. The interface eliminates all extraneous trading, swapping, token transfer, staking, NFT, and developer debugging panels, focusing exclusively on secure wallet onboarding, policy control, and multi-chain address viewing.

### Key Visual Tokens:
- **Background:** `#0E1014` (Dark mode default), `#F5F6F8` (Light mode)
- **Surfaces:** `#161920` (Card container), `#1D212A` (Secondary surface)
- **Borders:** `#2A2F3A`
- **Primary Accent:** `#2FC4A6` (Emerald / Mint highlight), `#0C7A66` (Light mode)
- **Typography:** Inter Variable font with clean monospace accents for addresses and numeric data.

---

## 2. COMPONENT ARCHITECTURE & USER JOURNEY SCREENS

```
apps/web/src/
├── App.tsx                                    # State machine & active gate resolver
├── context/
│   └── SessionContext.tsx                     # Global session state & gatekeeper
├── services/
│   └── authApi.ts                             # Typed client to Auth Server & Coordinators
├── types/
│   └── auth.ts                                # User, Session, Policy & Wallet interfaces
└── components/
    ├── layout/
    │   ├── AuthLayout.tsx                     # Centered minimal card with SARAL badge
    │   └── AppLayout.tsx                      # Header, user badge, theme toggle, logout
    ├── modals/
    │   └── QrModal.tsx                        # High-contrast QR code inspection modal
    └── views/
        ├── WelcomeLoginView.tsx               # Screen 1: Google OIDC & Phone input
        ├── OtpVerificationView.tsx            # Screen 2: 6-digit OTP input with timer
        ├── MfaView.tsx                        # Screen 3: TOTP setup/verify & recovery codes
        ├── WorkingPolicyView.tsx              # Screen 4: Time window & geofence setup
        ├── WalletCreateProgressView.tsx       # Screen 5: Real 8-step DKG progress tracker
        ├── WalletCreatedSuccessView.tsx       # Screen 6: "Your SARAL Wallet Is Ready"
        ├── WalletHomeView.tsx                 # Screen 7: SARAL Wallet Home & Chain Cards
        ├── SettingsView.tsx                   # Security & Working Policy Settings
        └── AccessRestrictedView.tsx           # Contextual policy lockout screen
```

---

## 3. SCREEN SPECIFICATIONS & USER EXPERIENCE

### Screen 1: Welcome / Login (`WelcomeLoginView`)
- Brand Header: Emerald 'S' mark + "SARAL" wordmark.
- Heading: "Welcome to SARAL Wallet".
- Primary Actions:
  - "Continue with Google"
  - "Continue with Phone Number" (+91 10-digit input).

### Screen 2: OTP Verification (`OtpVerificationView`)
- Displays masked phone number (e.g. `+91 98765 ****0`).
- 6 individual numeric input boxes with auto-focus, paste parsing, and auto-submit.
- 30-second resend countdown timer.
- "Change number" action.

### Screen 3: Second-Factor MFA (`MfaView`)
- Enrollment Mode (First-Time): Displays Authenticator QR URI, manual base32 secret, and 8 one-time backup recovery codes with "Copy All" convenience.
- Verification Mode (Returning): 6-digit challenge with toggle to use a backup recovery code (`XXXX-XXXX`).

### Screen 4: Working Policy Setup (`WorkingPolicyView`)
- Time restriction toggles, start/end time inputs, weekday selector (Mon-Sun), and IANA timezone indicator.
- Location restriction toggles, workspace name, GPS "Detect Location" button, and radius slider (1–100 km).
- Guardrail alert banner warning user of potential lockout outside authorized parameters.

### Screen 5: Wallet Creation Progress (`WalletCreateProgressView`)
- Displays real 8-step cryptographic progress checklist:
  1. Identity verified
  2. Security policy verified
  3. Node committee ready (15 nodes across Foundation, Public, Private)
  4. AVSS sharing in progress
  5. DKG contributions verified
  6. Distributed key material secured in node vaults
  7. Blockchain public keys verified
  8. Multi-chain wallet addresses generated
- Resumable: reconnecting or refreshing the page checks `/wallet/status` without restarting.

### Screen 6: Wallet Created Successfully (`WalletCreatedSuccessView`)
- Success confirmation banner.
- 3 chain cards: MST Blockchain, Solana Devnet, Bitcoin Taproot.
- Verified addresses, copy buttons, and "View QR" triggers.
- "Go to SARAL Wallet Home" action button.

### Screen 7: SARAL Wallet Home (`WalletHomeView`)
- Minimal top bar with user identity badge, session status, and active policy indicator.
- 3 supported chain cards (MST, Solana, Bitcoin Taproot) with one-click copy and QR inspection.
- Separation-of-Powers cryptographic guarantee notice.
- Clean navigation to Security & Policy Settings and Logout.
- **NO** trade, swap, send, transfer, staking, NFT, or raw developer debugging panels.

### Access Restricted Screen (`AccessRestrictedView`)
- Rendered when a user accesses the wallet outside of their configured working policy.
- Shows exact policy violation reason (e.g., outside permitted hours or outside geofence perimeter).
- "Retry Verification" and "Log out" buttons.
