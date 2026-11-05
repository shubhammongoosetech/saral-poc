# UI Redesign Decisions: Simple, Calm, Human-Centered SARAL Wallet

Date: 2026-11-05
Author: Senior Product Designer & Full-Stack Engineer

---

## 1. Principles & Objectives

The previous UI looked like an overloaded technical demo: 9 navbar tabs, technology subtitles on every screen, internal cryptographic parameters (Shamir $n$ and $k$, HRW hashes, DKG rounds, Byzantine fault tolerances, slashing invariants), complex modals, and over 265 scattered inline CSS styles.

The redesign transforms the interface into a **clean, white, calm, easy-to-use wallet** that any normal person understands in 10 seconds.

### Key Rules Followed:
1. **Zero backend logic changes**: All backend security checks, working policy enforcement, MFA, and MPC threshold operations remain 100% intact.
2. **Four top-level navigation items**: `SARAL` (brand, text only) on the left, and `Wallet`, `Activity`, `Settings`, `Logout` on the right.
3. **Streamlined First-Time Flow**: `Sign in -> Enter code -> Working hours -> Confirm -> Wallet`.
4. **Instant Returning-User Flow**: `Sign in -> Enter code -> Wallet`. (If working policy fails, a clear inline alert is shown with no technical jargon).
5. **Consolidated Settings**: Working policy, devices, guardians, recovery, and advanced technical data (key storage and network security) are merged into one comprehensive `Settings` page.
6. **Zero Inline Styles**: 100% of inline `style={{ ... }}` blocks are eliminated in favor of a lean, modular `<250` line stylesheet (`index.css`).
7. **Zero Jargon**: Technical jargon (FIG., HRW, MPC, DKG, epoch, domain, invariants, Byzantine, enclave, sovereign, rendezvous, slashing, protocol, patent) is removed from all primary user screens and replaced with plain language ("Key storage", "Network security", "Protection rule", "Send", "Confirm").

---

## 2. Route & Screen Consolidation

| Previous Route / Tab | New Location | Description / Behavior |
| :--- | :--- | :--- |
| **Navbar (9 items)** | **Top bar (4 items)** | `SARAL` (left), `Wallet`, `Activity`, `Settings`, `Logout` (right). |
| **Send & Sign (`/review`)** | **`Wallet` (`/wallet`)** | Send form with two inputs (To, Amount) placed directly under the wallet balance. |
| **Review (`/review`)** | **`Confirm` (`/review`)** | First-time session confirmation only (Login method, Two-step, Working hours, Location) with one "Confirm" button. |
| **Policy Gate (`/working-policy`)** | **`Settings > Working hours and location`** | Accessible during first-time onboarding at `/working-policy` and editable under Settings. |
| **Devices & Guardians (`/devices`)** | **`Settings > Devices and guardians`** | Consolidated into Settings with a clean table, device/guardian enrollment, and revoke controls. Old route `/devices` redirects to `/settings`. |
| **Recovery (`/recovery`)** | **`Settings > Recovery`** | Timelock countdown, Cancel button, and emergency restore options inside Settings. Old route `/recovery` redirects to `/settings`. |
| **Topology (`/topology`)** | **`Settings > Advanced > Key storage`** | Read-only container and node distribution view inside a collapsed `<details>` section. Old route `/topology` redirects to `/settings`. |
| **Economics & Staking (`/security`)** | **`Settings > Advanced > Network security`** | Read-only security stats and token pool overview inside a collapsed `<details>` section. Old route `/security` redirects to `/settings`. |
| **Activity Log (`/activity`)** | **`Activity` (`/activity`)** | Human-readable 3-column table: Time, What happened, Result. |

---

## 3. Screen-by-Screen Simplification

### 3.1 Sign In (`/login`)
- **Title**: `Sign in`.
- **Content**: Clean vertical layout with `Continue with Google` and a mobile phone number input with `Send code`.
- **Subtitles & Jargon**: All explanatory subtitles ("Access your non-custodial decentralized key container") and technical badges removed.

### 3.2 Two-Step Code (`/mfa`)
- **Title**: `Enter code`.
- **Content**: A single 6-digit text input, one `Verify` button, and a `Resend code` link with a 30-second countdown.
- **Returning User Behavior**: Once MFA is verified, the system automatically checks working hours and location. If allowed, the user is navigated directly to `/wallet`. If blocked, a clear message is displayed: *"Access allowed only during your working time and location."* No intrusive popups or full-screen modal overlays.

### 3.3 Working Hours (`/working-policy`)
- **Title**: `Working hours`.
- **Content**: Start time, End time, and City. One `Save` button.
- **Background Handling**: Automatically retains geographic coordinates and radius in the background without cluttering the screen with technical inputs.

### 3.4 Confirm (`/review`)
- **Title**: `Confirm`.
- **Content**: Clean two-column summary:
  - Login method
  - Two-step
  - Working hours
  - Location
- **Action**: One `Confirm` button that navigates directly to `/wallet`.

### 3.5 Wallet (`/wallet`)
- **Header**: Shortened public address (e.g. `0x71C...829a`) with one-click copy button, and current balance in MSTC.
- **First Time**: A prominent `Create wallet` button. After creation, this button disappears permanently.
- **Send Form**: Exactly two inputs (`To` recipient address and `Amount` in MSTC), a `Send` button, and a concise success link displaying the transaction on MSTScan.
- **Recent Transactions**: A clean 4-column table: Date, Recipient, Amount, Status. If empty: *"No transactions yet."*
- **Component Breakdown**:
  - `WalletHeader.tsx` (< 70 lines)
  - `SendForm.tsx` (< 110 lines)
  - `TransactionList.tsx` (< 90 lines)
  - `Wallet.tsx` (< 140 lines)

### 3.6 Activity (`/activity`)
- **Title**: `Activity`.
- **Structure**: Clean table with three columns:
  - **Time**: Formatted local date and time.
  - **What happened**: Plain English action descriptions (e.g., "Signed in", "Sent 0.01 MSTC", "Access check").
  - **Result**: Human-friendly status ("Success", "Blocked: outside working hours", "Pending").
- **Exclusions**: No event-type badges, no internal error codes, and no cryptographic hash strings in the main table.

### 3.7 Settings (`/settings`)
Single cohesive page structured into plain sections with standard `<h2>` headings:
1. **Account**: Login method, registered contact, and "Sign out everywhere" button.
2. **Working hours and location**: Editable fields for start time, end time, and city with a "Save changes" button.
3. **Devices and guardians**: Table of authorized devices and guardians with options to add or revoke.
4. **Recovery**: Emergency recovery initialization, active timelock countdown timer, and immediate "Cancel request" challenge button.
5. **Advanced** (collapsed by default `<details>`):
   - **Key storage**: Read-only display of participating nodes and protection containers.
   - **Network security**: Read-only display of network stake, security ratio, and insurance reserve.

---

## 4. Design System & CSS Architecture

A streamlined, unified stylesheet (`frontend/src/index.css`) under 250 lines replaces all previous inline styles:
- **Palette**:
  - Background: `#ffffff`
  - Text Primary: `#111827` (slate-900)
  - Text Muted: `#6b7280` (slate-500)
  - Border: `#e5e7eb` (slate-200)
  - Accent / Button Primary: `#1d4ed8` (blue-700)
  - Accent Hover: `#1e40af` (blue-800)
  - Danger / Error: `#dc2626`
  - Success: `#16a34a`
- **Typography**: System font stack (`system-ui, -apple-system, BlinkMacSystemFont, sans-serif`).
- **Spacing**: Strict 8px grid (8px, 16px, 24px, 32px).
- **Zero Glassmorphism / Zero Heavy Shadows**: Minimal `0 1px 2px rgba(0,0,0,0.05)` for cards.
- **Zero Inline Styles**: Completely clean JSX with semantic CSS classes.

