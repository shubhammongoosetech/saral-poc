# SARAL Wallet

A full-stack non-custodial cryptographic key management system and wallet built with React (TypeScript), Node.js (TypeScript Express), PostgreSQL, and the ethers v6 library.

SARAL implements a **3-Container Separation of Powers** architecture with **Shamir Secret Sharing (SSS)** and **Adaptive Location/Working Hours Access Policies**.

---

## 1. Tech Stack

- **Frontend**: React + TypeScript (Vite), React Router, Axios
- **Backend**: Node.js + TypeScript, Express, `pg` for PostgreSQL, ethers v6, `jsonwebtoken`, `zod` validation, `helmet`, `express-rate-limit`
- **Secret Sharing**: Shamir Secret Sharing (`secrets.js-grempe`)
- **Encryption**: AES-256-GCM authenticated encryption for all stored shares
- **Auth**: Google OAuth 2.0 and Mobile number + OTP with Two-Factor MFA
- **Blockchain**: MST Testnet (Chain ID: 11155111, RPC: `https://testnetrpc.mstblockchain.com`)

---

## 2. Folder Structure

```
saral-wallet/
  backend/
    src/
      config/        (env.ts, db.ts)
      routes/        (auth.ts, mfa.ts, profile.ts, wallet.ts)
      controllers/   (authController.ts, mfaController.ts, profileController.ts, walletController.ts)
      services/      (authService.ts, mfaService.ts, locationService.ts, walletService.ts, shamirService.ts, chainService.ts)
      middleware/    (authGuard.ts, errorHandler.ts)
      db/            (schema.sql, migrations/001_initial_schema.sql)
      utils/         (crypto.ts, jwt.ts, validation.ts)
      app.ts, server.ts
    .env.example
    package.json, tsconfig.json
  frontend/
    src/
      pages/         (Login.tsx, Mfa.tsx, WorkingPolicy.tsx, Review.tsx, Wallet.tsx)
      components/    (Navbar.tsx)
      api/           (client.ts, endpoints.ts)
      hooks/         (useAuth.ts, useLocation.ts)
      App.tsx, main.tsx
      index.css
    package.json, tsconfig.json
  README.md
```

---

## 3. Database Schema (PostgreSQL)

The database schema implements the following tables:
- `users(id, google_id, mobile, login_method, created_at)`
- `mfa(id, user_id, type, verified_at)`
- `work_policy(id, user_id, start_time, end_time, timezone, city, lat, lng, radius_km, set_at)`
- `wallets(id, user_id, address, public_key, created_at)`
- `key_shares(id, user_id, category, share_index, encrypted_share, n, threshold, created_at)`
- `access_logs(id, user_id, attempted_at, lat, lng, allowed, reason)`
- `transactions(id, user_id, tx_hash, to_address, amount, created_at)`
- `otps(id, user_id, code, purpose, expires_at, used, created_at)`

---

## 4. Setup Instructions

### Prerequisites
- Node.js (v18+) and npm
- PostgreSQL running locally on port 5432

### Step 1: Clone and Install Dependencies
```bash
# In the repository root
npm install

# Install backend dependencies
cd backend && npm install

# Install frontend dependencies
cd ../frontend && npm install
cd ..
```

### Step 2: Configure Environment Variables
Copy the example environment file to `backend/.env`:
```bash
cp backend/.env.example backend/.env
```

Verify `backend/.env` contents:
```env
PORT=3001
NODE_ENV=development
DATABASE_URL=postgresql://postgres:secret@localhost:5432/saral
JWT_SECRET=saral_dev_jwt_secret_key_2024_change_me
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:5173/login
SMS_PROVIDER_KEY=dev-sms-key
RPC_URL=https://testnetrpc.mstblockchain.com
CHAIN_ID=11155111
MASTER_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
SHARE_TOTAL_N=9
SHARE_THRESHOLD=5
TIME_TOLERANCE_MINUTES=0
LOCATION_RADIUS_KM=25
```

### Step 3: Run Database Migrations
Execute the schema migration against PostgreSQL:
```bash
# Using psql
PGPASSWORD=secret psql -h localhost -U postgres -d saral -f backend/src/db/schema.sql

# Or using the backend script
npm --prefix backend run db:migrate
```

### Step 4: Run the Application
Run both backend and frontend concurrently:
```bash
npm run dev
```

- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:3001`
- Swagger UI Documentation: `http://localhost:3001/docs`

---

## 5. Security & Cryptographic Architecture

### Key Generation & Container Sharding (Case A)
1. User clicks **Generate Wallet**.
2. Ethers generates an in-memory random wallet (`Wallet.createRandom()`).
3. The 32-byte private key is split across 3 containers using Information-Theoretic 3-way XOR decomposition:
   - `PUBLIC`: 32 random bytes
   - `INSTITUTIONAL`: 32 random bytes
   - `SOVEREIGN`: `privateKey ^ PUBLIC ^ INSTITUTIONAL`
4. Each container part is individually divided into $n$ shares with threshold $k$ (default $n=9$, $k=5$) via Shamir's Secret Sharing.
5. Every share is encrypted with `MASTER_ENCRYPTION_KEY` using AES-256-GCM with independent IVs and auth tags, then written to `key_shares`.
6. **The raw private key and unencrypted parts are wiped from memory immediately.** Only the public address and public key are saved.

### Access Rule Verification & Signing (Case B)
When the user requests to sign a transaction or view the wallet:
1. **MFA Verification**: Session must be authenticated and MFA verified.
2. **Time Window**: Current time in the user's saved timezone must fall between `start_time` and `end_time` (+ tolerance).
3. **Physical Location**: Coordinates sent by the browser must be within `LOCATION_RADIUS_KM` (25 km default) of the saved city coordinates (calculated via the Haversine formula).
4. **Login Method**: Session login method must match the method registered at first login.
5. If **any check fails**: HTTP 403 Forbidden is returned, access is blocked, and an audit row is inserted into `access_logs`.
6. If **all checks pass**: $k$ shares for each of the 3 containers are decrypted, each container is reconstructed, XOR combined to ephemeral memory, the transaction is signed, and the key is instantly discarded.

---

## 6. Test Plan

Follow these steps to test all 5 pages and security gates:

1. **Step 1: First Login (Page 1)**
   - Open `http://localhost:5173/login`.
   - Enter a mobile number (e.g., `+919876543210`) and click **Send OTP**.
   - Check the terminal console for the printed OTP (e.g. `[SMS OTP AUTH] ... CODE: 123456`).
   - Enter the OTP code and click **Verify & Continue**.

2. **Step 2: Second Factor MFA (Page 2)**
   - The app automatically dispatches an MFA OTP code (printed in the terminal console).
   - Enter the 6-digit MFA OTP and click **Verify MFA**.

3. **Step 3: Set Working Policy (Page 3)**
   - Enter permitted working hours: e.g., `10:00` to `23:00` (so it covers your current time).
   - Click **Detect GPS** to capture your coordinates and city (or leave default Indore `22.7196, 75.8577`).
   - Set radius to `25` km.
   - Click **Save Policy & Continue**.

4. **Step 4: Review Summary (Page 4)**
   - Review read-only summary: Login method, MFA status (Verified), Working Time, Working Location.
   - Click **Continue to Wallet**.

5. **Step 5: Generate Wallet (Page 5, Case A)**
   - The page displays "First-Time Setup: Wallet Initialization".
   - (Optional) Toggle "Configure Shamir Parameters" to view or customize $n$ and threshold.
   - Click **Generate Wallet**.
   - The backend splits the key into 3 containers, shards them with Shamir, encrypts with AES-256-GCM, and stores shares in PostgreSQL.
   - The generated wallet address and balance are displayed.

6. **Step 6: Ready to Sign & Send Transaction (Case B)**
   - Because current time and coordinates match the policy, the green banner confirms access authorization.
   - Click **Ready to Sign**.
   - Fill the payment form:
     - Recipient: `0x742d35Cc6634C0532925a3b844Bc454e4438f44e`
     - Amount: `0.001`
   - Click **Sign & Broadcast Transaction**.
   - The transaction hash is displayed with a **Copy** button.

7. **Step 7: Policy Gate Enforcement (Blocked Outside Working Hours)**
   - Click **Logout**.
   - Log back in with the same mobile number and complete MFA.
   - Click **Change Policy** on the review page, and set working hours outside the current time (e.g., `01:00` to `02:00`).
   - Go to `/wallet`.
   - The red alert banner appears: **"Access allowed only during your working time and location"**.
   - The **Ready to Sign** and signing buttons remain disabled.
   - Inspect PostgreSQL `access_logs` table: a rejection audit log row is recorded with `allowed = false`.
# saral-poc
