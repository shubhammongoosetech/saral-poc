# SARAL PROTOCOL V3 — WORKING POLICY ENGINE & CONTEXTUAL ACCESS SECURITY

**Document ID:** `SARAL-SEC-V3-POLICY-003`  
**Classification:** Security Architecture & Policy Enforcement  
**Branch:** `saral-dkg`  
**Status:** Formally Verified  
**Date:** November 19, 2026  

---

## 1. PURPOSE & THREAT MODEL

The SARAL Working Policy Engine provides contextual authorization governing **when** and **where** a user's wallet may be accessed or addresses recomputed. Even if primary credentials and MFA devices are compromised, attackers outside the authorized time window or geographic perimeter cannot access the wallet or interact with the node mesh.

---

## 2. TIME-BASED ACCESS CONTROL

### 2.1 Authoritative Server Time
All time policy evaluations execute server-side using authoritative system time (`new Date()`). Client-provided timestamps are strictly ignored to prevent clock manipulation attacks.

### 2.2 Timezone & Weekday Handling
- Evaluated using IANA timezones (e.g. `Asia/Kolkata`, `America/New_York`, `UTC`) via ECMAScript `Intl.DateTimeFormat`.
- The user's active timezone determines the local hour, minute, and weekday:
  $$\text{CurrentWeekday} \in \{\text{MON}, \text{TUE}, \text{WED}, \text{THU}, \text{FRI}, \text{SAT}, \text{SUN}\}$$

### 2.3 Window Calculations & Overnight Window Support
The policy engine supports both intra-day windows and overnight windows crossing midnight:
- **Normal Window ($T_{\text{start}} \le T_{\text{end}}$):**
  $$\text{Allowed} \iff T_{\text{start}} \le T_{\text{current}} \le T_{\text{end}}$$
- **Overnight Window ($T_{\text{start}} > T_{\text{end}}$):**
  $$\text{Allowed} \iff T_{\text{current}} \ge T_{\text{start}} \lor T_{\text{current}} \le T_{\text{end}}$$
  *(Example: 22:00 to 06:00 is active at 23:30 and 03:00, but denied at 14:00).*

### 2.4 Policy Expiration
Policies support an optional `expiresAt` ISO timestamp. If the server timestamp exceeds `expiresAt`, wallet access is denied fail-closed until an operator renews the policy.

---

## 3. LOCATION-BASED GEOFENCE CONTROL

### 3.1 Haversine Distance Evaluation
When location restriction is enabled, the distance between the client's current coordinates $(\phi_2, \lambda_2)$ and the approved workspace coordinates $(\phi_1, \lambda_1)$ is computed via the Haversine formula:

$$\Delta\phi = \phi_2 - \phi_1, \quad \Delta\lambda = \lambda_2 - \lambda_1$$
$$a = \sin^2\left(\frac{\Delta\phi}{2}\right) + \cos(\phi_1)\cos(\phi_2)\sin^2\left(\frac{\Delta\lambda}{2}\right)$$
$$c = 2 \cdot \text{atan2}\left(\sqrt{a}, \sqrt{1 - a}\right)$$
$$d = R \cdot c \quad (R = 6,371,000 \text{ meters})$$

If $d > \text{radiusMeters}$, access is denied immediately with code 403.

### 3.2 Fail-Closed Location Verification
If a user configures a location restriction, but submits a request without location coordinates (e.g., GPS permission denied by browser), the policy engine **fails closed**:
> `"Location coordinates required by active security policy but were not provided."`

### 3.3 Security Disclosure on Client-Side Spoofing
Browser Geolocation APIs, IP-based geolocation, and client coordinates are subject to device-level spoofing (e.g., mock GPS providers or rooted devices). SARAL Protocol explicitly documents:
- Client coordinates alone do not cryptographically prove physical presence.
- For high-assurance institutional deployments, location policies must be paired with hardware attestation, managed enterprise network boundaries, or hardware security keys.

---

## 4. ACCESS ATTEMPT AUDIT TRAIL

Every policy evaluation logs an immutable record into `AccessLog`:
- User ID
- Timestamp
- Client coordinates (if provided)
- Authorization outcome (`allowed: true/false`)
- Cryptographic reason string
