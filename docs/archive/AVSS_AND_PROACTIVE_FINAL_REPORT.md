Category 1: System Ko Start Aur Build Karne Ki Commands
1. Pura 24-Container Mesh Start Karna (Build Ke Sath)

Jab aap pehli baar project start kar rahe hon ya code me koi change kiya ho:

bash
docker compose -f infra/compose/full24.yml up -d --build
Short form (NPM script): npm run docker:full
Kya hota hai?
Docker saare images build karta hai (Node.js Auth Server, 3 Go Verifiers, 15 Go Nodes, 3 Go Coordinators, React Frontend).
-d ka matlab Detached Mode (background me chalana taaki terminal block na ho).
24 ke 24 containers start ho kar saral-mesh network me jud jate hain.
2. Kisi Ek Service Ko Rebuild Karna (Time Bachane Ke Liye)

Agar aapne sirf apps/auth-server ka code badla hai, to poora 24 containers rebuild karne ki zaroorat nahi hai:

bash
docker compose -f infra/compose/full24.yml up -d --build auth-server
Example: Agar aapne services/saral-node ke AVSS code me change kiya, to sirf Node 1 ko restart karein:
bash
docker compose -f infra/compose/full24.yml up -d --build node-f1
Category 2: Health Aur Status Check Karne Ki Commands
3. Saare Containers Ka Status Dekhna
bash
docker compose -f infra/compose/full24.yml ps
Short form: npm run docker:status
Example Output:
text
NAME                         IMAGE                 COMMAND                  SERVICE         STATUS
saral-postgres               postgres:16-alpine    "docker-entrypoint.s…"   postgres        Up (healthy)
saral-prod-auth-server       saral-auth-server     "docker-entrypoint.s…"   auth-server     Up (healthy)
saral-prod-coord-foundation  saral-coordinator     "/app/coordinator"       coord-found…    Up (healthy)
saral-prod-node-f1           saral-node            "/app/saral-node"        node-f1         Up (healthy)
... (baki 20 containers)

Important: Status me Up (healthy) dikhna chahiye. Agar kisi me unhealthy ya Exit dikhe, to matlab us container me koi error aayi hai.

4. Health Endpoints Ko Terminal Se Test Karna

Aap curl command se verify kar sakte hain ki services respond kar rahi hain ya nahi:

bash
# 1. Auth Server health check
curl http://localhost:3001/health
# 2. Foundation Coordinator health check
curl http://localhost:9001/health
# 3. Foundation Verifier health check
curl http://localhost:9101/health
Category 3: Debugging Aur Logs Dekhne Ki Commands
5. Kisi Specific Service Ke Live Logs Dekhna

Debugging ke liye ye sabse zyada use hone wali command hai:

bash
# Auth Server ke live logs dekhna (-f = follow)
docker compose -f infra/compose/full24.yml logs -f auth-server
# Coordinator ke live logs dekhna
docker compose -f infra/compose/full24.yml logs -f coordinator-foundation
# Kisi specific Go Node ke DKG/AVSS logs dekhna
docker compose -f infra/compose/full24.yml logs -f node-f1
Example Output (Node f1 logs):
text
[SARAL Node - FOUNDATION] Identity: saral-foundation-1 (Public Key: 2d89f372...)
[DKG Engine - saral-foundation-1] Session dkg-session-1 created (n=15, k=11, t=2)
[AVSS Engine] Received AVSS_SEND from saral-foundation-2 -> Verified Pedersen Commitment -> Sent AVSS_ECHO
Category 4: Container Ke Andar Ghusna (CLI Debugging)
6. Database (PostgreSQL) Ke Andar Tables Dekhna

Agar aap dekhna chahte hain ki user ka wallet create hua ya nahi:

bash
docker compose -f infra/compose/full24.yml exec postgres psql -U saral -d saral
Container ke andar SQL commands:
sql
-- Saare tables dekhna:
\dt
-- Wallets table check karna (Verify Zero-Address storage):
SELECT user_id, wallet_id, key_references FROM wallets;
-- Bahar aane ke liye:
\q
7. Node Ke Encrypted Vault Ko Check Karna

Dekhne ke liye ki node ne apne cryptographic share ko disk pe encrypt karke save kiya ya nahi:

bash
docker compose -f infra/compose/full24.yml exec node-f1 ls -la /vault
Result: Yahan aapko encrypted share files dikhengi jo AES-256-GCM se lock hoti hain.
Category 5: Stop Aur Clean Reset Commands
8. Containers Ko Normal Stop Karna (Data Bachakar)

Agar aap apna kaam khatam karke system band karna chahte hain (lekin database ka data save rakhna hai):

bash
docker compose -f infra/compose/full24.yml down
Short form: npm run docker:down
Isse containers stop aur remove ho jate hain, lekin database tables aur 15 node vaults safe rehte hain. Jab aap dobara up karoge to data wapas mil jayega.
9. Complete Wipeout / Fresh Reset (Sabse Powerful Command)

Jab aapne DB schema change kiya ho, ya DKG keys corrupt ho gayi hon aur aapko bilkul fresh shuruwat karni ho:

bash
docker compose -f infra/compose/full24.yml down -v
-v ka matlab: Volumes Delete Karo.
Isse kya hota hai?
saral_postgres_data volume delete ho jata hai (Database pura fresh ho jata hai).
node_f1_vault se lekar node_r5_vault tak ke 15 encrypted vaults wipe ho jate hain.
Jab aap dobara up karoge, to init.sql chalega aur poora network naye janam ki tarah fresh start hoga.
Summary Cheat Sheet
Kaam	Command
Pura Mesh Start	docker compose -f infra/compose/full24.yml up -d --build
Status Check	docker compose -f infra/compose/full24.yml ps
Auth Logs Dekhna	docker compose -f infra/compose/full24.yml logs -f auth-server
Node Logs Dekhna	docker compose -f infra/compose/full24.yml logs -f node-f1
Postgres CLI kholna	docker compose -f infra/compose/full24.yml exec postgres psql -U saral -d saral
Normal Band Karna	docker compose -f infra/compose/full24.yml down
Full Reset (Clean Wipe)	docker compose -f infra/compose/full24.yml down -v