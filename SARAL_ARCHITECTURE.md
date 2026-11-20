infra/
├── compose/     -> Docker Compose files (24 containers ko chalane ka remote control)
├── config/      -> Genesis configuration (15 nodes ki pehchan / phonebook)
├── postgres/    -> Database schema & initialization script (init.sql)
├── secrets/     -> Internal admin keys aur security tokens
└── tls/         -> mTLS Certificates (Nodes ke aapas me encrypted baat karne ke passes)

# 1. Pura mesh start kiya
docker compose -f infra/compose/full24.yml up -d
# 2. Sirf auth-server aur web ko stop kar diya (Ports free ho gaye!)
docker compose -f infra/compose/full24.yml stop auth-server web
# 3. Ab local terminal me chalayein:
npm run dev