const fs = require('fs');
const { execSync } = require('child_process');

const domains = [
  { prefix: 'f', domain: 'FOUNDATION' },
  { prefix: 'p', domain: 'PUBLIC' },
  { prefix: 'r', domain: 'PRIVATE' },
];

const participants = {};

for (const d of domains) {
  for (let i = 1; i <= 5; i++) {
    const container = `saral-prod-node-${d.prefix}${i}`;
    try {
      const raw = execSync(`docker exec ${container} cat /vault/identity.json`, { stdio: ['pipe', 'pipe', 'ignore'] }).toString();
      const id = JSON.parse(raw);
      const nodeId = id.nodeId;
      participants[nodeId] = {
        nodeId: nodeId,
        domain: d.domain,
        endpoint: `http://node-${d.prefix}${i}:8001`,
        publicKeyHex: id.publicKeyHex,
        encryptionKeyHex: id.encryptionPubKeyHex,
        approvedBy: 'genesis-bootstrap',
        enrolledAt: id.createdAt || new Date().toISOString(),
      };
    } catch (e) {
      // Ignored if container not ready yet
    }
  }
}

if (Object.keys(participants).length === 15) {
  fs.writeFileSync('infra/config/genesis_participants.json', JSON.stringify(participants, null, 2) + '\n');
  console.log('✓ Successfully synchronized infra/config/genesis_participants.json with all 15 node identities.');
} else {
  console.warn(`Warning: only found ${Object.keys(participants).length} participants, keeping existing genesis config.`);
}

