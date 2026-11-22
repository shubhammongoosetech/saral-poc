const { spawnSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const net = require('node:net');

const root = resolve(__dirname, '..');
const mode = process.argv[2];
if (mode !== 'full' && mode !== 'nodes') {
  console.error('Usage: node scripts/docker-stack.cjs full|nodes');
  process.exit(1);
}

function checkPortAvailable(port) {
  return new Promise((res) => {
    const s = net.createServer();
    s.once('error', () => res(false));
    s.listen(port, '127.0.0.1', () => {
      s.close(() => res(true));
    });
  });
}

async function findAvailablePort(startPort) {
  for (let p = startPort; p < startPort + 20; p++) {
    if (await checkPortAvailable(p)) return p;
  }
  return startPort;
}

function compose(args, input) {
  const result = spawnSync('docker', ['compose', '-f', 'infra/compose/full24.yml', ...args], {
    cwd: root,
    env: process.env,
    ...(input === undefined ? { stdio: 'inherit' } : { stdio: ['pipe', 'inherit', 'inherit'], input }),
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

async function main() {
  if (!process.env.POSTGRES_PORT) {
    const available = await checkPortAvailable(5432);
    if (!available) {
      const altPort = await findAvailablePort(5433);
      process.env.POSTGRES_PORT = String(altPort);
      console.log(`[docker-stack] Host port 5432 is in use (e.g. local PostgreSQL). Mapping container postgres to 127.0.0.1:${altPort}.`);
    }
  }

  compose(['up', '-d', '--wait', 'postgres']);

  // Existing volumes skip PostgreSQL initialization scripts. Only apply the additive change here.
  const policyMigration = readFileSync(resolve(root,
    'apps/auth-server/prisma/migrations/20261121200000_persist_work_policy_schedule/migration.sql'));
  compose(['exec', '-T', 'postgres', 'psql', '-X', '-U', 'saral', '-d', 'saral', '-v', 'ON_ERROR_STOP=1'], policyMigration);

  if (mode === 'full') {
    compose(['up', '-d', '--build', '--wait']);
  } else {
    const domains = ['foundation', 'public', 'private'];
    const verifiers = domains.map((domain) => `verifier-${domain}`);
    const nodes = ['f', 'p', 'r'].flatMap((prefix) =>
      Array.from({ length: 5 }, (_, index) => `node-${prefix}${index + 1}`));
    const coordinators = domains.map((domain) => `coordinator-${domain}`);
    compose(['up', '-d', '--build', '--no-deps', '--wait', ...verifiers, ...nodes, ...coordinators]);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
