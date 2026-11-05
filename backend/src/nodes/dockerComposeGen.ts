/**
 * dockerComposeGen.ts
 *
 * Dynamic Docker Compose Generator for SARAL Multi-Container Node Clusters.
 *
 * Patent & Specification Mandates (Section 2.3):
 *   - Docker Compose generated directly from dynamic topology (e.g. 19 or 27 nodes).
 *   - One container service per node process across Foundation, Public, and Private domains.
 *   - Includes postgres database and backend API services.
 */

import fs from 'fs';
import path from 'path';
import { buildClusterTopology, ClusterTopology } from '../topology/allocation';

export function generateDockerComposeConfig(topology: ClusterTopology): string {
  const lines: string[] = [
    '# SARAL Cluster — Dynamically Generated Docker Compose Configuration',
    '# Generated automatically from cluster topology specification',
    '',
    "version: '3.8'",
    '',
    'services:',
    '  postgres:',
    '    image: postgres:16-alpine',
    '    container_name: saral-postgres',
    '    restart: unless-stopped',
    '    environment:',
    '      POSTGRES_USER: postgres',
    '      POSTGRES_PASSWORD: secret_change_me',
    '      POSTGRES_DB: saral',
    '    ports:',
    '      - "5432:5432"',
    '    volumes:',
    '      - saral_pg_data:/var/lib/postgresql/data',
    '    networks:',
    '      - saral-net',
    '',
  ];

  const domains = [topology.foundation, topology.public, topology.private];

  let portCounter = 4001;
  for (const domainAlloc of domains) {
    for (let i = 0; i < domainAlloc.count; i++) {
      const nodeId = domainAlloc.nodeIds[i];
      const port = portCounter++;
      lines.push(`  ${nodeId}:`);
      lines.push(`    image: node:24-alpine`);
      lines.push(`    container_name: ${nodeId}`);
      lines.push(`    restart: unless-stopped`);
      lines.push(`    working_dir: /app`);
      lines.push(`    environment:`);
      lines.push(`      - NODE_ID=${nodeId}`);
      lines.push(`      - DOMAIN=${domainAlloc.domain}`);
      lines.push(`      - NODE_INDEX=${i + 1}`);
      lines.push(`      - PORT=${port}`);
      lines.push(`    volumes:`);
      lines.push(`      - ./data/${domainAlloc.domain.toLowerCase()}/${nodeId}:/vault`);
      lines.push(`    ports:`);
      lines.push(`      - "${port}:${port}"`);
      lines.push(`    networks:`);
      lines.push(`      - saral-net`);
      lines.push('');
    }
  }

  lines.push('networks:');
  lines.push('  saral-net:');
  lines.push('    driver: bridge');
  lines.push('');
  lines.push('volumes:');
  lines.push('  saral_pg_data:');
  lines.push('');

  return lines.join('\n');
}

export function writeDockerComposeFile(
  outputPath?: string,
  N: number = 19
): string {
  const targetPath = outputPath || path.resolve(process.cwd(), 'docker-compose.generated.yml');
  const topology = buildClusterTopology(N);
  const content = generateDockerComposeConfig(topology);
  fs.writeFileSync(targetPath, content, 'utf8');
  return targetPath;
}

if (require.main === module) {
  const nArg = process.argv.find((a) => a.startsWith('--nodes='));
  const n = nArg ? parseInt(nArg.split('=')[1], 10) : 19;
  const p = writeDockerComposeFile(undefined, n);
  console.log(`[DockerComposeGen] Generated ${p} for ${n} dynamic nodes.`);
}

