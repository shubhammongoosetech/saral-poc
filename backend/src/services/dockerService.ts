/**
 * dockerService.ts
 *
 * Backward-compatible facade for nodeClusterService.
 * Directs share management through the SARAL 27-Node Cluster Architecture.
 */

import { nodeCluster, buildNodeName, buildLegacyContainerName } from './nodeClusterService';
import { DomainType } from '../crypto/thresholdEcdsa';

export interface ContainerInfo {
  containerId: string;
  containerName: string;
}

export function buildContainerName(
  userId: string,
  category: string,
  shareIndex: number
): string {
  return buildLegacyContainerName(userId, category, shareIndex);
}

export async function createShareContainer(
  userId: string,
  category: string,
  shareIndex: number,
  encryptedShare: string
): Promise<ContainerInfo> {
  const domain = (
    category.toUpperCase() === 'INSTITUTIONAL' ? 'FOUNDATION' :
    category.toUpperCase() === 'SOVEREIGN' ? 'PRIVATE' : 'PUBLIC'
  ) as DomainType;

  const nodeInfo = await nodeCluster.deployShareToNode(userId, domain, shareIndex, encryptedShare);
  return {
    containerId: nodeInfo.nodeId,
    containerName: nodeInfo.nodeName,
  };
}

export async function readSharesBatch(
  containerNames: string[]
): Promise<Map<string, string>> {
  const dummyNodes = containerNames.map((name) => {
    const parts = name.split('-');
    const domainTag = parts[parts.length - 2] || 'public';
    const index = parseInt(parts[parts.length - 1] || '1', 10);
    const domain = (
      domainTag === 'institutional' || domainTag === 'foundation' ? 'FOUNDATION' :
      domainTag === 'sovereign' || domainTag === 'private' ? 'PRIVATE' : 'PUBLIC'
    ) as DomainType;

    return {
      userId: '',
      domain,
      nodeIndex: index,
      containerName: name,
    };
  });

  return await nodeCluster.retrieveSharesBatch(dummyNodes);
}

export async function readShareFromContainer(
  containerName: string
): Promise<string> {
  const batch = await readSharesBatch([containerName]);
  const share = batch.get(containerName);
  if (!share) throw new Error(`Failed to read share from container: ${containerName}`);
  return share;
}

export async function removeShareContainers(
  userId: string,
  categories: string[],
  n: number
): Promise<void> {
  await nodeCluster.destroyUserNodes(userId);
}

export async function listShareContainers(): Promise<string[]> {
  return [];
}
