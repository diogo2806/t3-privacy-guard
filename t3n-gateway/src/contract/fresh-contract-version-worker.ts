import { parentPort, workerData } from 'node:worker_threads';
import { getContractVersion } from '@terminal3/t3n-sdk';

interface FreshContractVersionWorkerData {
  readonly nodeUrl: string;
  readonly contractId: string;
}

interface FreshContractVersionWorkerResponse {
  readonly ok: boolean;
  readonly version?: string;
}

async function run(): Promise<void> {
  const { nodeUrl, contractId } = workerData as FreshContractVersionWorkerData;
  try {
    const version = await getContractVersion(nodeUrl, contractId);
    const response: FreshContractVersionWorkerResponse = { ok: true, version };
    parentPort?.postMessage(response);
  } catch {
    const response: FreshContractVersionWorkerResponse = { ok: false };
    parentPort?.postMessage(response);
  }
}

await run();
