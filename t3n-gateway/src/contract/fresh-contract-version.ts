import { Worker } from 'node:worker_threads';

interface FreshContractVersionWorkerResponse {
  readonly ok: boolean;
  readonly version?: string;
}

function validResponse(value: unknown): value is FreshContractVersionWorkerResponse {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<FreshContractVersionWorkerResponse>;
  return typeof candidate.ok === 'boolean'
    && (candidate.version == null || typeof candidate.version === 'string');
}

export async function getFreshContractVersion(nodeUrl: string, contractId: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const worker = new Worker(new URL('./fresh-contract-version-worker.js', import.meta.url), {
      workerData: { nodeUrl, contractId },
    });
    let settled = false;

    const fail = (): void => {
      if (settled) return;
      settled = true;
      reject(new Error('Fresh T3N contract version lookup failed'));
    };

    worker.once('message', (message: unknown) => {
      if (settled) return;
      if (!validResponse(message) || !message.ok || !message.version?.trim()) {
        fail();
        void worker.terminate();
        return;
      }
      settled = true;
      resolve(message.version);
      void worker.terminate();
    });
    worker.once('error', fail);
    worker.once('exit', (code) => {
      if (!settled && code !== 0) fail();
      else if (!settled) fail();
    });
  });
}
