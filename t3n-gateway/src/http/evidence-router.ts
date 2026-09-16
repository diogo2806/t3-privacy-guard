import { Router } from 'express';
import { readRuntimeEvidenceBundle } from '../evidence/runtime-evidence-store.js';

export function createEvidenceRouter(): Router {
  const router = Router();
  router.get('/latest', async (_request, response) => {
    const bundle = await readRuntimeEvidenceBundle();
    if (bundle.state === 'ABSENT') {
      response.status(204).end();
      return;
    }
    if (bundle.state === 'INVALID') {
      response.status(409).json({ state: 'INVALID', message: 'Runtime evidence bundle is incomplete or invalid' });
      return;
    }
    response.json({ state: 'AVAILABLE', manifest: bundle.manifest, testnet: bundle.testnet });
  });
  return router;
}
