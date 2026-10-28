import { readTrustRuntime } from './config/env.js';

// Only the selected runtime's modules are loaded: self-hosted mode never imports the T3N SDK or opens a session.
if (readTrustRuntime() === 'selfhosted') {
  await import('./selfhosted/main.js');
} else {
  await import('./t3n-main.js');
}
