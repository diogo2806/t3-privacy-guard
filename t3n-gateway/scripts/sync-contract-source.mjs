import { cp, mkdir, rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const gatewayRoot = resolve(scriptDir, '..');
const repositoryRoot = resolve(gatewayRoot, '..');
const sourceRoot = resolve(repositoryRoot, 'contracts/privacy-guard');
const targetRoot = resolve(gatewayRoot, 'contract-source');

await rm(targetRoot, { recursive: true, force: true });
await mkdir(targetRoot, { recursive: true });
await cp(resolve(sourceRoot, 'Cargo.toml'), resolve(targetRoot, 'Cargo.toml'));
await cp(resolve(sourceRoot, 'src'), resolve(targetRoot, 'src'), { recursive: true });
await cp(resolve(sourceRoot, 'wit'), resolve(targetRoot, 'wit'), { recursive: true });

console.log('Synchronized contracts/privacy-guard into t3n-gateway/contract-source.');
