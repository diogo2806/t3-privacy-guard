const SEMVER_PATTERN = /^\d+\.\d+\.\d+$/;

export const PACKAGED_CONTRACT_VERSION = '0.4.1';
export const LEGACY_DEPLOYMENT_CONTRACT_VERSIONS = Object.freeze(['0.4.0'] as const);

function parseVersion(value: string): readonly [number, number, number] {
  if (!SEMVER_PATTERN.test(value)) throw new Error('Contract version must be semantic version MAJOR.MINOR.PATCH');
  const parts = value.split('.').map(Number);
  return [parts[0], parts[1], parts[2]];
}

export function compareContractVersions(left: string, right: string): number {
  const leftParts = parseVersion(left);
  const rightParts = parseVersion(right);
  for (let index = 0; index < leftParts.length; index += 1) {
    if (leftParts[index] < rightParts[index]) return -1;
    if (leftParts[index] > rightParts[index]) return 1;
  }
  return 0;
}

export function resolvePackagedContractVersion(configured: string | undefined): string {
  const normalized = configured?.trim();
  if (!normalized || normalized === PACKAGED_CONTRACT_VERSION) return PACKAGED_CONTRACT_VERSION;
  if (!SEMVER_PATTERN.test(normalized)) throw new Error('T3N_CONTRACT_VERSION must be semantic version MAJOR.MINOR.PATCH');
  if (LEGACY_DEPLOYMENT_CONTRACT_VERSIONS.includes(normalized as (typeof LEGACY_DEPLOYMENT_CONTRACT_VERSIONS)[number])) {
    return PACKAGED_CONTRACT_VERSION;
  }
  throw new Error(`T3N_CONTRACT_VERSION must match packaged contract version ${PACKAGED_CONTRACT_VERSION}`);
}
