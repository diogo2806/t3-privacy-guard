import {
  assertPolicyVersionImmutable,
  canonicalizeOperationalPolicy,
  type CanonicalOperationalPolicy,
} from './policy-document.js';

export type PolicyEntryReader = (key: string) => Promise<string | null>;
export type PolicyEntryWriter = (key: string, value: string) => Promise<void>;

export function parsePersistedPolicy(value: string | null, label: string): CanonicalOperationalPolicy | null {
  if (!value) return null;
  try {
    return canonicalizeOperationalPolicy(JSON.parse(value) as unknown);
  } catch {
    throw new Error(`${label} contains an invalid operational policy`);
  }
}

export async function readOptionalPolicyEntry(readEntry: PolicyEntryReader, key: string): Promise<string | null> {
  try {
    return await readEntry(key);
  } catch {
    return null;
  }
}

export async function ensureImmutablePolicyVersion(
  target: CanonicalOperationalPolicy,
  readEntry: PolicyEntryReader,
  writeEntry: PolicyEntryWriter,
): Promise<void> {
  const versionKey = `version:${target.document.version}`;
  const storedVersion = parsePersistedPolicy(
    await readOptionalPolicyEntry(readEntry, versionKey),
    `Stored policy version ${target.document.version}`,
  );
  assertPolicyVersionImmutable(storedVersion, target);
  if (!storedVersion) await writeEntry(versionKey, target.canonicalJson);
}

export async function activateOperationalPolicy(
  target: CanonicalOperationalPolicy,
  readEntry: PolicyEntryReader,
  writeEntry: PolicyEntryWriter,
): Promise<void> {
  await writeEntry('current', target.canonicalJson);
  const verified = parsePersistedPolicy(await readEntry('current'), 'Policy read-back');
  if (!verified) throw new Error('Policy read-back returned no value');
  if (verified.document.version !== target.document.version || verified.hash !== target.hash) {
    throw new Error('Policy read-back version/hash mismatch');
  }
}
