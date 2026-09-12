export function assertNoSecretLeak(serializedArtifact: string, secrets: Array<string | null | undefined>): void {
  for (const secret of secrets) {
    if (!secret) continue;
    if (secret.length < 6) {
      throw new Error('Leak detector secret values must be at least 6 characters long');
    }
    if (serializedArtifact.includes(secret)) {
      throw new Error('Evidence artifact contains forbidden secret material');
    }
  }
}

export function sanitizeEvidenceError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message
    .replace(/0x[a-fA-F0-9]{64}/g, '[REDACTED_PRIVATE_KEY]')
    .replace(/t3n_key_[A-Za-z0-9._-]+/g, '[REDACTED_T3N_KEY]')
    .replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]')
    .slice(0, 800);
}
