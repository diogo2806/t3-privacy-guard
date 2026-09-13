import { describe, expect, it } from 'vitest';
import { ENTERPRISE_SCENARIOS } from './scenarioDefinitions';

describe('enterprise scenario definitions', () => {
  it('represents exactly the four actions already supported by the Rust policy', () => {
    expect(ENTERPRISE_SCENARIOS.map((scenario) => scenario.technicalAction)).toEqual([
      'revoke-credential',
      'isolate-account',
      'create-incident',
      'notify-security',
    ]);
    expect(ENTERPRISE_SCENARIOS.map((scenario) => scenario.title)).toEqual([
      'Credential compromised',
      'Account takeover',
      'Record security incident',
      'Notify security contact',
    ]);
  });

  it('keeps protected execution limited to the action with implemented REVOKED read-back', () => {
    expect(ENTERPRISE_SCENARIOS.filter((scenario) => scenario.executionMode === 'protected').map((scenario) => scenario.technicalAction)).toEqual(['revoke-credential']);
    expect(ENTERPRISE_SCENARIOS.filter((scenario) => scenario.executionMode === 'evaluation-only')).toHaveLength(3);
  });

  it('uses only synthetic prompt content and never embeds literal profile placeholders or plaintext PII', () => {
    for (const scenario of ENTERPRISE_SCENARIOS) {
      expect(scenario.prompt).not.toMatch(/\{\{|\}\}|profile\./i);
      expect(scenario.prompt).not.toMatch(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
      expect(scenario.prompt).not.toMatch(/\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/);
      expect(scenario.prompt).not.toMatch(/\bsk-[A-Za-z0-9_-]{12,}\b/);
      expect(scenario.prompt).not.toMatch(/\bBearer\s+[A-Za-z0-9._-]+/i);
    }
  });

  it('uses verified_email only as the logical reference for the notification scenario', () => {
    const notification = ENTERPRISE_SCENARIOS.find((scenario) => scenario.id === 'notify-security-contact');
    expect(notification?.prompt).toContain('verified_email');
    expect(notification?.prompt).not.toContain('@');
    expect(ENTERPRISE_SCENARIOS.filter((scenario) => scenario.id !== 'notify-security-contact').every((scenario) => !scenario.prompt.includes('verified_email'))).toBe(true);
  });
});
