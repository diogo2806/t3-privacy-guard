import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { DecisionPanel } from './DecisionPanel';

const baseDecision = {
  id: 'd1',
  actionProposalId: 'a1',
  decision: 'ALLOW' as const,
  reasonCode: 'POLICY_ALLOW',
  reason: 'Action and requested data satisfy the active versioned policy',
  allowedFields: ['incident_id'],
  redactedFields: [],
  allowedPrivateRefs: [],
  redactedPrivateRefs: [],
  policyVersion: '2026-09-12.1',
  policyHash: 'a'.repeat(64),
  requiresHumanAuthorization: true,
  evaluatedAt: new Date().toISOString(),
};

describe('DecisionPanel', () => {
  it('renders policy provenance without calling it attestation', () => {
    render(<DecisionPanel decision={baseDecision} />);
    expect(screen.getByRole('heading', { name: 'ALLOW' })).toBeInTheDocument();
    expect(screen.getByText('2026-09-12.1')).toBeInTheDocument();
    expect(screen.getByText('a'.repeat(64))).toBeInTheDocument();
    expect(screen.getByText('REQUIRED')).toBeInTheDocument();
    expect(document.body.textContent?.toLowerCase()).not.toContain('attestation');
  });

  it('renders a deny reason without secret values', () => {
    render(<DecisionPanel decision={{ ...baseDecision, decision: 'DENY', reasonCode: 'SECRET_DISCLOSURE_FORBIDDEN', reason: 'Direct disclosure is forbidden', allowedFields: [] }} />);
    expect(screen.getByRole('heading', { name: 'DENY' })).toBeInTheDocument();
    expect(screen.getByText('SECRET_DISCLOSURE_FORBIDDEN')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('api-secret-value');
  });

  it('marks legacy decisions without policy metadata as unable to authorize remediation', () => {
    render(<DecisionPanel decision={{ ...baseDecision, policyVersion: null, policyHash: null, requiresHumanAuthorization: null }} />);
    expect(screen.getByText(/no verifiable policy metadata/i)).toBeInTheDocument();
    expect(screen.getByText('Unavailable (legacy/fail-closed)')).toBeInTheDocument();
  });
});
