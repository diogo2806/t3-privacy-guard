import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { DecisionPanel } from './DecisionPanel';

describe('DecisionPanel', () => {
  it('renders a deny reason without secret values', () => {
    render(<DecisionPanel decision={{ id: 'd1', actionProposalId: 'a1', decision: 'DENY', reasonCode: 'SECRET_DISCLOSURE_FORBIDDEN', reason: 'Direct disclosure is forbidden', allowedFields: [], redactedFields: [], evaluatedAt: new Date().toISOString() }} />);
    expect(screen.getByRole('heading', { name: 'DENY' })).toBeInTheDocument();
    expect(screen.getByText('SECRET_DISCLOSURE_FORBIDDEN')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('api-secret-value');
  });
});
