import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { ShieldCheck } from 'lucide-react';
import { Button, IconButton } from './Button';
import { InlineNotice } from './InlineNotice';
import { SectionHeader } from './SectionHeader';
import { StatusBadge } from './StatusBadge';
import { Surface } from './Surface';

describe('shared UI primitives', () => {
  it('keeps one semantic class source for core surfaces and controls', () => {
    render(
      <Surface aria-label="surface">
        <SectionHeader eyebrow="Policy" title="Decision" icon={<ShieldCheck aria-hidden="true" />} />
        <StatusBadge tone="high">HIGH</StatusBadge>
        <InlineNotice>Policy metadata is required.</InlineNotice>
        <Button variant="primary">Analyze</Button>
        <IconButton aria-label="Inspect" title="Inspect">i</IconButton>
      </Surface>,
    );

    expect(screen.getByLabelText('surface')).toHaveClass('card');
    expect(screen.getByRole('button', { name: 'Analyze' })).toHaveClass('button-primary');
    expect(screen.getByRole('button', { name: 'Inspect' })).toHaveAttribute('title', 'Inspect');
    expect(screen.getByText('HIGH')).toHaveClass('severity-badge-high');
    expect(screen.getByText('Policy metadata is required.')).toHaveClass('inline-notice');
  });
});
