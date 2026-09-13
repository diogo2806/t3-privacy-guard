import type { ReactNode } from 'react';

export type StatusBadgeTone = 'low' | 'medium' | 'high' | 'critical';

interface StatusBadgeProps {
  tone?: StatusBadgeTone;
  children: ReactNode;
  className?: string;
}

export function StatusBadge({ tone = 'medium', children, className = '' }: StatusBadgeProps) {
  return <span className={`severity-badge severity-badge-${tone} ${className}`.trim()}>{children}</span>;
}
