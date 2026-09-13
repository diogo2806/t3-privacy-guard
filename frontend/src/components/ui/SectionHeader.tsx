import type { ReactNode } from 'react';

export type SectionHeaderTone = 'default' | 'danger' | 'success';

interface SectionHeaderProps {
  eyebrow: string;
  title: ReactNode;
  titleId?: string;
  icon?: ReactNode;
  trailing?: ReactNode;
  compact?: boolean;
  tone?: SectionHeaderTone;
}

export function SectionHeader({ eyebrow, title, titleId, icon, trailing, compact = true, tone = 'default' }: SectionHeaderProps) {
  const iconClasses = ['section-icon', tone !== 'default' ? `section-icon-${tone}` : ''].filter(Boolean).join(' ');
  return (
    <div className={`card-heading${compact ? ' compact' : ''}`}>
      {icon && <div className={iconClasses}>{icon}</div>}
      <div><p className="eyebrow">{eyebrow}</p><h2 id={titleId}>{title}</h2></div>
      {trailing}
    </div>
  );
}
