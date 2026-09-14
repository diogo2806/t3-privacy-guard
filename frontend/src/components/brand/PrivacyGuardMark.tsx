interface PrivacyGuardMarkProps {
  className?: string;
  testId?: string;
}

export function PrivacyGuardMark({ className = '', testId }: PrivacyGuardMarkProps) {
  return (
    <span className={`brand-icon ${className}`.trim()} aria-hidden="true" data-testid={testId}>
      <svg viewBox="0 0 32 32" role="img" focusable="false">
        <path d="M3 16h4M12 16h3M20 16h3M27 16h2" fill="none" stroke="currentColor" strokeWidth="2.25" strokeLinecap="round" />
        <path d="M7 9h5v14H7M15 7h5v18h-5M23 10h4v12h-4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
        <path d="M9.5 13v6M17.5 11v10M25 13v6" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity=".72" />
      </svg>
    </span>
  );
}
