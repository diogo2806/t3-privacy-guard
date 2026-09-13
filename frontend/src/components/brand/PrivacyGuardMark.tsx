interface PrivacyGuardMarkProps {
  className?: string;
}

export function PrivacyGuardMark({ className = '' }: PrivacyGuardMarkProps) {
  return (
    <span className={`brand-icon ${className}`.trim()} aria-hidden="true">
      <svg viewBox="0 0 32 32" role="img" focusable="false">
        <path d="M6 7.5 16 3l10 4.5v7.25c0 6.2-3.55 11.1-10 14.25C9.55 25.85 6 20.95 6 14.75V7.5Z" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
        <path d="M11 11.5h5v4.25h5V20h-5v4.25h-5V20H8.5v-4.25H11V11.5Z" fill="currentColor" opacity=".92" />
        <path d="M21 9.5h3M21 23h3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </svg>
    </span>
  );
}
