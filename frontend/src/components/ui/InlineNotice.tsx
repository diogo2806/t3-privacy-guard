import type { ComponentPropsWithoutRef } from 'react';

export function InlineNotice({ className = '', ...props }: ComponentPropsWithoutRef<'p'>) {
  return <p className={`inline-notice ${className}`.trim()} {...props} />;
}
