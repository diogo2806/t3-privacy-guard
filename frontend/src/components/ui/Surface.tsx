import type { ComponentPropsWithoutRef } from 'react';

export interface SurfaceProps extends ComponentPropsWithoutRef<'section'> {
  elevated?: boolean;
}

export function Surface({ className = '', elevated = false, ...props }: SurfaceProps) {
  const classes = ['card', elevated ? 'card-elevated' : '', className].filter(Boolean).join(' ');
  return <section className={classes} {...props} />;
}
