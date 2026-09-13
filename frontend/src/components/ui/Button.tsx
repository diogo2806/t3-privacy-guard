import type { ComponentPropsWithoutRef } from 'react';

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost';

interface ButtonProps extends ComponentPropsWithoutRef<'button'> {
  variant?: ButtonVariant;
}

export function Button({ variant = 'secondary', className = '', type = 'button', ...props }: ButtonProps) {
  return <button type={type} className={`button button-${variant} ${className}`.trim()} {...props} />;
}

export function IconButton({ className = '', type = 'button', ...props }: ComponentPropsWithoutRef<'button'>) {
  return <button type={type} className={`icon-button ${className}`.trim()} {...props} />;
}
