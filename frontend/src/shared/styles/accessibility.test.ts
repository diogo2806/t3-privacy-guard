import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const tokensCss = readFileSync(new URL('./tokens.css', import.meta.url), 'utf8');
const dashboardCss = readFileSync(new URL('./dashboard.css', import.meta.url), 'utf8');

function tokenHex(name: string): string {
  const match = tokensCss.match(new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})`));
  if (!match) throw new Error(`Missing hexadecimal token --${name}`);
  return match[1];
}

function relativeLuminance(hex: string): number {
  const channels = [1, 3, 5].map((start) => Number.parseInt(hex.slice(start, start + 2), 16) / 255);
  const [red, green, blue] = channels.map((channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
  return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
}

function contrastRatio(foreground: string, background: string): number {
  const foregroundLuminance = relativeLuminance(foreground);
  const backgroundLuminance = relativeLuminance(background);
  const lighter = Math.max(foregroundLuminance, backgroundLuminance);
  const darker = Math.min(foregroundLuminance, backgroundLuminance);
  return (lighter + 0.05) / (darker + 0.05);
}

describe('critical visual accessibility tokens', () => {
  it('keeps tertiary technical text at WCAG AA contrast on every semantic surface', () => {
    const foreground = tokenHex('text-tertiary');
    const surfaces = ['canvas', 'surface-1', 'surface-2', 'surface-3', 'interactive-surface'];

    for (const surface of surfaces) {
      expect(contrastRatio(foreground, tokenHex(surface)), `${surface} contrast`).toBeGreaterThanOrEqual(4.5);
    }
  });

  it('does not reintroduce the legacy low-contrast audit color', () => {
    expect(dashboardCss.toLowerCase()).not.toContain('#60758f');
    expect(dashboardCss).toContain('.audit-list time, .audit-list small { display: block; color: var(--text-tertiary);');
  });
});
