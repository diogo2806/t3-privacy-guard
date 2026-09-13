import { isIP } from 'node:net';

export const SENSITIVE_PROMPT_CATEGORIES = [
  'EMAIL_LITERAL',
  'CPF_LITERAL',
  'CNPJ_LITERAL',
  'PHONE_LITERAL',
  'PUBLIC_IP_LITERAL',
  'API_KEY_LITERAL',
  'BEARER_TOKEN',
  'JWT',
  'PRIVATE_KEY',
  'PASSWORD_LITERAL',
  'CARD_NUMBER_CANDIDATE',
] as const;

export type SensitivePromptCategory = (typeof SENSITIVE_PROMPT_CATEGORIES)[number];

export const PROMPT_PRIVACY_GUARD_SCOPE = Object.freeze({
  coverage: 'HIGH_CONFIDENCE_PARTIAL' as const,
  semanticPiiScanner: false,
  supportedCategories: SENSITIVE_PROMPT_CATEGORIES,
});

export interface PromptPrivacyInspection {
  readonly safe: boolean;
  readonly categories: SensitivePromptCategory[];
}

export class SensitivePromptError extends Error {
  constructor(readonly categories: SensitivePromptCategory[]) {
    super('SENSITIVE_PROMPT_REJECTED');
    this.name = 'SensitivePromptError';
  }
}

function validCpf(value: string): boolean {
  const digits = value.replace(/\D/g, '');
  if (digits.length !== 11 || /^(\d)\1{10}$/.test(digits)) return false;

  const calculate = (length: number): number => {
    let sum = 0;
    for (let index = 0; index < length; index += 1) {
      sum += Number(digits[index]) * (length + 1 - index);
    }
    const remainder = (sum * 10) % 11;
    return remainder === 10 ? 0 : remainder;
  };

  return calculate(9) === Number(digits[9]) && calculate(10) === Number(digits[10]);
}

export function validCnpj(value: string): boolean {
  const digits = value.replace(/\D/g, '');
  if (digits.length !== 14 || /^(\d)\1{13}$/.test(digits)) return false;

  const calculate = (length: 12 | 13): number => {
    const weights = length === 12
      ? [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
      : [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const sum = weights.reduce((total, weight, index) => total + Number(digits[index]) * weight, 0);
    const remainder = sum % 11;
    return remainder < 2 ? 0 : 11 - remainder;
  };

  return calculate(12) === Number(digits[12]) && calculate(13) === Number(digits[13]);
}

function passesLuhn(value: string): boolean {
  const digits = value.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let doubleDigit = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = Number(digits[index]);
    if (doubleDigit) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    doubleDigit = !doubleDigit;
  }
  return sum % 10 === 0;
}

function containsValidCpf(text: string): boolean {
  const candidates = text.match(/(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)/g) ?? [];
  return candidates.some(validCpf);
}

export function containsValidCnpj(text: string): boolean {
  const candidates = text.match(/(?<!\d)\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}(?!\d)/g) ?? [];
  return candidates.some(validCnpj);
}

function phoneDigitCount(value: string): number {
  return (value.match(/\d/g) ?? []).length;
}

export function containsStrongPhoneLiteral(text: string): boolean {
  if (/(?<![\w+])\+[1-9]\d{7,14}(?!\d)/.test(text)) return true;

  const labeledPhone = /\b(?:phone|mobile|telefone|celular)\s*[:=]\s*(\+?\d[\d(). -]{6,}\d)/gi;
  let match: RegExpExecArray | null;
  while ((match = labeledPhone.exec(text)) !== null) {
    const digits = phoneDigitCount(match[1]);
    if (digits >= 8 && digits <= 15) return true;
  }
  return false;
}

export function isPublicIpAddress(value: string): boolean {
  const candidate = value.trim().replace(/^\[/, '').replace(/\]?[.,;)]*$/, '');
  const version = isIP(candidate);
  if (version === 4) {
    const [first, second, third] = candidate.split('.').map(Number);
    if (first === 0 || first === 10 || first === 127 || first >= 224) return false;
    if (first === 100 && second >= 64 && second <= 127) return false;
    if (first === 169 && second === 254) return false;
    if (first === 172 && second >= 16 && second <= 31) return false;
    if (first === 192 && second === 168) return false;
    if (first === 192 && second === 0) return false;
    if (first === 198 && (second === 18 || second === 19)) return false;
    if (first === 198 && second === 51 && third === 100) return false;
    if (first === 203 && second === 0 && third === 113) return false;
    return true;
  }

  if (version === 6) {
    const normalized = candidate.toLowerCase();
    if (normalized === '::' || normalized === '::1') return false;
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return false;
    if (/^fe[89ab]/.test(normalized)) return false;
    if (normalized.startsWith('ff')) return false;
    if (normalized.startsWith('2001:db8:') || normalized === '2001:db8::') return false;
    if (normalized.startsWith('::ffff:')) return false;
    return true;
  }

  return false;
}

export function containsLabeledPublicIp(text: string): boolean {
  const labeledIp = /\b(?:(?:client|customer|user)\s+ip(?:\s+address)?|ip\s+(?:do|da)\s+(?:cliente|usu[aá]rio))\s*[:=]\s*(\[[0-9a-f:.]+\]|[0-9a-f:.]+)/gi;
  let match: RegExpExecArray | null;
  while ((match = labeledIp.exec(text)) !== null) {
    if (isPublicIpAddress(match[1])) return true;
  }
  return false;
}

function containsLuhnCard(text: string): boolean {
  const candidates = text.match(/(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g) ?? [];
  return candidates.some((candidate) => passesLuhn(candidate));
}

export function inspectPromptForSensitiveLiterals(prompt: string): PromptPrivacyInspection {
  const text = prompt.normalize('NFKC');
  const found = new Set<SensitivePromptCategory>();

  if (/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b/i.test(text)) found.add('EMAIL_LITERAL');
  if (containsValidCpf(text)) found.add('CPF_LITERAL');
  if (containsValidCnpj(text)) found.add('CNPJ_LITERAL');
  if (containsStrongPhoneLiteral(text)) found.add('PHONE_LITERAL');
  if (containsLabeledPublicIp(text)) found.add('PUBLIC_IP_LITERAL');
  if (/\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+\/-]{8,}={0,2}/i.test(text)) found.add('BEARER_TOKEN');
  if (/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/.test(text)) found.add('JWT');
  if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(text) || /\b0x[a-fA-F0-9]{64}\b/.test(text)) found.add('PRIVATE_KEY');
  if (/\bpassword\s*[:=]\s*(?:"[^"]{4,}"|'[^']{4,}'|[^\s,;]{4,})/i.test(text)) found.add('PASSWORD_LITERAL');
  if (/\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|token)\s*[:=]\s*(?:"[^"]{6,}"|'[^']{6,}'|[A-Za-z0-9._~+\/-]{8,}={0,2})/i.test(text)
      || /\bsk-[A-Za-z0-9_-]{16,}\b/.test(text)) {
    found.add('API_KEY_LITERAL');
  }
  if (containsLuhnCard(text)) found.add('CARD_NUMBER_CANDIDATE');

  return { safe: found.size === 0, categories: [...found].sort() };
}

export function assertPromptSafeForExternalProvider(prompt: string): void {
  const inspection = inspectPromptForSensitiveLiterals(prompt);
  if (!inspection.safe) throw new SensitivePromptError(inspection.categories);
}
