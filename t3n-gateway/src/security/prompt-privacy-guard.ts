export type SensitivePromptCategory =
  | 'EMAIL_LITERAL'
  | 'CPF_LITERAL'
  | 'API_KEY_LITERAL'
  | 'BEARER_TOKEN'
  | 'JWT'
  | 'PRIVATE_KEY'
  | 'PASSWORD_LITERAL'
  | 'CARD_NUMBER_CANDIDATE';

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

function containsLuhnCard(text: string): boolean {
  const candidates = text.match(/(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g) ?? [];
  return candidates.some((candidate) => passesLuhn(candidate));
}

export function inspectPromptForSensitiveLiterals(prompt: string): PromptPrivacyInspection {
  const text = prompt.normalize('NFKC');
  const found = new Set<SensitivePromptCategory>();

  if (/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b/i.test(text)) found.add('EMAIL_LITERAL');
  if (containsValidCpf(text)) found.add('CPF_LITERAL');
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
