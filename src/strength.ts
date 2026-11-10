export type StrengthLevel = 'empty' | 'weak' | 'fair' | 'strong';

export type StrengthResult = {
  level: StrengthLevel;
  label: string;
  hint: string;
};

/**
 * A coarse, local hint only — not a substitute for a long, unique passphrase.
 */
export function passphraseStrength(passphrase: string): StrengthResult {
  if (passphrase.length === 0) {
    return { level: 'empty', label: '', hint: '' };
  }

  const classes = [
    /[a-z]/.test(passphrase),
    /[A-Z]/.test(passphrase),
    /\d/.test(passphrase),
    /[^A-Za-z0-9]/.test(passphrase),
  ].filter(Boolean).length;

  if (passphrase.length < 10 || classes < 2) {
    return {
      level: 'weak',
      label: 'Weak',
      hint: 'Use a longer passphrase with mixed characters. Strength is entirely up to you.',
    };
  }

  if (passphrase.length >= 16 && classes >= 3) {
    return {
      level: 'strong',
      label: 'Strong',
      hint: 'A long, unique passphrase is the main protection for this file.',
    };
  }

  return {
    level: 'fair',
    label: 'Fair',
    hint: 'Longer is better. Aim for 16 or more characters with mixed types.',
  };
}
