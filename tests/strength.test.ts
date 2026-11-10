import { describe, expect, it } from 'vitest';
import { passphraseStrength } from '../src/strength';

describe('passphraseStrength', () => {
  it('treats an empty value as empty', () => {
    expect(passphraseStrength('').level).toBe('empty');
  });

  it('flags short or single-class passphrases as weak', () => {
    expect(passphraseStrength('abc').level).toBe('weak');
    expect(passphraseStrength('abcdefghij').level).toBe('weak');
    expect(passphraseStrength('1234567890').level).toBe('weak');
  });

  it('rates a mixed mid-length passphrase as fair', () => {
    expect(passphraseStrength('Short Mix 1').level).toBe('fair');
  });

  it('rates a long mixed passphrase as strong', () => {
    expect(passphraseStrength('correct-Horse battery 99').level).toBe('strong');
  });
});
