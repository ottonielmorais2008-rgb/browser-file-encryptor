import { describe, expect, it } from 'vitest';
import {
  GCM_TAG_LENGTH,
  HEADER_LENGTH,
  InvalidContainerError,
  MAGIC,
  SALT_LENGTH,
  VERSION,
  encryptFile,
  parseHeader,
} from '../src/crypto';

function minimalStub(): Uint8Array {
  const data = new Uint8Array(HEADER_LENGTH + GCM_TAG_LENGTH);
  data.set(MAGIC, 0);
  data[MAGIC.length] = VERSION;
  return data;
}

describe('parseHeader', () => {
  it('parses salt, IV, and ciphertext from a real container', async () => {
    const container = await encryptFile(new Uint8Array([1, 2, 3]), 'a.txt', 'header-pass');
    const header = parseHeader(container);
    expect(header.version).toBe(VERSION);
    expect(header.salt.length).toBe(SALT_LENGTH);
    expect(header.iv.length).toBe(12);
    expect(header.ciphertext.length).toBe(container.length - HEADER_LENGTH);
    expect(header.ciphertext.length).toBeGreaterThanOrEqual(GCM_TAG_LENGTH);
  });

  it('rejects a truncated file', () => {
    expect(() => parseHeader(new Uint8Array(10))).toThrow(InvalidContainerError);
    expect(() => parseHeader(new Uint8Array(HEADER_LENGTH + GCM_TAG_LENGTH - 1))).toThrow(
      InvalidContainerError,
    );
  });

  it('rejects a wrong magic value', () => {
    const data = minimalStub();
    data[0] = 0x00;
    expect(() => parseHeader(data)).toThrow('expected header');
  });

  it('rejects an unsupported version', () => {
    const data = minimalStub();
    data[MAGIC.length] = 99;
    expect(() => parseHeader(data)).toThrow('Unsupported container version: 99.');
  });

  it('accepts a minimum-length container with valid magic and version', () => {
    const data = minimalStub();
    const header = parseHeader(data);
    expect(header.version).toBe(1);
    expect(header.ciphertext.length).toBe(GCM_TAG_LENGTH);
  });
});
