import { describe, expect, it } from 'vitest';
import {
  AuthenticationError,
  EmptyPassphraseError,
  FileTooLargeError,
  FilenameTooLongError,
  GCM_TAG_LENGTH,
  HEADER_LENGTH,
  MAX_FILE_BYTES,
  MAX_FILENAME_BYTES,
  MAGIC,
  VERSION,
  decryptFile,
  encryptFile,
} from '../src/crypto';

describe('encryptFile / decryptFile', () => {
  it('round-trips a text file and restores the original name', async () => {
    const contents = new TextEncoder().encode('hello, portfolio');
    const container = await encryptFile(contents, 'notes.txt', 'correct horse battery staple!');
    const result = await decryptFile(container, 'correct horse battery staple!');
    expect(result.filename).toBe('notes.txt');
    expect(Array.from(result.contents)).toEqual(Array.from(contents));
  });

  it('round-trips an empty file', async () => {
    const contents = new Uint8Array(0);
    const container = await encryptFile(contents, 'empty.dat', 'another-long-passphrase');
    const result = await decryptFile(container, 'another-long-passphrase');
    expect(result.filename).toBe('empty.dat');
    expect(result.contents.length).toBe(0);
  });

  it('round-trips a binary file with nulls and high bytes', async () => {
    const contents = new Uint8Array(256);
    for (let i = 0; i < 256; i += 1) {
      contents[i] = i;
    }
    const container = await encryptFile(contents, 'blob.bin', 'bin-passphrase-123');
    const result = await decryptFile(container, 'bin-passphrase-123');
    expect(result.filename).toBe('blob.bin');
    expect(Array.from(result.contents)).toEqual(Array.from(contents));
  });

  it('uses a unique salt and IV on each encryption', async () => {
    const contents = new Uint8Array([1, 2, 3, 4]);
    const first = await encryptFile(contents, 'a.bin', 'same-passphrase');
    const second = await encryptFile(contents, 'a.bin', 'same-passphrase');
    expect(Array.from(first)).not.toEqual(Array.from(second));
    expect(Array.from(first.subarray(5, 21))).not.toEqual(Array.from(second.subarray(5, 21)));
    expect(Array.from(first.subarray(21, 33))).not.toEqual(Array.from(second.subarray(21, 33)));
  });

  it('produces a container that starts with the magic and version', async () => {
    const container = await encryptFile(new Uint8Array([9]), 'x', 'passphrase-ok');
    expect(Array.from(container.subarray(0, 4))).toEqual(Array.from(MAGIC));
    expect(container[4]).toBe(VERSION);
    expect(container.length).toBeGreaterThanOrEqual(HEADER_LENGTH + GCM_TAG_LENGTH);
  });

  it('fails clearly when the passphrase is wrong', async () => {
    const container = await encryptFile(new Uint8Array([7, 8, 9]), 'secret.txt', 'right-passphrase');
    await expect(decryptFile(container, 'wrong-passphrase')).rejects.toBeInstanceOf(
      AuthenticationError,
    );
    await expect(decryptFile(container, 'wrong-passphrase')).rejects.toThrow(
      'Wrong passphrase or the file has been tampered with.',
    );
  });

  it('fails when a ciphertext byte is flipped', async () => {
    const container = await encryptFile(new Uint8Array([10, 20, 30]), 'tamper.txt', 'passphrase-ok');
    const tampered = new Uint8Array(container);
    const last = tampered.length - 1;
    tampered[last] = tampered[last] ^ 0x01;
    await expect(decryptFile(tampered, 'passphrase-ok')).rejects.toBeInstanceOf(
      AuthenticationError,
    );
  });

  it('fails when a header salt byte is flipped', async () => {
    const container = await encryptFile(new Uint8Array([10, 20, 30]), 'tamper.txt', 'passphrase-ok');
    const tampered = new Uint8Array(container);
    tampered[10] = tampered[10] ^ 0x01;
    await expect(decryptFile(tampered, 'passphrase-ok')).rejects.toBeInstanceOf(
      AuthenticationError,
    );
  });

  it('rejects an empty passphrase', async () => {
    await expect(encryptFile(new Uint8Array([1]), 'a.txt', '')).rejects.toBeInstanceOf(
      EmptyPassphraseError,
    );
  });

  it('rejects a file that exceeds the size limit', async () => {
    const tooBig = new Uint8Array(MAX_FILE_BYTES + 1);
    await expect(encryptFile(tooBig, 'huge.bin', 'passphrase-ok')).rejects.toBeInstanceOf(
      FileTooLargeError,
    );
  });

  it('rejects a file name that is too long', async () => {
    const name = 'n'.repeat(MAX_FILENAME_BYTES + 1);
    await expect(encryptFile(new Uint8Array([1]), name, 'passphrase-ok')).rejects.toBeInstanceOf(
      FilenameTooLongError,
    );
  });

  it('preserves a unicode file name', async () => {
    const contents = new Uint8Array([0xff, 0x00, 0xfe]);
    const container = await encryptFile(contents, 'retrato-ação.png', 'unicode-passphrase');
    const result = await decryptFile(container, 'unicode-passphrase');
    expect(result.filename).toBe('retrato-ação.png');
    expect(Array.from(result.contents)).toEqual(Array.from(contents));
  });
});
