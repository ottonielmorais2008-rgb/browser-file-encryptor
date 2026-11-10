/**
 * Self-describing encrypted file container.
 *
 * Layout (version 1):
 *   0–3    magic "BFEN"
 *   4      version (1)
 *   5–20   16-byte PBKDF2 salt
 *   21–32  12-byte AES-GCM IV
 *   33–    ciphertext (AES-256-GCM, 16-byte tag appended)
 *
 * Plaintext inside the ciphertext:
 *   uint16be filename length
 *   UTF-8 filename
 *   original file bytes
 *
 * The original name is encrypted with the contents so it is not leaked
 * in the header. A wrong passphrase or a flipped byte fails GCM auth.
 */

export const MAGIC = new Uint8Array([0x42, 0x46, 0x45, 0x4e]); // BFEN
export const VERSION = 1;
export const SALT_LENGTH = 16;
export const IV_LENGTH = 12;
export const GCM_TAG_LENGTH = 16;
export const PBKDF2_ITERATIONS = 600_000;
export const KEY_LENGTH_BITS = 256;
export const HEADER_LENGTH = MAGIC.length + 1 + SALT_LENGTH + IV_LENGTH;
export const MAX_FILE_BYTES = 50 * 1024 * 1024;
export const MAX_FILENAME_BYTES = 1024;
export const MAX_CONTAINER_BYTES =
  MAX_FILE_BYTES + HEADER_LENGTH + GCM_TAG_LENGTH + 2 + MAX_FILENAME_BYTES;

export class InvalidContainerError extends Error {
  constructor(message = 'This file is not a valid encrypted container.') {
    super(message);
    this.name = 'InvalidContainerError';
  }
}

export class AuthenticationError extends Error {
  constructor(
    message = 'Wrong passphrase or the file has been tampered with.',
  ) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export class FileTooLargeError extends Error {
  constructor(message = `Files larger than ${MAX_FILE_BYTES / (1024 * 1024)} MiB are not supported.`) {
    super(message);
    this.name = 'FileTooLargeError';
  }
}

export class FilenameTooLongError extends Error {
  constructor(message = 'The file name is too long to store in the container.') {
    super(message);
    this.name = 'FilenameTooLongError';
  }
}

export class EmptyPassphraseError extends Error {
  constructor(message = 'A passphrase is required.') {
    super(message);
    this.name = 'EmptyPassphraseError';
  }
}

export type ContainerHeader = {
  version: number;
  salt: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
};

export type DecryptedFile = {
  filename: string;
  contents: Uint8Array;
};

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const total = parts.reduce((n, part) => n + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function toBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function encodePlaintext(filename: string, contents: Uint8Array): Uint8Array {
  const nameBytes = new TextEncoder().encode(filename);
  if (nameBytes.length > MAX_FILENAME_BYTES) {
    throw new FilenameTooLongError();
  }
  const prefix = new Uint8Array(2);
  new DataView(prefix.buffer).setUint16(0, nameBytes.length, false);
  return concat(prefix, nameBytes, contents);
}

function decodePlaintext(plaintext: Uint8Array): DecryptedFile {
  if (plaintext.length < 2) {
    throw new InvalidContainerError('The decrypted payload is truncated.');
  }
  const nameLength = new DataView(
    plaintext.buffer,
    plaintext.byteOffset,
    plaintext.byteLength,
  ).getUint16(0, false);
  if (nameLength > MAX_FILENAME_BYTES || plaintext.length < 2 + nameLength) {
    throw new InvalidContainerError('The decrypted payload is malformed.');
  }
  const filename = new TextDecoder('utf-8', { fatal: true }).decode(
    plaintext.subarray(2, 2 + nameLength),
  );
  return { filename, contents: plaintext.subarray(2 + nameLength) };
}

export function parseHeader(data: Uint8Array): ContainerHeader {
  if (data.length < HEADER_LENGTH + GCM_TAG_LENGTH) {
    throw new InvalidContainerError('The file is too short to be an encrypted container.');
  }
  const magic = data.subarray(0, MAGIC.length);
  if (!bytesEqual(magic, MAGIC)) {
    throw new InvalidContainerError('The file does not start with the expected header.');
  }
  const version = data[MAGIC.length];
  if (version !== VERSION) {
    throw new InvalidContainerError(`Unsupported container version: ${version}.`);
  }
  const saltStart = MAGIC.length + 1;
  const ivStart = saltStart + SALT_LENGTH;
  const cipherStart = ivStart + IV_LENGTH;
  return {
    version,
    salt: data.subarray(saltStart, ivStart),
    iv: data.subarray(ivStart, cipherStart),
    ciphertext: data.subarray(cipherStart),
  };
}

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  if (passphrase.length === 0) {
    throw new EmptyPassphraseError();
  }
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: toBufferSource(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    material,
    { name: 'AES-GCM', length: KEY_LENGTH_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function encryptFile(
  contents: Uint8Array,
  filename: string,
  passphrase: string,
): Promise<Uint8Array> {
  if (contents.byteLength > MAX_FILE_BYTES) {
    throw new FileTooLargeError();
  }
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key = await deriveKey(passphrase, salt);
  const plaintext = encodePlaintext(filename, contents);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      key,
      toBufferSource(plaintext),
    ),
  );
  const header = new Uint8Array(HEADER_LENGTH);
  header.set(MAGIC, 0);
  header[MAGIC.length] = VERSION;
  header.set(salt, MAGIC.length + 1);
  header.set(iv, MAGIC.length + 1 + SALT_LENGTH);
  return concat(header, ciphertext);
}

export async function decryptFile(
  container: Uint8Array,
  passphrase: string,
): Promise<DecryptedFile> {
  if (container.byteLength > MAX_CONTAINER_BYTES) {
    throw new FileTooLargeError();
  }
  const header = parseHeader(container);
  const key = await deriveKey(passphrase, header.salt);
  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: toBufferSource(header.iv), tagLength: 128 },
        key,
        toBufferSource(header.ciphertext),
      ),
    );
  } catch {
    throw new AuthenticationError();
  }
  try {
    return decodePlaintext(plaintext);
  } catch (error) {
    if (error instanceof TypeError) {
      throw new InvalidContainerError('The decrypted file name is not valid UTF-8.');
    }
    throw error;
  }
}
