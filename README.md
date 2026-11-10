# Browser File Encryptor

[![CI](https://github.com/ottonielmorais2008-rgb/browser-file-encryptor/actions/workflows/ci.yml/badge.svg)](https://github.com/ottonielmorais2008-rgb/browser-file-encryptor/actions/workflows/ci.yml)

Encrypt and decrypt files entirely in the browser with the Web Crypto API. The file and the passphrase never leave the device. There is no backend and the page makes no network requests.

**Live demo:** [https://ottonielmorais2008-rgb.github.io/browser-file-encryptor/](https://ottonielmorais2008-rgb.github.io/browser-file-encryptor/)

## What it does

- Drag and drop a file, or pick one from disk.
- Encrypt it with a passphrase and download a `.enc` container.
- Decrypt a `.enc` file with the same passphrase to restore the original name and bytes.
- Show a simple passphrase-strength hint (encrypt mode only).
- Reject a wrong passphrase or a tampered file with a clear error.

The tool holds the file in memory and accepts files up to 50 MiB.

## Security design

| Piece | Choice |
| --- | --- |
| Cipher | AES-256-GCM (128-bit tag) |
| Key derivation | PBKDF2-SHA-256, 600,000 iterations |
| Salt | 16 random bytes per file |
| IV | 12 random bytes per file |
| Filename | Stored inside the ciphertext, not in the clear header |

The container is self-describing:

```
magic "BFEN" (4 bytes)
version (1 byte, currently 1)
salt (16 bytes)
IV (12 bytes)
ciphertext + GCM tag
```

The plaintext inside the ciphertext is a length-prefixed UTF-8 file name followed by the original file bytes. GCM authentication fails if the passphrase is wrong or any protected byte is changed.

A strict Content-Security-Policy meta tag allows only same-origin scripts and styles (`connect-src 'none'`), so the page cannot call out to the network even if the code is later changed by mistake.

## Limitations

- **Passphrase strength is everything.** There is no second factor and no key file. A short or reused passphrase can be guessed offline.
- **This code has not been audited.** Treat it as a portfolio demonstration, not as a replacement for well-reviewed tools such as age or GPG.
- **Large files are held in memory**, which is why the UI caps files at 50 MiB.
- **PBKDF2 is deliberately slow** (600,000 iterations). Encrypting or decrypting can take a few seconds, especially on older machines.
- The strength meter is a coarse hint, not a password cracker or a guarantee.

## Run locally

```bash
npm ci
npm test
npm run dev
```

The dev server listens on `http://127.0.0.1:5173/`. Use that address only when running the app on your own machine; the public demo is the GitHub Pages link above.

## Tests and CI

GitHub Actions runs typechecking, 21 Vitest tests, and the production build on every push and pull request. Tests cover:

- Round-trip encryption and decryption, including empty and binary files
- Restoration of the original file name (including Unicode names)
- Wrong passphrase and tampered bytes (header and ciphertext)
- Header parsing (truncated input, bad magic, unsupported version)
- Passphrase-strength hints
- Unique salt and IV on each encryption

A successful push to `main` deploys the `dist` folder to GitHub Pages.

## What went wrong

- TypeScript 5.9's DOM typings reject a `Uint8Array` coming from `subarray()` as a `BufferSource`, because the underlying buffer might be a `SharedArrayBuffer`. The first typecheck failed on the PBKDF2 and AES-GCM calls. The fix is a small helper that copies those views into a fresh `ArrayBuffer`-backed `Uint8Array` before passing them to Web Crypto. That change is only for typings; the runtime bytes are unchanged.
- A file just under the 50 MiB plaintext limit becomes slightly larger once the header, GCM tag, and encrypted file name are added. The first UI check used the same 50 MiB cap for decryption, which would have rejected a valid `.enc` file produced from a near-limit original. Decrypt mode now allows the extra container overhead.

## License

MIT
