import {
  AuthenticationError,
  EmptyPassphraseError,
  FileTooLargeError,
  FilenameTooLongError,
  InvalidContainerError,
  MAX_FILE_BYTES,
  decryptFile,
  encryptFile,
} from './crypto';
import { passphraseStrength } from './strength';

type Mode = 'encrypt' | 'decrypt';

const fileInput = document.querySelector('#file-input') as HTMLInputElement;
const dropZone = document.querySelector('#drop-zone') as HTMLLabelElement;
const dropLabel = document.querySelector('#drop-label') as HTMLSpanElement;
const fileMeta = document.querySelector('#file-meta') as HTMLSpanElement;
const passphraseInput = document.querySelector('#passphrase') as HTMLInputElement;
const confirmField = document.querySelector('#confirm-field') as HTMLDivElement;
const confirmInput = document.querySelector('#confirm') as HTMLInputElement;
const strengthEl = document.querySelector('#strength') as HTMLParagraphElement;
const runButton = document.querySelector('#run') as HTMLButtonElement;
const resetButton = document.querySelector('#reset') as HTMLButtonElement;
const statusEl = document.querySelector('#status') as HTMLParagraphElement;
const downloadLink = document.querySelector('#download') as HTMLAnchorElement;
const encryptTab = document.querySelector('#mode-encrypt') as HTMLButtonElement;
const decryptTab = document.querySelector('#mode-decrypt') as HTMLButtonElement;

let mode: Mode = 'encrypt';
let selectedFile: File | null = null;
let objectUrl: string | null = null;

function setStatus(message: string, isError = false): void {
  statusEl.textContent = message;
  statusEl.classList.toggle('is-error', isError);
}

function clearDownload(): void {
  if (objectUrl) {
    URL.revokeObjectURL(objectUrl);
    objectUrl = null;
  }
  downloadLink.hidden = true;
  downloadLink.removeAttribute('href');
  downloadLink.removeAttribute('download');
}

function describeFile(file: File): string {
  const kib = file.size / 1024;
  const size = file.size >= 1024 * 1024
    ? `${(file.size / (1024 * 1024)).toFixed(1)} MiB`
    : `${kib < 1 ? file.size + ' B' : kib.toFixed(1) + ' KiB'}`;
  return `${file.name} · ${size}`;
}

function takeFile(file: File | undefined): void {
  clearDownload();
  setStatus('');
  if (!file) {
    return;
  }
  if (file.size > MAX_FILE_BYTES) {
    selectedFile = null;
    fileInput.value = '';
    dropLabel.textContent = 'Drop a file here or choose one';
    fileMeta.textContent = '';
    setStatus(`This file is larger than the 50 MiB limit (${describeFile(file)}).`, true);
    return;
  }
  selectedFile = file;
  dropLabel.textContent = 'File selected';
  fileMeta.textContent = describeFile(file);
}

function setMode(next: Mode): void {
  mode = next;
  encryptTab.classList.toggle('is-active', next === 'encrypt');
  decryptTab.classList.toggle('is-active', next === 'decrypt');
  encryptTab.setAttribute('aria-selected', String(next === 'encrypt'));
  decryptTab.setAttribute('aria-selected', String(next === 'decrypt'));
  confirmField.hidden = next !== 'encrypt';
  strengthEl.hidden = next !== 'encrypt' || passphraseInput.value.length === 0;
  runButton.textContent = next === 'encrypt' ? 'Encrypt file' : 'Decrypt file';
  fileInput.accept = next === 'decrypt' ? '.enc,application/octet-stream' : '';
  clearDownload();
  setStatus('');
  updateStrength();
}

function updateStrength(): void {
  if (mode !== 'encrypt') {
    strengthEl.hidden = true;
    return;
  }
  const result = passphraseStrength(passphraseInput.value);
  if (result.level === 'empty') {
    strengthEl.hidden = true;
    strengthEl.textContent = '';
    return;
  }
  strengthEl.hidden = false;
  strengthEl.dataset.level = result.level;
  strengthEl.textContent = `${result.label}. ${result.hint}`;
}

function errorMessage(error: unknown): string {
  if (
    error instanceof AuthenticationError ||
    error instanceof InvalidContainerError ||
    error instanceof EmptyPassphraseError ||
    error instanceof FileTooLargeError ||
    error instanceof FilenameTooLongError
  ) {
    return error.message;
  }
  return 'Something went wrong while processing the file.';
}

function prepareDownload(bytes: Uint8Array, name: string, label: string): void {
  clearDownload();
  // Copy into a fresh ArrayBuffer-backed view so Blob types stay happy.
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const blob = new Blob([copy], { type: 'application/octet-stream' });
  objectUrl = URL.createObjectURL(blob);
  downloadLink.href = objectUrl;
  downloadLink.download = name;
  downloadLink.textContent = label;
  downloadLink.hidden = false;
}

async function run(): Promise<void> {
  clearDownload();
  if (!selectedFile) {
    setStatus('Choose a file first.', true);
    return;
  }
  const passphrase = passphraseInput.value;
  if (!passphrase) {
    setStatus('A passphrase is required.', true);
    return;
  }
  if (mode === 'encrypt' && passphrase !== confirmInput.value) {
    setStatus('The passphrases do not match.', true);
    return;
  }

  runButton.disabled = true;
  setStatus(mode === 'encrypt' ? 'Encrypting… this can take a few seconds.' : 'Decrypting… this can take a few seconds.');
  await new Promise((resolve) => window.setTimeout(resolve, 30));

  try {
    const input = new Uint8Array(await selectedFile.arrayBuffer());
    if (mode === 'encrypt') {
      const container = await encryptFile(input, selectedFile.name, passphrase);
      const name = `${selectedFile.name}.enc`;
      prepareDownload(container, name, `Download ${name}`);
      setStatus('Encryption finished. Download the .enc file and store the passphrase separately.');
    } else {
      const result = await decryptFile(input, passphrase);
      const safeName = result.filename.trim() || 'decrypted.bin';
      prepareDownload(result.contents, safeName, `Download ${safeName}`);
      setStatus('Decryption finished. The original file name and contents have been restored.');
    }
  } catch (error) {
    setStatus(errorMessage(error), true);
  } finally {
    runButton.disabled = false;
  }
}

function reset(): void {
  selectedFile = null;
  fileInput.value = '';
  passphraseInput.value = '';
  confirmInput.value = '';
  dropLabel.textContent = 'Drop a file here or choose one';
  fileMeta.textContent = '';
  clearDownload();
  setStatus('');
  updateStrength();
}

encryptTab.addEventListener('click', () => setMode('encrypt'));
decryptTab.addEventListener('click', () => setMode('decrypt'));
fileInput.addEventListener('change', () => takeFile(fileInput.files?.[0]));
passphraseInput.addEventListener('input', updateStrength);
runButton.addEventListener('click', () => {
  void run();
});
resetButton.addEventListener('click', reset);

dropZone.addEventListener('dragover', (event) => {
  event.preventDefault();
  dropZone.classList.add('is-over');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('is-over'));
dropZone.addEventListener('drop', (event) => {
  event.preventDefault();
  dropZone.classList.remove('is-over');
  takeFile(event.dataTransfer?.files[0]);
});
