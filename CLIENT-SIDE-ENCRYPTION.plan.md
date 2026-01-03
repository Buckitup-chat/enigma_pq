# Client-Side Encryption Plan

## Overview

Zero-knowledge encryption system where the server stores only encrypted data. All encryption/decryption happens in the browser using WASM-based ChaCha20-Poly1305 IETF.

**Key Properties:**
- Server never sees plaintext
- 1MB chunk size for streaming and random access
- WASM ChaCha20-Poly1305 IETF (12-byte nonce, Erlang compatible)
- Supports file uploads, downloads, and video streaming
- Seekable video playback via independent chunk encryption

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Browser (Client)                      │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────┐ │
│  │ File Upload  │───▶│   Encrypt    │───▶│  Upload   │ │
│  │   (Plain)    │    │  (1MB chunks)│    │(Encrypted)│ │
│  └──────────────┘    └──────────────┘    └───────────┘ │
│                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────┐ │
│  │  Download    │◀───│   Decrypt    │◀───│ Download  │ │
│  │   (Plain)    │    │  (1MB chunks)│    │(Encrypted)│ │
│  └──────────────┘    └──────────────┘    └───────────┘ │
│                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────┐ │
│  │Video Element │◀───│Stream Decrypt│◀───│   Fetch   │ │
│  │ MediaSource  │    │  (on-demand) │    │  Chunks   │ │
│  └──────────────┘    └──────────────┘    └───────────┘ │
└─────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │      Server      │
                    │ (Encrypted only) │
                    └──────────────────┘
```

## Chunk Strategy

### Chunk Size: 1MB (1,048,576 bytes)

**Rationale:**
- Large enough for efficient I/O and reduced overhead
- Small enough for responsive streaming and memory management
- Good balance for video seeking (modern videos @ 5-10 Mbps = ~0.6-1.2MB/sec)
- Browser memory friendly (typical 50MB video = 50 chunks in memory)

### Encrypted Chunk Structure

```
┌─────────────────────────────────────────────────────┐
│                 Encrypted Chunk                     │
├──────────────────┬──────────────────┬───────────────┤
│   Ciphertext     │   Poly1305 Tag   │               │
│   (1MB max)      │   (16 bytes)     │               │
└──────────────────┴──────────────────┴───────────────┘
         │                  │
         └──────────────────┴─── Total: plaintext_size + 16 bytes
```

**Storage Format:**
```
File on server:
┌──────────┬──────────┬──────────┬─────┬──────────┐
│ Metadata │ Chunk 0  │ Chunk 1  │ ... │ Chunk N  │
│  Header  │(1MB+16B) │(1MB+16B) │     │(<1MB+16B)│
└──────────┴──────────┴──────────┴─────┴──────────┘

Metadata Header (first 512 bytes):
- Magic: "ENIGMA_ENC" (10 bytes)
- Version: 1 (1 byte)
- Cipher: "chacha20poly1305" (17 bytes)
- File ID: 32 bytes (SHA-256 of original filename + timestamp)
- Original size: 8 bytes (uint64)
- Chunk size: 4 bytes (uint32, always 1048576)
- Chunk count: 4 bytes (uint32)
- Reserved: 436 bytes
```

## Nonce Management

### Strategy: Deterministic Nonce Derivation

**Critical Security Property:** Each chunk gets a **unique** nonce; nonce reuse with same key = catastrophic failure.

```
Nonce (12 bytes) = File_ID (8 bytes) + Chunk_Index (4 bytes)

File_ID = SHA-256(original_filename || upload_timestamp)[0:8]
Chunk_Index = 0, 1, 2, ... (uint32, big-endian)
```

**Example:**
```javascript
// File: "vacation.mp4", uploaded at 1704326400
const fileId = sha256("vacation.mp4||1704326400").slice(0, 8);
// fileId = 0x1a2b3c4d5e6f7a8b

// Chunk 0: nonce = 0x1a2b3c4d5e6f7a8b00000000
// Chunk 1: nonce = 0x1a2b3c4d5e6f7a8b00000001
// Chunk 2: nonce = 0x1a2b3c4d5e6f7a8b00000002
```

**Advantages:**
- Fully deterministic (no need to store nonces)
- Seekable (can decrypt chunk N without decrypting chunks 0..N-1)
- Maximum 2^32 chunks = 4TB per file @ 1MB chunks
- File ID ensures different files never share nonces even with same key

## Key Management

### Key Hierarchy

```
User Master Key (derived from password)
        │
        ├─▶ File Encryption Key (per file)
        │       └─▶ Used for ChaCha20-Poly1305 encryption
        │
        └─▶ Key Wrapping Key (for sharing)
                └─▶ Encrypts file keys for other users
```

### Key Derivation (PBKDF2 or Argon2)

```javascript
// User master key from password
const masterKey = await deriveKey(password, salt, iterations);

// Per-file encryption key
const fileKey = await HKDF(masterKey, fileId, "enigma-file-key");
// fileKey = 32 bytes for ChaCha20-Poly1305
```

### Key Storage Options

1. **Session-based (most secure):**
   - Derive from password on login
   - Store in memory only (JavaScript variable)
   - Lost on page refresh (re-login required)

2. **Browser storage (convenience):**
   - Encrypted with device key in IndexedDB
   - Persistent across sessions
   - Less secure (vulnerable to XSS)

3. **Server-assisted (key wrapping):**
   - Server stores wrapped file keys
   - User password unwraps keys
   - Server never sees unwrapped keys

## Implementation: File Upload

### Flow

```
1. User selects file
2. Generate File ID and derive file key
3. Read file in 1MB chunks
4. Encrypt each chunk with ChaCha20-Poly1305
5. Build metadata header
6. Upload encrypted chunks + header to server
```

### Code Structure

```javascript
class FileEncryptor {
  constructor(wasmChaCha) {
    this.chaCha = wasmChaCha; // Noble or libsodium
    this.chunkSize = 1048576; // 1MB
  }

  async encryptFile(file, fileKey) {
    const fileId = await this.generateFileId(file);
    const chunks = [];

    // Read and encrypt chunks
    let chunkIndex = 0;
    for (let offset = 0; offset < file.size; offset += this.chunkSize) {
      const chunk = await this.readChunk(file, offset, this.chunkSize);
      const nonce = this.deriveNonce(fileId, chunkIndex);
      const encrypted = this.encryptChunk(chunk, fileKey, nonce);
      chunks.push(encrypted);
      chunkIndex++;
    }

    // Build metadata
    const metadata = this.buildMetadata(file, fileId, chunks.length);

    // Upload
    await this.uploadEncrypted(metadata, chunks);

    return { fileId, chunkCount: chunks.length };
  }

  encryptChunk(plainChunk, key, nonce) {
    // Noble implementation
    const cipher = this.chaCha(key, nonce);
    return cipher.encrypt(plainChunk); // Returns ciphertext + 16-byte tag
  }

  deriveNonce(fileId, chunkIndex) {
    const nonce = new Uint8Array(12);
    nonce.set(fileId.slice(0, 8), 0); // First 8 bytes: File ID
    new DataView(nonce.buffer).setUint32(8, chunkIndex, false); // Last 4 bytes: chunk index (big-endian)
    return nonce;
  }

  async generateFileId(file) {
    const timestamp = Date.now().toString();
    const input = new TextEncoder().encode(file.name + "||" + timestamp);
    const hash = await crypto.subtle.digest('SHA-256', input);
    return new Uint8Array(hash);
  }

  async uploadEncrypted(metadata, chunks) {
    // Stream upload using fetch + ReadableStream
    const stream = new ReadableStream({
      async start(controller) {
        controller.enqueue(metadata);
        for (const chunk of chunks) {
          controller.enqueue(chunk);
        }
        controller.close();
      }
    });

    await fetch('/api/upload', {
      method: 'POST',
      body: stream,
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Encrypted': 'true'
      }
    });
  }
}
```

### Progressive Upload with Progress Tracking

```javascript
async encryptAndUploadWithProgress(file, fileKey, onProgress) {
  const fileId = await this.generateFileId(file);
  const totalChunks = Math.ceil(file.size / this.chunkSize);

  // Upload metadata first
  const metadata = this.buildMetadata(file, fileId, totalChunks);
  await this.uploadMetadata(metadata);

  // Stream chunks
  for (let i = 0; i < totalChunks; i++) {
    const offset = i * this.chunkSize;
    const chunk = await this.readChunk(file, offset, this.chunkSize);
    const nonce = this.deriveNonce(fileId, i);
    const encrypted = this.encryptChunk(chunk, fileKey, nonce);

    await this.uploadChunk(fileId, i, encrypted);
    onProgress(i + 1, totalChunks);
  }
}
```

## Implementation: File Download

### Flow

```
1. Fetch encrypted file metadata
2. Fetch encrypted chunks (can be done in parallel or streaming)
3. Decrypt each chunk with ChaCha20-Poly1305
4. Reconstruct original file
5. Trigger browser download
```

### Code Structure

```javascript
class FileDecryptor {
  constructor(wasmChaCha) {
    this.chaCha = wasmChaCha;
    this.chunkSize = 1048576;
  }

  async downloadAndDecrypt(fileId, fileKey, onProgress) {
    // Fetch metadata
    const metadata = await this.fetchMetadata(fileId);
    const { chunkCount, originalSize } = metadata;

    // Decrypt chunks
    const decryptedChunks = [];
    for (let i = 0; i < chunkCount; i++) {
      const encryptedChunk = await this.fetchChunk(fileId, i);
      const nonce = this.deriveNonce(fileId, i);
      const decrypted = this.decryptChunk(encryptedChunk, fileKey, nonce);
      decryptedChunks.push(decrypted);
      onProgress(i + 1, chunkCount);
    }

    // Reconstruct file
    const blob = new Blob(decryptedChunks);
    this.triggerDownload(blob, metadata.originalName);
  }

  decryptChunk(encryptedChunk, key, nonce) {
    const cipher = this.chaCha(key, nonce);
    try {
      return cipher.decrypt(encryptedChunk); // Auto-verifies Poly1305 tag
    } catch (e) {
      throw new Error(`Chunk decryption failed: ${e.message}`);
    }
  }

  triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  async fetchChunk(fileId, chunkIndex) {
    const response = await fetch(`/api/files/${fileId}/chunks/${chunkIndex}`);
    return new Uint8Array(await response.arrayBuffer());
  }
}
```

### Streaming Download (Memory Efficient)

```javascript
async downloadAndDecryptStreaming(fileId, fileKey) {
  const metadata = await this.fetchMetadata(fileId);

  const decryptStream = new ReadableStream({
    async start(controller) {
      for (let i = 0; i < metadata.chunkCount; i++) {
        const encChunk = await this.fetchChunk(fileId, i);
        const nonce = this.deriveNonce(fileId, i);
        const decrypted = this.decryptChunk(encChunk, fileKey, nonce);
        controller.enqueue(decrypted);
      }
      controller.close();
    }
  });

  // Stream to download
  const response = new Response(decryptStream);
  const blob = await response.blob();
  this.triggerDownload(blob, metadata.originalName);
}
```

## Implementation: Video Streaming

### Flow

```
1. Initialize MediaSource API
2. Create SourceBuffer with correct codec
3. Fetch encrypted chunks on-demand
4. Decrypt chunks as they arrive
5. Append decrypted chunks to SourceBuffer
6. Support seeking (jump to any chunk by index)
```

### Code Structure

```javascript
class VideoStreamer {
  constructor(wasmChaCha) {
    this.chaCha = wasmChaCha;
    this.chunkSize = 1048576;
  }

  async streamVideo(videoElement, fileId, fileKey) {
    const metadata = await this.fetchMetadata(fileId);

    // Initialize MediaSource
    const mediaSource = new MediaSource();
    videoElement.src = URL.createObjectURL(mediaSource);

    await new Promise((resolve) => {
      mediaSource.addEventListener('sourceopen', resolve, { once: true });
    });

    // Create SourceBuffer
    const mimeType = metadata.mimeType || 'video/mp4; codecs="avc1.42E01E"';
    const sourceBuffer = mediaSource.addSourceBuffer(mimeType);

    // Stream chunks
    await this.streamChunks(sourceBuffer, fileId, fileKey, metadata.chunkCount);

    mediaSource.endOfStream();
  }

  async streamChunks(sourceBuffer, fileId, fileKey, chunkCount) {
    for (let i = 0; i < chunkCount; i++) {
      // Fetch encrypted chunk
      const encChunk = await this.fetchChunk(fileId, i);

      // Decrypt
      const nonce = this.deriveNonce(fileId, i);
      const decrypted = this.decryptChunk(encChunk, fileKey, nonce);

      // Wait for SourceBuffer to be ready
      if (sourceBuffer.updating) {
        await new Promise(resolve => {
          sourceBuffer.addEventListener('updateend', resolve, { once: true });
        });
      }

      // Append decrypted chunk
      sourceBuffer.appendBuffer(decrypted);
    }
  }

  async seekToTime(sourceBuffer, fileId, fileKey, targetTime, fps = 30) {
    // Estimate chunk index based on video bitrate or time
    const approxBytesPerSecond = 1250000; // ~10 Mbps video
    const byteOffset = targetTime * approxBytesPerSecond;
    const chunkIndex = Math.floor(byteOffset / this.chunkSize);

    // Fetch and decrypt target chunk
    const encChunk = await this.fetchChunk(fileId, chunkIndex);
    const nonce = this.deriveNonce(fileId, chunkIndex);
    const decrypted = this.decryptChunk(encChunk, fileKey, nonce);

    // Clear buffer and append
    sourceBuffer.abort();
    sourceBuffer.remove(0, sourceBuffer.buffered.end(0));
    await new Promise(r => sourceBuffer.addEventListener('updateend', r, { once: true }));
    sourceBuffer.appendBuffer(decrypted);
  }
}
```

### Advanced: Buffering Strategy

```javascript
class AdaptiveVideoStreamer extends VideoStreamer {
  constructor(wasmChaCha) {
    super(wasmChaCha);
    this.bufferAhead = 5; // Buffer 5 chunks ahead
    this.currentChunk = 0;
  }

  async streamWithBuffering(sourceBuffer, fileId, fileKey, chunkCount) {
    while (this.currentChunk < chunkCount) {
      // Decrypt chunks in parallel (buffer ahead)
      const chunkPromises = [];
      for (let i = 0; i < this.bufferAhead && (this.currentChunk + i) < chunkCount; i++) {
        chunkPromises.push(this.fetchAndDecryptChunk(fileId, fileKey, this.currentChunk + i));
      }

      const decryptedChunks = await Promise.all(chunkPromises);

      // Append sequentially
      for (const chunk of decryptedChunks) {
        await this.appendToBuffer(sourceBuffer, chunk);
        this.currentChunk++;
      }
    }
  }

  async fetchAndDecryptChunk(fileId, fileKey, index) {
    const encChunk = await this.fetchChunk(fileId, index);
    const nonce = this.deriveNonce(fileId, index);
    return this.decryptChunk(encChunk, fileKey, nonce);
  }
}
```

## WASM Library Integration

### Option 1: Noble Ciphers (Recommended)

**Pros:**
- Optimized JavaScript (not WASM, but very fast)
- 12-byte nonce support (Erlang compatible)
- Tree-shakeable, small bundle
- No WASM loading overhead

```javascript
import { chacha20poly1305 } from '@noble/ciphers/chacha';

const key = new Uint8Array(32); // Your key
const nonce = new Uint8Array(12); // Derived nonce
const cipher = chacha20poly1305(key, nonce);

const ciphertext = cipher.encrypt(plaintext); // Returns Uint8Array (ct + tag)
const decrypted = cipher.decrypt(ciphertext);  // Throws if tag invalid
```

### Option 2: libsodium.js (WASM)

**Pros:**
- True WASM performance
- Battle-tested library
- Full libsodium feature set

**Cons:**
- ~500KB bundle size
- Async initialization required

```javascript
import sodium from 'libsodium-wrappers';

await sodium.ready;

const key = sodium.crypto_aead_chacha20poly1305_ietf_keygen();
const nonce = new Uint8Array(12);
const aad = new Uint8Array(0); // Additional authenticated data

const ciphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
  plaintext, aad, null, nonce, key
);

const decrypted = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
  null, ciphertext, aad, nonce, key
);
```

### Performance Comparison (from benchmark.html)

Based on typical browser benchmarks:

| Implementation | Throughput | Bundle Size | Notes |
|----------------|------------|-------------|-------|
| AES-GCM (Native) | 200-2000 MB/s | 0 KB | Hardware accelerated, but not available in workers |
| Noble ChaCha20 | 100-300 MB/s | ~15 KB | Best balance |
| libsodium WASM | 300-600 MB/s | ~500 KB | Fastest WASM |
| Pure JS ChaCha | 20-50 MB/s | ~5 KB | Fallback only |

**Recommendation:** Use **Noble** for production (small bundle, Erlang compatible, fast enough for real-time 4K video).

## Performance Optimizations

### 1. Web Workers for Encryption

```javascript
// main.js
const encWorker = new Worker('encrypt-worker.js');

encWorker.postMessage({
  type: 'encrypt',
  chunk: chunkData,
  key,
  nonce
});

encWorker.onmessage = (e) => {
  const { encrypted } = e.data;
  uploadChunk(encrypted);
};

// encrypt-worker.js
import { chacha20poly1305 } from '@noble/ciphers/chacha';

self.onmessage = (e) => {
  const { chunk, key, nonce } = e.data;
  const cipher = chacha20poly1305(key, nonce);
  const encrypted = cipher.encrypt(chunk);
  self.postMessage({ encrypted });
};
```

### 2. Parallel Chunk Processing

```javascript
async encryptChunksParallel(chunks, fileKey, fileId) {
  const workers = 4; // Navigator.hardwareConcurrency
  const workerPool = Array.from({ length: workers }, () => new Worker('encrypt-worker.js'));

  const tasks = chunks.map((chunk, i) => ({
    worker: workerPool[i % workers],
    chunk,
    nonce: this.deriveNonce(fileId, i)
  }));

  return Promise.all(tasks.map(async ({ worker, chunk, nonce }) => {
    return new Promise((resolve) => {
      worker.postMessage({ chunk, key: fileKey, nonce });
      worker.onmessage = (e) => resolve(e.data.encrypted);
    });
  }));
}
```

### 3. Chunk Caching (IndexedDB)

```javascript
class ChunkCache {
  constructor() {
    this.db = null;
  }

  async init() {
    this.db = await idb.openDB('encrypted-chunks', 1, {
      upgrade(db) {
        db.createObjectStore('chunks', { keyPath: ['fileId', 'chunkIndex'] });
      }
    });
  }

  async cacheChunk(fileId, chunkIndex, data) {
    await this.db.put('chunks', { fileId, chunkIndex, data, timestamp: Date.now() });
  }

  async getChunk(fileId, chunkIndex) {
    return await this.db.get('chunks', [fileId, chunkIndex]);
  }
}
```

## Security Considerations

### 1. Nonce Uniqueness (Critical)

- **NEVER reuse nonce with same key**
- Our deterministic scheme guarantees uniqueness per (file, chunk)
- Different files get different File IDs → different nonces
- Maximum 2^32 chunks per file (4TB @ 1MB chunks) before exhaustion

### 2. Key Storage

- **Never log keys**
- Use `SecureContext` APIs only (HTTPS or localhost)
- Clear keys from memory when done:
  ```javascript
  key.fill(0); // Zero out key material
  ```

### 3. Authentication Tag Verification

- ChaCha20-Poly1305 includes 16-byte authentication tag
- Decryption automatically verifies tag
- **Never ignore decryption errors** (indicates tampering or wrong key)

### 4. Side-Channel Resistance

- ChaCha20 is constant-time (resistant to timing attacks)
- AES-GCM requires AES-NI for constant-time (not guaranteed in browsers)

### 5. Random Number Generation

- Always use `crypto.getRandomValues()` for keys/salts
- Never use `Math.random()` for cryptographic purposes

## Browser Compatibility

| Feature | Chrome | Firefox | Safari | Edge |
|---------|--------|---------|--------|------|
| Web Crypto API | ✅ 37+ | ✅ 34+ | ✅ 11+ | ✅ 79+ |
| MediaSource API | ✅ 23+ | ✅ 42+ | ✅ 8+ | ✅ 12+ |
| ReadableStream | ✅ 52+ | ✅ 65+ | ✅ 10.1+ | ✅ 79+ |
| WASM | ✅ 57+ | ✅ 52+ | ✅ 11+ | ✅ 79+ |
| IndexedDB | ✅ 24+ | ✅ 16+ | ✅ 10+ | ✅ 79+ |

**Minimum supported:** Chrome 57, Firefox 65, Safari 11, Edge 79

## Server-Side Requirements

Server must support:

1. **Chunked uploads:**
   ```
   POST /api/upload
   Content-Type: application/octet-stream
   X-Encrypted: true
   X-File-ID: <file_id>

   [metadata header (512 bytes)]
   [chunk 0 (1MB + 16B)]
   [chunk 1 (1MB + 16B)]
   ...
   ```

2. **Range requests for chunks:**
   ```
   GET /api/files/{file_id}/chunks/{chunk_index}
   → Returns single encrypted chunk (1MB + 16B)
   ```

3. **Metadata endpoint:**
   ```
   GET /api/files/{file_id}/metadata
   → Returns JSON: { originalName, size, chunkCount, mimeType, ... }
   ```

4. **Storage structure:**
   ```
   /encrypted_files/
     ├── {file_id}/
     │   ├── metadata.json
     │   ├── chunk_0.bin
     │   ├── chunk_1.bin
     │   └── ...
   ```

## Testing Strategy

### 1. Unit Tests

```javascript
describe('FileEncryptor', () => {
  it('encrypts and decrypts a 1MB chunk correctly', async () => {
    const chunk = randomBytes(1048576);
    const key = randomBytes(32);
    const nonce = randomBytes(12);

    const encrypted = encryptor.encryptChunk(chunk, key, nonce);
    const decrypted = decryptor.decryptChunk(encrypted, key, nonce);

    expect(decrypted).toEqual(chunk);
  });

  it('throws on tampered ciphertext', async () => {
    const encrypted = encryptor.encryptChunk(chunk, key, nonce);
    encrypted[0] ^= 1; // Flip one bit

    expect(() => decryptor.decryptChunk(encrypted, key, nonce)).toThrow();
  });
});
```

### 2. Integration Tests

- Upload 10MB file, download, verify hash matches
- Stream 100MB video, seek to middle, verify playback
- Upload file, re-login, download (test key derivation)

### 3. Performance Tests

- Encrypt 1GB file, measure throughput
- Stream 4K video (25 Mbps), verify no dropped frames
- Parallel upload of 10 files

### 4. Cross-Platform Tests

- Test on Chrome, Firefox, Safari
- Test on Desktop, Mobile
- Test with slow network (throttle to 1 Mbps)

## Migration from Blowfish CFB

Current EnigmaPq uses Blowfish CFB64 (sequential, non-authenticated). Migration path:

1. **Phase 1:** Implement ChaCha20-Poly1305 in parallel
   - Add `Enigma.Cipher.ChaCha` module
   - Keep existing Blowfish for backwards compatibility

2. **Phase 2:** Browser implementation
   - Build `enigma-browser.js` with Noble
   - Test vector compatibility with Erlang

3. **Phase 3:** Re-encrypt existing files
   - Background job to re-encrypt Blowfish → ChaCha
   - Mark files with encryption version

4. **Phase 4:** Deprecate Blowfish
   - Remove Blowfish code after migration complete

## Example: Complete File Upload Flow

```javascript
// 1. User selects file
const fileInput = document.getElementById('fileInput');
const file = fileInput.files[0];

// 2. Derive key from password
const password = prompt('Enter encryption password:');
const salt = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('enigma-salt'));
const masterKey = await crypto.subtle.importKey(
  'raw',
  await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']),
    256
  ),
  { name: 'AES-GCM' },
  false,
  ['encrypt']
);

// 3. Encrypt and upload
const encryptor = new FileEncryptor(nobleChaCha);
await encryptor.encryptAndUploadWithProgress(file, masterKey, (current, total) => {
  console.log(`Progress: ${current}/${total} chunks`);
});

console.log('Upload complete!');
```

## Next Steps

1. **Proof of Concept:**
   - Create minimal HTML page with Noble integration
   - Encrypt/decrypt 10MB file
   - Verify test vectors match Erlang

2. **Browser Library:**
   - Package as `enigma-browser` npm module
   - TypeScript types
   - Documentation

3. **Server Integration:**
   - Add chunked upload endpoint to Phoenix
   - Store encrypted chunks on filesystem or S3
   - Implement range request handler

4. **Production Hardening:**
   - Key management UI (password, recovery)
   - Error handling and retries
   - Progress indicators
   - File sharing (key wrapping)

## References

- ChaCha20-Poly1305 RFC: https://datatracker.ietf.org/doc/html/rfc8439
- Noble Ciphers: https://github.com/paulmillr/noble-ciphers
- MediaSource API: https://developer.mozilla.org/en-US/docs/Web/API/MediaSource
- Web Crypto API: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
