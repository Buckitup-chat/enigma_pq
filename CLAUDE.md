# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

EnigmaPq is an encryption library being carved out for post-quantum cryptography support using OTP 28. It provides a unified API for:
- Asymmetric encryption (ECDH key exchange via secp256k1)
- Symmetric encryption (Blowfish CFB64)
- Digital signatures (ECDSA)
- Hashing (SHA3-256)
- Shamir's Secret Sharing

This is an early-stage extraction from the BuckitUp encrypted chat platform.

## Build Commands

```bash
mix deps.get         # Install dependencies
mix test             # Run all tests
mix test path/to/test.exs:42  # Run specific test line
mix format           # Format code
mix credo --strict   # Lint code
```

## Architecture

### Module Structure

```
Enigma                    # Main facade, delegates to submodules
├── Enigma.Crypt          # Asymmetric crypto: key generation, encrypt/decrypt, sign/verify
├── Enigma.Cipher         # Symmetric crypto: Blowfish CFB64 cipher/decipher
├── Enigma.Hash           # SHA3-256 hashing with protocol for custom types
│   └── Enigma.Hash.Protocol  # Protocol for hashing arbitrary types
└── Enigma.SecretSharing  # Shamir's Secret Sharing via KeyX
```

### Cryptographic Primitives

| Operation | Algorithm | Library |
|-----------|-----------|---------|
| Key Exchange | ECDH (secp256k1) | Curvy |
| Signing | ECDSA (compact) | Curvy |
| Symmetric Cipher | Blowfish CFB64 | :crypto |
| Hashing | SHA3-256 | :crypto |
| Secret Sharing | Shamir's | KeyX |

### Key Encryption Patterns

- **Plain encryption**: `encrypt/3` / `decrypt/3` - Basic ECDH + symmetric
- **Signed encryption**: `encrypt_and_sign/3` / `decrypt_signed/4` - Adds author signature
- **Bisigned encryption**: `encrypt_and_bisign/3` / `decrypt_bisigned/3` - For room-key scenarios where both sender and destination sign

### Post-Quantum Migration Goal

This library is being refactored to support post-quantum algorithms while maintaining the current API. Future work will replace secp256k1/ECDSA with PQ-safe alternatives.

## Code Style

Follow STYLE.md conventions:
- Prefer pipelines over nested calls
- Use `then/2` for transformations, `tap/2` for side effects
- Use `with` for error handling chains with tagged tuples
- Run `mix format` and `mix credo --strict` before commits

## Testing Style

Tests use context maps passed through pipeline chains (see `test/enigma/encryption_test.exs` for the pattern):

```elixir
%{}
|> there_are_alice_and_bob_and_the_message
|> alice_encrypts_the_message_to_bob
|> bob_decrypts_the_message_from_alice
|> assert_decrypted_message_is_the_same
```
