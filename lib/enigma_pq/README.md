# EnigmaPq.Crypt - Post-Quantum Cryptography Module

This module provides a post-quantum analog of `Enigma.Crypt` using NIST-standardized algorithms:
- **ML-KEM1024** (Module-Lattice-Based Key-Encapsulation Mechanism) for key exchange
- **ML-DSA87** (Module-Lattice-Based Digital Signature Algorithm) for digital signatures

## Key Differences from Classical Enigma.Crypt

### Key Encapsulation Mechanism (KEM) vs ECDH

The classical `Enigma.Crypt` uses ECDH (Elliptic Curve Diffie-Hellman) where both parties can independently compute the same shared secret. ML-KEM uses a different paradigm:

1. **Encapsulation**: One party uses the recipient's public key to generate a shared secret and an encapsulated ciphertext
2. **Decapsulation**: The recipient uses their private key to extract the shared secret from the ciphertext

This means encrypted data must include both the ciphertext and the KEM encapsulated secret.

### Separate Key Types

Unlike classical crypto where one key pair can be used for both key agreement and signing, post-quantum crypto uses separate key pairs:

- **KEM keys**: Generated with `generate_keys/0` - used for encryption/decryption
- **Signing keys**: Generated with `generate_signing_keys/0` - used for signatures

## API Compatibility

The module preserves the same function signatures as `Enigma.Crypt` where possible:

- `generate_keys/0` - Generate ML-KEM1024 key pair
- `generate_signing_keys/0` - Generate ML-DSA87 signing key pair
- `encrypt/3` - Encrypt data (returns `{encrypted_data, kem_ciphertext}`)
- `decrypt/3` - Decrypt data
- `sign/2` - Sign data with ML-DSA87
- `valid_sign?/3` - Verify ML-DSA87 signature
- `encrypt_and_sign/3` - Encrypt and sign
- `decrypt_signed/4` - Decrypt and verify signature

## Usage Example

```elixir
# Generate keys
{alice_kem_private, alice_kem_public} = EnigmaPq.Crypt.generate_keys()
{alice_sign_private, alice_sign_public} = EnigmaPq.Crypt.generate_signing_keys()
{bob_kem_private, bob_kem_public} = EnigmaPq.Crypt.generate_keys()

# Alice encrypts for Bob
message = "Secret quantum-safe message"
encrypted = EnigmaPq.Crypt.encrypt(message, alice_kem_private, bob_kem_public)

# Bob decrypts
decrypted = EnigmaPq.Crypt.decrypt(encrypted, bob_kem_private, alice_kem_public)

# Alice encrypts and signs
encrypted_signed = EnigmaPq.Crypt.encrypt_and_sign(
  message, 
  alice_sign_private, 
  bob_kem_public
)

# Bob decrypts and verifies
{:ok, verified_message} = EnigmaPq.Crypt.decrypt_signed(
  encrypted_signed,
  bob_kem_private,
  bob_kem_public,
  alice_sign_public
)
```

## Requirements

- Erlang/OTP 28 or later (includes native ML-KEM and ML-DSA support)
- OpenSSL 3.5 or later (provides the underlying PQ algorithms)

## Security Level

- **ML-KEM1024**: NIST Security Level 5 (~256-bit classical, ~256-bit quantum security)
- **ML-DSA87**: NIST Security Level 5 (~256-bit classical, ~256-bit quantum security)

These provide the highest security level standardized by NIST, suitable for long-term protection against both classical and quantum attacks.
