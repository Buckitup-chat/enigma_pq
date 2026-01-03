# Hybrid Cryptography Recommendation

This document outlines the recommendation for using hybrid cryptography in EnigmaPq during the post-quantum transition period.

## Why Hybrid?

Hybrid cryptography combines classical algorithms with post-quantum ones. The attacker must break **both** to compromise the system.

| Concern | Solution |
|---------|----------|
| PQ algorithms are new | They lack decades of cryptanalysis that RSA/ECDSA have |
| Classical algorithms are quantum-vulnerable | A future quantum computer could break them |
| Hybrid = belt AND suspenders | Security holds if either algorithm remains secure |

## How It Works

### Key Exchange (ECDH + ML-KEM)

```
Classical:     Alice ──ECDH──> shared_secret_1
Post-Quantum:  Alice ──ML-KEM──> shared_secret_2

Final key = KDF(shared_secret_1 || shared_secret_2)
```

- If ECDH is broken by quantum computer → ML-KEM protects you
- If ML-KEM has undiscovered flaw → ECDH protects you

### Signatures (ECDSA + ML-DSA)

```
signature = {ecdsa_sig, mldsa_sig}

Verification: valid only if BOTH signatures verify
```

## Trade-offs

| Aspect | Classical Only | Hybrid |
|--------|----------------|--------|
| Key sizes | Small (32-64 bytes) | Larger (ML-KEM adds ~800-1500 bytes) |
| Signature sizes | Small (~64 bytes ECDSA) | Larger (ML-DSA adds ~2500-4600 bytes) |
| Computation | Fast | Slower (two operations) |
| Security | Vulnerable to quantum | Secure against classical AND quantum |
| Confidence | High (proven over decades) | High (two independent security assumptions) |

## NIST Recommendations

NIST recommends hybrid solutions as a temporary measure during the post-quantum transition:

> "The desired property of hybrid techniques is that derived keys remain secure if at least one of the component schemes is secure."

Key points from NIST guidance:

- **FIPS 140-3 validation**: Hybrid algorithms can be validated as long as one component is NIST-approved (e.g., ML-KEM, ML-DSA)
- **Transition timeline**: Quantum-vulnerable algorithms will be deprecated by 2035, with high-risk systems transitioning earlier
- **Long-term goal**: Replace hybrid PQ/Traditional with PQC-only algorithms once confidence is established

### NIST PQC Standards (August 2024)

| Standard | Algorithm | Use Case |
|----------|-----------|----------|
| FIPS 203 | ML-KEM | Key encapsulation (key exchange) |
| FIPS 204 | ML-DSA | Digital signatures |
| FIPS 205 | SLH-DSA | Digital signatures (hash-based backup) |

### Backup Algorithm (March 2025)

NIST selected **HQC** as a backup for ML-KEM, based on different mathematical foundations (code-based vs lattice-based). This provides defense-in-depth if weaknesses are discovered in ML-KEM.

## Recommendation for EnigmaPq

During the transition period (approximately 5-10 years), use **hybrid mode**:

1. **Key Exchange**: ECDH (secp256k1) + ML-KEM
2. **Signatures**: ECDSA + ML-DSA

This maximizes security confidence while the cryptographic community gains experience with post-quantum algorithms.

## References

- [NIST Releases First 3 Finalized Post-Quantum Encryption Standards (August 2024)](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)
- [NIST IR 8547: Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/ipd)
- [NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption (March 2025)](https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption)
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
