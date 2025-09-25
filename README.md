# Keylara

Keylara is a high-security cryptographic library for Erlang/OTP designed to provide strong cryptographic operations with enhanced entropy through the ALARA (Distributed Entropy Network System).

The library supports a variety of algorithms, both classical and post-quantum, each implemented in its own module.

## Features and Algorithms

### Classical Algorithms

* **RSA** (`keylara_rsa.erl`):
  RSA (Rivest–Shamir–Adleman) is a widely used public-key cryptosystem for secure data transmission. Keylara uses RSA for key pair generation and encryption/decryption operations. Its security is based on the difficulty of factoring large integers.

* **AES** (`keylara_aes.erl`):
  AES (Advanced Encryption Standard) is a symmetric-key algorithm used for secure data encryption. It provides confidentiality for data at rest and in transit with different key sizes (128, 192, 256 bits).

* **ChaCha20** (`keylara_chacha20.erl`):
  ChaCha20 is a modern stream cipher designed for high performance and strong security, particularly in software implementations. It is used for fast symmetric encryption and is resistant to timing attacks.

---

### Post-Quantum Algorithms

* **ML-KEM (CRYSTALS-Kyber)** (`keylara_mlkem.erl`):
  ML-KEM is a Key Encapsulation Mechanism based on the Kyber lattice-based algorithm. It is designed to resist quantum computer attacks and is used for secure key exchange and encapsulation.

* **Dilithium** (`keylara_dilithium.erl`):
  Dilithium is a lattice-based digital signature scheme from the CRYSTALS project. It provides post-quantum signature security and is used for signing and verifying messages.

* **SLHDSA** (`keylara_slhdsa.erl`):
  SLH-DSA is a post-quantum digital signature algorithm providing authentication and integrity for messages. It is designed to resist both classical and quantum attacks.

---

### Integration with Alara Network

The ALARA (Distributed Entropy Network System) enhances the randomness used for cryptographic operations, increasing security and reducing predictability of keys.

---

Keylara is intended to be explored through its comprehensive set of test files, which demonstrate usage patterns, algorithmic correctness, and error handling. These tests serve both as validation and as practical examples for integrating Keylara into your applications.

Contributions are welcome! If you want to improve Keylara, add algorithms, or fix issues, please submit a pull request (PR) on the repository.

