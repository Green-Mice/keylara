# Keylara

Keylara is a high-security cryptographic library for Erlang/OTP designed to provide strong cryptographic operations with enhanced entropy through the ALARA (Distributed Entropy Network System).

The library supports a variety of algorithms, both classical and post-quantum, each implemented in its own module.

## Features and Algorithms

* **RSA**:
  RSA (Rivest–Shamir–Adleman) is one of the first public-key cryptosystems, widely used for secure data transmission. In Keylara, RSA is used for key pair generation and encryption/decryption operations. Its security is based on the difficulty of factoring large integers.

* **ML-KEM (CRYSTALS-Kyber)**:
  ML-KEM is a Key Encapsulation Mechanism based on the Kyber algorithm, part of the CRYSTALS suite. Kyber is a lattice-based post-quantum cryptosystem designed to be secure against quantum computer attacks. Keylara uses ML-KEM for secure key exchange and encapsulation.

* **Dilithium**:
  Dilithium is a lattice-based digital signature scheme from the CRYSTALS project. It provides strong post-quantum signature security, designed to resist attacks from both classical and quantum computers. Keylara supports Dilithium for signing and verifying messages.

* **Integration with Alara Network**:
  The ALARA (Distributed Entropy Network System) enhances the randomness used for cryptographic operations, increasing security and reducing predictability of keys.

Keylara is intended to be explored through its comprehensive set of test files, which demonstrate usage patterns, algorithmic correctness, and error handling. These tests serve both as validation and as practical examples for integrating Keylara into your applications.

