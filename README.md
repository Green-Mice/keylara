# keylara
KeyLARA is a high-security cryptographic library for Erlang/OTP that leverages the ALARA (Distributed Entropy Network System) for generating cryptographically secure keys and performing encryption operations.

## Features

- RSA key pair generation
- RSA encryption/decryption
- AES key generation
- AES encryption/decryption
- Integration with Alara network for enhanced entropy

## API Reference

### RSA Operations

```erlang
{ok, {PublicKey, PrivateKey}} = keylara:generate_rsa_keypair(NetPid)
{ok, {PublicKey, PrivateKey}} = keylara:generate_rsa_keypair(NetPid, KeySize)
{ok, EncryptedData} = keylara:rsa_encrypt(Data, PublicKey)
{ok, DecryptedData} = keylara:rsa_decrypt(EncryptedData, PrivateKey)
```

## Requirements

- Erlang/OTP
- Crypto and Public Key applications
- Alara network (optional, for enhanced entropy)

## Usage

```
1> keylara\:start().
Keylara started in standalone mode (Alara not available)
ok
2> {ok, {PublicKey, PrivateKey}} = keylara:generate_rsa_keypair(self(), 2048).
{ok,{{1337,1337,...},...}}
3> {ok, Encrypted} = keylara:rsa_encrypt("Hello, World!", PublicKey).
{ok,<<...>>}
4> {ok, Decrypted} = keylara:rsa_decrypt(Encrypted, PrivateKey).
{ok,"Hello, World!"}
```


