# go-yubikey

[![Go Reference](https://pkg.go.dev/badge/github.com/Laisky/go-yubikey/v3.svg)](https://pkg.go.dev/github.com/Laisky/go-yubikey/v3)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A Go library that provides high-level utilities for YubiKey PIV (Personal Identity Verification) operations, built on the maintained [Laisky/piv-go v1 security fork](https://github.com/Laisky/piv-go/pull/2).

## Version Compatibility

| Version | Go     |
| ------- | ------ |
| v1      | 1.20+  |
| v2 (current) | 1.26+ |
| v3      | 1.26+  |

## v3 migration and fork qualification

v3 is an intentional next-major security contract. It directly pins
`github.com/Laisky/piv-go v1.11.1-0.20261009201053-f7096021a5d6`
(commit `f7096021a5d6e1aa3030233b76f43d3b07a0e3e9`), a backport to upstream
v1.11.0 of the reviewed RSA fix at `bb5951c53fb1e4e77cf2f42ce4fdcc7119bd6478`.
Applications need no `replace` directive; upstream PR 195 is independent.

| Consumer change | v2 | v3 |
| --- | --- | --- |
| Library import | `github.com/Laisky/go-yubikey/v2` | `github.com/Laisky/go-yubikey/v3` |
| PIV types/import | `github.com/go-piv/piv-go/piv` | `github.com/Laisky/piv-go/piv` |
| Decrypt contract | Legacy PKCS #1 v1.5, nil options | RSA-OAEP SHA-256, MGF1 SHA-256, empty label |
| Ciphertext framing | Unspecified wrapper framing | Exactly one modulus-sized block, preserving leading zeros |
| Management APIs | `[24]byte`, 3DES | `[24]byte`, 3DES preserved |
| Device RSA sizes | 1024/2048 | 1024/2048 preserved |

The fork retains v1 management, signing, ECDH and non-RSA behavior rather than
adopting the unrelated v2 API/firmware expansion. Only the RSA private-key
factory arm, concrete decrypter and raw RSA response decoder change; the
reviewed padding implementation and PSS/MGF helpers are unchanged.

The own-fork import path still changes concrete `piv.YubiKey` and `piv.Slot`
type identity. Migrate caller PIV imports together with the library import.
Keeping the old public concrete types would keep the old dependency handling
the device; a library-local `replace` does not propagate to applications.
Together with the intentional ciphertext change, this warrants v3 even though
the dependency is a v1 backport. This is not a v2 patch.

Existing PKCS #1 v1.5 ciphertext must be re-encrypted from trusted original
plaintext with matching OAEP parameters. v3 never auto-detects or falls back.
Callers that obtain `crypto.Decrypter` directly and pass nil options bypass
this wrapper; those calls require their own explicit OAEP migration. Existing
ECDH/ECIES callers must retain their protocol rather than pass ECIES envelopes
to this RSA-only method.

`ResetForPIV` still generates RSA-2048 and a 24-byte 3DES management key.
`WithManagementKeyOut(*[24]byte)` retains its output shape. No AES management
selection, larger RSA device algorithm, reset or provisioning change is added.
The fork's Go floor is 1.20 for `rsa.OAEPOptions.MGFHash`; this library's existing
Go 1.26 floor is unchanged.

### RSA-OAEP usage

Use standard-library single-block encryption:

```go
ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
if err != nil {
    return err
}
plaintext, err = goyubikey.Decrypt(card, pin, piv.SlotAuthentication, ciphertext)
```

The maximum plaintext length is `publicKey.Size() - 66` bytes. Encryption of
an empty plaintext still produces one modulus-sized ciphertext block. Chunking
helpers and concatenated RSA blocks do not match this API; use an appropriate
application envelope for larger messages. Invalid public keys, ciphertext sizes
or ciphertext integers outside the RSA modulus are rejected before private-key
acquisition. Any decryption error returns nil plaintext.

### Validation limits and hardware tests

Software controls and regressions exercise the production wrapper's key-source
boundary with real software RSA. A separate wrapper test invokes the actual
fork decrypter but stops at a deliberately failing PIN callback. Fork tests
invoke concrete keyRSA.Decrypt with software raw exponentiation, and the actual
APDU response parser with a fake transmitter. These checks do not establish physical-card behavior, firmware support,
PIN/touch handling, PC/SC chaining, device timing or FIPS acceptance.

Hardware tests are disabled before card enumeration by default. Running read/use
hardware tests requires `GO_YUBIKEY_HARDWARE_TESTS=1`. The destructive reset test
additionally requires `GO_YUBIKEY_DESTRUCTIVE_TESTS=1`; both gates apply. These
flags are intended only for a separately approved disposable test token and are
not enabled in routine qualification or CI.

## Prerequisites

This library depends on `piv-go`, which requires a C compiler and system libraries for smart card access.

- **macOS**: No additional dependencies (uses built-in smart card framework).
- **Linux**: Install `libpcsclite-dev` (Debian/Ubuntu) or `pcsc-lite-devel` (Fedora/RHEL).
- **Windows**: No additional dependencies (uses built-in WinSCard).

See [piv-go Installation](https://github.com/go-piv/piv-go#installation) for details.

## Installation

```bash
go get github.com/Laisky/go-yubikey/v3
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    goyubikey "github.com/Laisky/go-yubikey/v3"
    "github.com/Laisky/piv-go/piv"
)

func main() {
    // List all connected YubiKeys
    cards, err := goyubikey.ListCards(true)
    if err != nil {
        log.Fatal(err)
    }
    defer func() {
        for _, c := range cards {
            c.Close()
        }
    }()

    fmt.Printf("Found %d YubiKey(s)\n", len(cards))

    // Attest a key in the authentication slot
    certs, err := goyubikey.Attest2(cards[0], piv.SlotAuthentication)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Slot certificate subject: %s\n", certs[0].Subject)
}
```

## API Overview

### Card Management

- **`ListCards(skipInvalidCard bool) ([]*piv.YubiKey, error)`** — Discover and open all connected YubiKey devices. Set `skipInvalidCard` to `true` to silently skip inaccessible cards.

- **`ResetForPIV(card *piv.YubiKey, pin string, opts ...ResetForPIVOption) error`** — Factory-reset a YubiKey and configure it for PIV: sets a random PUK, applies the given PIN, and generates an RSA 2048 key. Options: `WithSlot(slot)`, `WithRequireTouch()`.

- **`NewPIN() (string, error)`** / **`NewPUK() (string, error)`** — Generate cryptographically random 8-digit PIN/PUK codes.

### Attestation & Verification

- **`Attest2(yk *piv.YubiKey, slot piv.Slot) ([]*x509.Certificate, error)`** — Attest a slot key and return a verified certificate chain (slot cert + attestation cert), validated against the Yubico PIV Root CA.

- **`VerifyPIVCerts(certs []*x509.Certificate) error`** — Verify a certificate chain against the embedded Yubico PIV Root CA.

### Cryptographic Operations

- **`SignWithSHA256(yk *piv.YubiKey, pin string, slot piv.Slot, content io.Reader) ([]byte, error)`** — Compute a SHA-256 digest over `content` and sign it with the slot's private key.

- **`Decrypt(yk *piv.YubiKey, pin string, slot piv.Slot, cipher []byte) ([]byte, error)`** — Decrypt one RSA-OAEP block with SHA-256, MGF1 SHA-256 and an empty label. Other key types, legacy PKCS #1 v1.5 and concatenated blocks are rejected.

> **Note:** YubiKey does not support concurrent access. Ensure each `*piv.YubiKey` handle is closed after use to avoid `"other connections outstanding"` errors.

## License

[MIT](LICENSE)
