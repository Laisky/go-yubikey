# go-yubikey

[![Go Reference](https://pkg.go.dev/badge/github.com/Laisky/go-yubikey/v3.svg)](https://pkg.go.dev/github.com/Laisky/go-yubikey/v3)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A Go library that provides high-level utilities for YubiKey PIV (Personal Identity Verification) operations, built on the maintained [Laisky/piv-go v2 fork](https://github.com/Laisky/piv-go/pull/1).

## Version Compatibility

| Version | Go     |
| ------- | ------ |
| v1      | 1.20+  |
| v2 (current) | 1.26+ |
| v3      | 1.26+  |

## v3 migration and fork qualification

v3 is an intentional next-major release. The directly consumable fork is pinned
to `github.com/Laisky/piv-go/v2 v2.0.0-20261009193015-894213b04ce4`
(commit `894213b04ce40a4d3c9348a7297a41a3e0face8e`), based on the reviewed
RSA fix at `bb5951c53fb1e4e77cf2f42ce4fdcc7119bd6478`. It is a direct dependency;
applications need no `replace` directive. Upstream PR 195 is independent of
this integration.

| Consumer change | v2 | v3 |
| --- | --- | --- |
| Library import | `github.com/Laisky/go-yubikey/v2` | `github.com/Laisky/go-yubikey/v3` |
| PIV types/import | `github.com/go-piv/piv-go/piv` | `github.com/Laisky/piv-go/v2/piv` |
| Decrypt contract | Legacy PKCS #1 v1.5, nil options | RSA-OAEP SHA-256, MGF1 SHA-256, empty label |
| Ciphertext framing | Unspecified wrapper framing | Exactly one modulus-sized block, preserving leading zeros |

The concrete `piv.YubiKey` and `piv.Slot` types have changed package identity.
Migrate caller PIV imports together with the library import; old and fork types
are not interchangeable. Existing PKCS #1 v1.5 ciphertext must be re-encrypted
from trusted original plaintext with the matching OAEP parameters. v3 never
auto-detects or falls back to legacy decryption.

`ResetForPIV` continues to generate RSA-2048 and a 24-byte management key.
`WithManagementKeyOut(*[24]byte)` retains its output shape. The v2 fork selects
AES-192 for that management-key length on firmware 5.4 or newer, and 3DES on
older firmware; administrative callers must use the matching fork behavior.
No reset, key generation, PIN/PUK change or physical-token operation was performed
to qualify this migration.

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
boundary with real software RSA. The fork also retains its raw RSA/APDU boundary
tests. These checks do not establish physical-card behavior, firmware support,
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
    "github.com/Laisky/piv-go/v2/piv"
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
