# go-yubikey

[![Go Reference](https://pkg.go.dev/badge/github.com/Laisky/go-yubikey/v2.svg)](https://pkg.go.dev/github.com/Laisky/go-yubikey/v2)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A Go library that provides high-level utilities for YubiKey PIV (Personal Identity Verification) operations, built on top of [go-piv/piv-go](https://github.com/go-piv/piv-go).

## Version Compatibility

| Version | Go     |
| ------- | ------ |
| v1      | 1.20+  |
| v2      | 1.25+  |

## Prerequisites

This library depends on `piv-go`, which requires a C compiler and system libraries for smart card access.

- **macOS**: No additional dependencies (uses built-in smart card framework).
- **Linux**: Install `libpcsclite-dev` (Debian/Ubuntu) or `pcsc-lite-devel` (Fedora/RHEL).
- **Windows**: No additional dependencies (uses built-in WinSCard).

See [piv-go Installation](https://github.com/go-piv/piv-go#installation) for details.

## Installation

```bash
go get github.com/Laisky/go-yubikey/v2
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    goyubikey "github.com/Laisky/go-yubikey/v2"
    "github.com/go-piv/piv-go/piv"
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

## Compatible RSA decryption and new OAEP APIs

Existing v2 imports and exported PIV types remain unchanged. Existing `Decrypt` continues to select legacy PKCS #1 v1.5, so upgrading does not require reencryption of valid historical single-block data. `DecryptLegacy` gives the same operation an explicit migration name. Both are deprecated: arbitrary-message PKCS #1 v1.5 decryption retains padding-oracle risk and belongs only in a restricted, trusted migration workflow.

For new data, use `EncryptOAEP` and `DecryptOAEP` explicitly. These use one RSA-1024/2048 block, SHA-256, MGF1 SHA-256 and an empty label; plaintext capacity is modulus size minus 66 bytes. They never try another padding algorithm on failure.

The application must explicitly select the reviewed compatibility fork in its root `go.mod` to enable `DecryptOAEP`. In that application's root directory, run:

    go mod edit -replace=github.com/go-piv/piv-go=github.com/Laisky/piv-go@v1.11.1-0.20261009203706-c682bc1db34c
    go mod tidy

Dependency replacements do not propagate. With the original upstream dependency, the library still compiles and legacy calls remain available, while `DecryptOAEP` returns `ErrOAEPUnsupported` before decryption because that implementation ignores OAEP options. Public PIV package imports remain `github.com/go-piv/piv-go/piv`.

See [COMPATIBILITY.md](COMPATIBILITY.md) for the version-selection and migration contract, supported historical fixtures, and limits.

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

- **`Decrypt(yk *piv.YubiKey, pin string, slot piv.Slot, cipher []byte) ([]byte, error)`** — Preserve legacy PKCS #1 v1.5 decryption for historical data (deprecated).

- **`EncryptOAEP(pub *rsa.PublicKey, plaintext []byte) ([]byte, error)`** — Explicit single-block OAEP encryption for new data.
- **`DecryptOAEP(yk *piv.YubiKey, pin string, slot piv.Slot, cipher []byte) ([]byte, error)`** — Explicit OAEP decryption; requires the reviewed fork.
- **`DecryptLegacy(...)`** — Explicit name for the unchanged legacy operation (deprecated).

> **Note:** YubiKey does not support concurrent access. Ensure each `*piv.YubiKey` handle is closed after use to avoid `"other connections outstanding"` errors.

## License

[MIT](LICENSE)
