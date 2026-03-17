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

- **`Decrypt(yk *piv.YubiKey, pin string, slot piv.Slot, cipher []byte) ([]byte, error)`** — Decrypt ciphertext using the slot's private key.

> **Note:** YubiKey does not support concurrent access. Ensure each `*piv.YubiKey` handle is closed after use to avoid `"other connections outstanding"` errors.

## License

[MIT](LICENSE)
