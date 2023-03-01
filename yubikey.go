// Package goyubikey utils for yubikey
package goyubikey

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"syscall"

	"github.com/Laisky/errors"
	"github.com/Laisky/zap"
	"github.com/go-piv/piv-go/piv"
	"golang.org/x/term"

	gcrypto "github.com/Laisky/go-utils/v4/crypto"
	glog "github.com/Laisky/go-utils/v4/log"
)

var (
	// yubikeyPIVCAPem public ca for yubikey PIV slots
	yubikeyPIVCAPem = []byte(`-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIDBAZHMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMMIFl1
YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAwMDAwMFoY
DzIwNTIwNDE3MDAwMDAwWjArMSkwJwYDVQQDDCBZdWJpY28gUElWIFJvb3QgQ0Eg
U2VyaWFsIDI2Mzc1MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMN2
cMTNR6YCdcTFRxuPy31PabRn5m6pJ+nSE0HRWpoaM8fc8wHC+Tmb98jmNvhWNE2E
ilU85uYKfEFP9d6Q2GmytqBnxZsAa3KqZiCCx2LwQ4iYEOb1llgotVr/whEpdVOq
joU0P5e1j1y7OfwOvky/+AXIN/9Xp0VFlYRk2tQ9GcdYKDmqU+db9iKwpAzid4oH
BVLIhmD3pvkWaRA2H3DA9t7H/HNq5v3OiO1jyLZeKqZoMbPObrxqDg+9fOdShzgf
wCqgT3XVmTeiwvBSTctyi9mHQfYd2DwkaqxRnLbNVyK9zl+DzjSGp9IhVPiVtGet
X02dxhQnGS7K6BO0Qe8CAwEAAaNCMEAwHQYDVR0OBBYEFMpfyvLEojGc6SJf8ez0
1d8Cv4O/MA8GA1UdEwQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQBc7Ih8Bc1fkC+FyN1fhjWioBCMr3vjneh7MLbA6kSoyWF70N3s
XhbXvT4eRh0hvxqvMZNjPU/VlRn6gLVtoEikDLrYFXN6Hh6Wmyy1GTnspnOvMvz2
lLKuym9KYdYLDgnj3BeAvzIhVzzYSeU77/Cupofj093OuAswW0jYvXsGTyix6B3d
bW5yWvyS9zNXaqGaUmP3U9/b6DlHdDogMLu3VLpBB9bm5bjaKWWJYgWltCVgUbFq
Fqyi4+JE014cSgR57Jcu3dZiehB6UtAPgad9L5cNvua/IWRmm+ANy3O2LH++Pyl8
SREzU8onbBsjMg9QDiSf5oJLKvd/Ren+zGY7
-----END CERTIFICATE-----`)
	yubikeyPIVCA *x509.Certificate
)

func init() {
	var err error
	if yubikeyPIVCA, err = gcrypto.Pem2Cert(yubikeyPIVCAPem); err != nil {
		glog.Shared.Panic("parse yubikey piv ca pem", zap.Error(err))
	}
}

// ListYubikeys list all plugin yubikey cards
func ListYubikeys(skipInvalidCard bool) (cards []*piv.YubiKey, err error) {
	allCards, err := piv.Cards()
	if err != nil {
		return nil, errors.Wrap(err, "list all smart cards")
	}

NEXT_CARD:
	for _, card := range allCards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			c, err := piv.Open(card)
			if err != nil {
				if skipInvalidCard {
					continue NEXT_CARD
				}

				return nil, errors.Wrapf(err, "open yubikey %q", card)
			}

			cards = append(cards, c)
		}
	}

	return cards, nil
}

// InputPassword read password from stdin input
func InputPassword(hint string) (string, error) {
	fmt.Printf("%s: ", hint)
	bytepw, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", errors.Wrap(err, "read input password")
	}

	return string(bytepw), nil
}

// VerifyYubikeyCert attest yubikey slot by yubico root ca
func VerifyYubikeyCert(yk *piv.YubiKey, slot piv.Slot) error {
	cert, err := yk.Attest(slot)
	if err != nil {
		return errors.Wrap(err, "attest key")
	}

	ak, err := yk.AttestationCertificate()
	if err != nil {
		return errors.Wrap(err, "get ak")
	}
	intermedia := x509.NewCertPool()
	intermedia.AddCert(ak)

	roots := x509.NewCertPool()
	roots.AddCert(yubikeyPIVCA)
	if _, err = cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermedia,
	}); err != nil {
		return errors.Wrap(err, "slot cert cannot verify by piv root ca")
	}

	return nil
}

// YubikeyPubkey get yubikey slot's public key
func YubikeyPubkey(yk *piv.YubiKey, pin string, slot piv.Slot) (pubkey crypto.PublicKey, err error) {
	cert, err := yk.Attest(slot)
	if err != nil {
		return nil, errors.Wrap(err, "attest key")
	}

	return cert.PublicKey, nil
}

// YubikeyDecrypt decrypt by slot's private key
func YubikeyDecrypt(yk *piv.YubiKey, pin string, slot piv.Slot, cipher []byte) (plaintext []byte, err error) {
	cert, err := yk.Attest(slot)
	if err != nil {
		return nil, errors.Wrap(err, "attest key")
	}

	priv, err := yk.PrivateKey(slot, cert.PublicKey, piv.KeyAuth{PIN: pin})
	if err != nil {
		return nil, errors.Wrap(err, "get prikey")
	}

	deviceDecrypter := priv.(crypto.Decrypter)
	plaintext, err = deviceDecrypter.Decrypt(rand.Reader, cipher, nil)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt by device prikey")
	}

	return plaintext, nil
}

// YubikeySignWithSHA256 sign by slot's private key
func YubikeySignWithSHA256(yk *piv.YubiKey,
	pin string,
	slot piv.Slot,
	content io.Reader) (signature []byte, err error) {
	cert, err := yk.Attest(slot)
	if err != nil {
		return nil, errors.Wrap(err, "attest key")
	}

	priv, err := yk.PrivateKey(slot, cert.PublicKey, piv.KeyAuth{PIN: pin})
	if err != nil {
		return nil, errors.Wrap(err, "get prikey")
	}

	hasher := sha256.New()
	if _, err = io.Copy(hasher, content); err != nil {
		return nil, errors.Wrap(err, "read content")
	}

	signer := priv.(crypto.Signer)
	return signer.Sign(rand.Reader, hasher.Sum(nil), crypto.SHA256)
}
