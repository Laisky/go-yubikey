// Package goyubikey utils for yubikey
package goyubikey

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"io"
	"strings"

	"github.com/Laisky/errors"
	gcrypto "github.com/Laisky/go-utils/v4/crypto"
	glog "github.com/Laisky/go-utils/v4/log"
	"github.com/Laisky/zap"
	"github.com/go-piv/piv-go/piv"
)

var (
	// pivCAPem public ca for yubikey PIV slots
	pivCAPem = []byte(`-----BEGIN CERTIFICATE-----
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
	pivCA *x509.Certificate
)

func init() {
	var err error
	if pivCA, err = gcrypto.Pem2Cert(pivCAPem); err != nil {
		glog.Shared.Panic("parse yubikey piv ca pem", zap.Error(err))
	}
}

// VerifyPIVCerts verify certs exported from yubikey PIV slots by Yubico PIV root ca
func VerifyPIVCerts(certs []*x509.Certificate) error {
	root := x509.NewCertPool()
	root.AddCert(pivCA)

	intermedia := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermedia.AddCert(cert)
	}

	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         root,
		Intermediates: intermedia,
	})
	if err != nil {
		return errors.Wrap(err, "verify cert")
	}

	return nil
}

// ListCards function lists all Yubikey plugin cards.
//
// Note that Yubikey does not allow concurrent access,
// and attempting to do so will result in an error message
// "connecting to smart card: the smart card cannot be accessed
// because of other connections outstanding".
//
// Therefore, it is necessary to make sure that each card is
// properly closed after being used.
func ListCards(skipInvalidCard bool) (cards []*piv.YubiKey, err error) {
	// Get all available smart cards.
	allCards, err := piv.Cards()
	if err != nil {
		return nil, errors.Wrap(err, "list all smart cards")
	}

	// Iterate through all smart cards.
NEXT_CARD:
	for _, card := range allCards {
		// Make sure that the smart card is a YubiKey plugin card.
		if strings.Contains(strings.ToLower(card), "yubikey") {
			// Open the card.
			c, err := piv.Open(card)
			if err != nil {
				glog.Shared.Debug("card is invalid", zap.Error(err))
				// If `skipInvalidCard` is true, skip this smart card and move on to the next one.
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

// Attest function attests the key in the slot by yubico Root CA,
// and returns the certificate of the key.
//
// Deprecated: Use `Attest2` instead.
func Attest(yk *piv.YubiKey, slot piv.Slot) (slotCert *x509.Certificate, err error) {
	// Obtain the certificate of the key in the slot
	slotCert, err = yk.Attest(slot)
	if err != nil {
		return nil, errors.Wrap(err, "attest key")
	}

	// Obtain the attestation certificate of the YubiKey
	ak, err := yk.AttestationCertificate()
	if err != nil {
		return nil, errors.Wrap(err, "get ak")
	}
	// Add the attestation certificate to the intermediates pool
	intermedia := x509.NewCertPool()
	intermedia.AddCert(ak)

	// Set up the root and intermediates certificates pool
	roots := x509.NewCertPool()
	roots.AddCert(pivCA)

	// Verify the certificate of the key against the root and intermediates certificate pool
	if _, err = slotCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermedia,
	}); err != nil {
		return nil, errors.Wrap(err, "slot cert cannot verify by piv root ca")
	}

	return slotCert, nil
}

// Attest2 get the certificate chain of the key in the slot,
// all certificates in the chain are verified by yubico Root CA.
func Attest2(yk *piv.YubiKey, slot piv.Slot) (certsChain []*x509.Certificate, err error) {
	// Obtain the certificate of the key in the slot
	slotCert, err := yk.Attest(slot)
	if err != nil {
		return nil, errors.Wrap(err, "attest key")
	}

	// Obtain the attestation certificate of the YubiKey
	ak, err := yk.AttestationCertificate()
	if err != nil {
		return nil, errors.Wrap(err, "get ak")
	}

	certsChain = []*x509.Certificate{slotCert, ak}
	if err = VerifyPIVCerts(certsChain); err != nil {
		return nil, errors.Wrap(err, "verify piv certs")
	}

	return certsChain, nil
}

// Decrypt decrypt by slot's private key
func Decrypt(yk *piv.YubiKey,
	pin string,
	slot piv.Slot,
	cipher []byte) (plaintext []byte, err error) {
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

// SignWithSHA256 signs the content using the private key present in the slot
// described by YubiKey.
// It returns the signature or an error in case of any failures.
func SignWithSHA256(yk *piv.YubiKey,
	pin string,
	slot piv.Slot,
	content io.Reader) (signature []byte, err error) {
	// Get the Attestation Certificate for the key present in the slot.
	// It can be used for verifying the public key or any other purposes
	cert, err := yk.Attest(slot)
	if err != nil {
		return nil, errors.Wrap(err, "attest the key in the slot")
	}

	// Get the private key object for the key present in the slot.
	// It can be used to sign data with the private key
	priv, err := yk.PrivateKey(slot, cert.PublicKey, piv.KeyAuth{PIN: pin})
	if err != nil {
		return nil, errors.Wrap(err, "get the private key for the slot")
	}

	// Compute the SHA-256 digest of the content
	hasher := sha256.New()
	if _, err = io.Copy(hasher, content); err != nil {
		return nil, errors.Wrap(err, "read the content")
	}

	// Sign the SHA-256 digest of the content with the private key
	signer := priv.(crypto.Signer)
	return signer.Sign(rand.Reader, hasher.Sum(nil), crypto.SHA256)
}
