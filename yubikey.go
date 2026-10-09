// Package goyubikey utils for yubikey
package goyubikey

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"io"
	"math/big"
	"strings"

	"github.com/Laisky/errors/v2"
	gcrypto "github.com/Laisky/go-utils/v6/crypto"
	glog "github.com/Laisky/go-utils/v6/log"
	"github.com/Laisky/piv-go/piv"
	"github.com/Laisky/zap"
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
	if len(certs) == 0 {
		return errors.New("empty certificate chain")
	}

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

// Decrypt decrypts one RSA-OAEP ciphertext with SHA-256, MGF1 SHA-256 and
// an empty label using the slot's RSA private key. Ciphertext must contain
// exactly one modulus-sized block; plaintext capacity is modulus size minus
// 66 bytes. The v1 fork supports RSA-1024/2048. PKCS #1 v1.5,
// concatenated blocks and other algorithms are rejected.
// On any failure, no plaintext is returned.
//
// This contract intentionally replaces the v2 legacy decryption behavior;
// callers must encrypt with matching OAEP parameters before using v3.
func Decrypt(yk *piv.YubiKey, pin string, slot piv.Slot, cipher []byte) ([]byte, error) {
	if yk == nil {
		return nil, errors.New("YubiKey must not be nil")
	}
	return decryptFromKeySource(pivDecryptionKeySource{yk: yk, pin: pin, slot: slot}, cipher)
}

// decryptionKeySource separates the existing device/key acquisition boundary
// from the decryption contract so software tests need no device or credentials.
type decryptionKeySource interface {
	attest() (*x509.Certificate, error)
	privateKey(crypto.PublicKey) (crypto.PrivateKey, error)
}

type pivDecryptionKeySource struct {
	yk   *piv.YubiKey
	pin  string
	slot piv.Slot
}

func (s pivDecryptionKeySource) attest() (*x509.Certificate, error) { return s.yk.Attest(s.slot) }
func (s pivDecryptionKeySource) privateKey(public crypto.PublicKey) (crypto.PrivateKey, error) {
	return s.yk.PrivateKey(s.slot, public, piv.KeyAuth{PIN: s.pin})
}

func decryptFromKeySource(source decryptionKeySource, cipher []byte) ([]byte, error) {
	var plaintext []byte
	cert, err := source.attest()
	if err != nil {
		return nil, errors.Wrap(err, "attest key")
	}

	if cert == nil {
		return nil, errors.New("attestation returned no certificate")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub == nil || pub.N == nil || pub.N.Sign() <= 0 || pub.E < 2 || pub.E > 1<<31-1 {
		return nil, rsa.ErrDecryption
	}
	switch pub.N.BitLen() {
	case 1024, 2048:
	default:
		return nil, rsa.ErrDecryption
	}
	if len(cipher) != pub.Size() || new(big.Int).SetBytes(cipher).Cmp(pub.N) >= 0 {
		return nil, rsa.ErrDecryption
	}
	priv, err := source.privateKey(pub)
	if err != nil {
		return nil, errors.Wrap(err, "get prikey")
	}

	deviceDecrypter, ok := priv.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("private key does not implement crypto.Decrypter")
	}
	privatePublic, ok := deviceDecrypter.Public().(*rsa.PublicKey)
	if !ok || privatePublic == nil || privatePublic.N == nil || privatePublic.E != pub.E || privatePublic.N.Cmp(pub.N) != 0 {
		return nil, errors.New("private key does not match the attested RSA public key")
	}
	plaintext, err = deviceDecrypter.Decrypt(rand.Reader, cipher, &rsa.OAEPOptions{
		Hash: crypto.SHA256, MGFHash: crypto.SHA256,
	})
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
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key does not implement crypto.Signer")
	}
	return signer.Sign(rand.Reader, hasher.Sum(nil), crypto.SHA256)
}
