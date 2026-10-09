package goyubikey

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"math/big"

	"github.com/Laisky/errors/v2"
	"github.com/go-piv/piv-go/piv"
)

// ErrOAEPUnsupported means the selected PIV implementation cannot be trusted
// to honor RSA-OAEP options. No decryption or fallback is performed.
var ErrOAEPUnsupported = errors.New("RSA-OAEP requires the reviewed PIV fork; configure the application's go.mod replacement")

// EncryptOAEP encrypts exactly one RSA block using SHA-256, MGF1 SHA-256,
// and an empty label. Its output must be passed explicitly to DecryptOAEP.
// It rejects unsupported keys and oversized input, and never selects PKCS #1 v1.5.
func EncryptOAEP(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	if pub == nil || pub.N == nil || pub.N.Sign() <= 0 || pub.E < 2 || pub.E > 1<<31-1 {
		return nil, errors.New("invalid RSA public key")
	}
	switch pub.N.BitLen() {
	case 1024, 2048:
	default:
		return nil, errors.New("RSA-OAEP supports RSA-1024/2048 PIV keys")
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
}

// DecryptOAEP decrypts one RSA-OAEP ciphertext with SHA-256, MGF1 SHA-256 and
// an empty label using the slot's RSA private key. Ciphertext must contain
// exactly one modulus-sized block; plaintext capacity is modulus size minus
// 66 bytes. The v1 fork supports RSA-1024/2048. PKCS #1 v1.5,
// concatenated blocks and other algorithms are rejected.
// On any failure, no plaintext is returned.
//
// This is an explicit new-data contract; Decrypt and DecryptLegacy retain the
// historical PKCS #1 v1.5 behavior. The application must select the reviewed
// compatibility fork with a root go.mod replacement. The original upstream
// implementation is rejected because it ignores OAEP options.
func DecryptOAEP(yk *piv.YubiKey, pin string, slot piv.Slot, cipher []byte) ([]byte, error) {
	if yk == nil {
		return nil, errors.New("YubiKey must not be nil")
	}
	return decryptOAEPFromKeySource(newDecryptionKeySource(yk, pin, slot), cipher)
}

// decryptionKeySource separates the existing device/key acquisition boundary
// from the decryption contract so software tests need no device or credentials.
type decryptionKeySource interface {
	attest() (*x509.Certificate, error)
	privateKey(crypto.PublicKey) (crypto.PrivateKey, error)
}

// newDecryptionKeySource is the device-acquisition seam used by behavioral
// tests. Production always obtains keys from the concrete PIV handle.
var newDecryptionKeySource = func(yk *piv.YubiKey, pin string, slot piv.Slot) decryptionKeySource {
	return pivDecryptionKeySource{yk: yk, pin: pin, slot: slot}
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

func decryptOAEPFromKeySource(source decryptionKeySource, cipher []byte) ([]byte, error) {
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
	capable, ok := deviceDecrypter.(interface{ SupportsRSAOAEP() bool })
	if !ok || !capable.SupportsRSAOAEP() {
		return nil, ErrOAEPUnsupported
	}
	plaintext, err = deviceDecrypter.Decrypt(rand.Reader, cipher, &rsa.OAEPOptions{
		Hash: crypto.SHA256, MGFHash: crypto.SHA256,
	})
	if err != nil {
		return nil, errors.Wrap(err, "decrypt by device prikey")
	}

	return plaintext, nil
}
