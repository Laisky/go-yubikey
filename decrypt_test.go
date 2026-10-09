package goyubikey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"testing"
)

type testDecryptionKeySource struct {
	cert                      *x509.Certificate
	private                   crypto.PrivateKey
	attestErr, privateErr     error
	attestCalls, privateCalls int
	requestedPublic           crypto.PublicKey
}

func (s *testDecryptionKeySource) attest() (*x509.Certificate, error) {
	s.attestCalls++
	return s.cert, s.attestErr
}
func (s *testDecryptionKeySource) privateKey(public crypto.PublicKey) (crypto.PrivateKey, error) {
	s.privateCalls++
	s.requestedPublic = public
	return s.private, s.privateErr
}
func softwareKeySource(priv *rsa.PrivateKey) *testDecryptionKeySource {
	return &testDecryptionKeySource{cert: &x509.Certificate{PublicKey: &priv.PublicKey}, private: testOAEPPrivateKey{priv}}
}

type testOAEPPrivateKey struct{ *rsa.PrivateKey }

func (testOAEPPrivateKey) SupportsRSAOAEP() bool { return true }

type testDecrypter struct {
	public  crypto.PublicKey
	decrypt func(io.Reader, []byte, crypto.DecrypterOpts) ([]byte, error)
}

func (testDecrypter) SupportsRSAOAEP() bool      { return true }
func (d testDecrypter) Public() crypto.PublicKey { return d.public }
func (d testDecrypter) Decrypt(r io.Reader, c []byte, o crypto.DecrypterOpts) ([]byte, error) {
	return d.decrypt(r, c, o)
}
func newRSAControl(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
func encryptOAEPControl(t *testing.T, pub *rsa.PublicKey, message, label []byte) []byte {
	t.Helper()
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, message, label)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

// Retained OAEP regression cases are adapted to the explicit new API.
// The separate legacy fixture verifies the unchanged nil-options contract.
func TestDecryptOAEPRegression(t *testing.T) {
	priv := newRSAControl(t, 2048)
	message := []byte("RSA OAEP wrapper control")
	oaep := encryptOAEPControl(t, &priv.PublicKey, message, nil)
	t.Run("software OAEP control", func(t *testing.T) {
		got, err := priv.Decrypt(nil, oaep, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA256})
		if err != nil || !bytes.Equal(got, message) {
			t.Fatalf("software OAEP control %x/%v", got, err)
		}
	})
	t.Run("OAEP round trip", func(t *testing.T) {
		got, err := decryptOAEPFromKeySource(softwareKeySource(priv), oaep)
		if err != nil || !bytes.Equal(got, message) {
			t.Fatalf("wrapper got %x/%v, want %x", got, err, message)
		}
	})
	t.Run("OAEP empty message", func(t *testing.T) {
		ciphertext := encryptOAEPControl(t, &priv.PublicKey, nil, nil)
		got, err := decryptOAEPFromKeySource(softwareKeySource(priv), ciphertext)
		if err != nil || len(got) != 0 {
			t.Fatalf("empty wrapper got %x/%v", got, err)
		}
	})
	t.Run("valid legacy ciphertext rejected", func(t *testing.T) {
		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, message)
		if err != nil {
			t.Fatal(err)
		}
		control, err := rsa.DecryptPKCS1v15(nil, priv, ciphertext)
		if err != nil || !bytes.Equal(control, message) {
			t.Fatalf("invalid legacy control %x/%v", control, err)
		}
		got, err := decryptOAEPFromKeySource(softwareKeySource(priv), ciphertext)
		if !errors.Is(err, rsa.ErrDecryption) || got != nil {
			t.Fatalf("legacy accepted %x/%v", got, err)
		}
	})
	t.Run("explicit parameters forwarded", func(t *testing.T) {
		source := softwareKeySource(priv)
		calls := 0
		source.private = testDecrypter{public: &priv.PublicKey, decrypt: func(random io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
			calls++
			o, ok := opts.(*rsa.OAEPOptions)
			if !ok || o == nil || o.Hash != crypto.SHA256 || o.MGFHash != crypto.SHA256 || len(o.Label) != 0 || random == nil || !bytes.Equal(ciphertext, oaep) {
				t.Errorf("missing OAEP SHA256/MGF1 SHA256/empty-label contract: %#v", opts)
				return nil, rsa.ErrDecryption
			}
			return priv.Decrypt(random, ciphertext, opts)
		}}
		got, err := decryptOAEPFromKeySource(source, oaep)
		if err != nil || !bytes.Equal(got, message) || calls != 1 {
			t.Fatalf("got %x/%v, calls %d", got, err, calls)
		}
	})
	t.Run("malformed ciphertext rejected", func(t *testing.T) {
		ciphertext := make([]byte, priv.Size())
		control, err := priv.Decrypt(nil, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
		if !errors.Is(err, rsa.ErrDecryption) || control != nil {
			t.Fatalf("malformed software control %x/%v", control, err)
		}
		got, err := decryptOAEPFromKeySource(softwareKeySource(priv), ciphertext)
		if !errors.Is(err, rsa.ErrDecryption) || got != nil {
			t.Fatalf("malformed returned %x/%v", got, err)
		}
	})
	t.Run("partial plaintext discarded", func(t *testing.T) {
		sentinel := errors.New("software device operation failed")
		source := softwareKeySource(priv)
		source.private = testDecrypter{public: &priv.PublicKey, decrypt: func(io.Reader, []byte, crypto.DecrypterOpts) ([]byte, error) { return []byte("partial"), sentinel }}
		got, err := decryptOAEPFromKeySource(source, oaep)
		if !errors.Is(err, sentinel) || got != nil {
			t.Fatalf("partial output %x/%v", got, err)
		}
	})
}

func TestDecryptOAEPRoundTrips(t *testing.T) {
	for _, bits := range []int{1024, 2048} {
		t.Run(fmt.Sprintf("RSA%d", bits), func(t *testing.T) {
			priv := newRSAControl(t, bits)
			for _, size := range []int{0, 16, priv.Size() - 2*sha256.Size - 2} {
				t.Run(fmt.Sprintf("length-%d", size), func(t *testing.T) {
					message := make([]byte, size)
					for i := range message {
						message[i] = []byte{0, 0x42, 0xff, 0}[i%4]
					}
					ciphertext := encryptOAEPControl(t, &priv.PublicKey, message, nil)
					control, controlErr := priv.Decrypt(nil, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA256})
					source := softwareKeySource(priv)
					got, err := decryptOAEPFromKeySource(source, ciphertext)
					if err != nil || controlErr != nil || !bytes.Equal(got, message) || !bytes.Equal(control, message) || source.attestCalls != 1 || source.privateCalls != 1 || source.requestedPublic != source.cert.PublicKey {
						t.Fatalf("got %x/%v, control %x/%v, attest/private calls %d/%d", got, err, control, controlErr, source.attestCalls, source.privateCalls)
					}
				})
			}
		})
	}
}

func TestDecryptOAEPParameterBinding(t *testing.T) {
	priv := newRSAControl(t, 2048)
	message := []byte("parameter binding")
	tests := []struct {
		name       string
		ciphertext []byte
	}{
		{"wrong label", encryptOAEPControl(t, &priv.PublicKey, message, []byte("other protocol"))},
		{"wrong hash", nil},
	}
	var err error
	tests[1].ciphertext, err = rsa.EncryptOAEP(crypto.SHA512.New(), rand.Reader, &priv.PublicKey, message, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control, controlErr := priv.Decrypt(nil, tt.ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA256})
			got, err := decryptOAEPFromKeySource(softwareKeySource(priv), tt.ciphertext)
			if !errors.Is(controlErr, rsa.ErrDecryption) || control != nil || !errors.Is(err, rsa.ErrDecryption) || got != nil {
				t.Fatalf("got %x/%v, control %x/%v", got, err, control, controlErr)
			}
		})
	}
}

func TestDecryptPreflight(t *testing.T) {
	priv := newRSAControl(t, 2048)
	ciphertext := encryptOAEPControl(t, &priv.PublicKey, []byte("control"), nil)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		public     crypto.PublicKey
		ciphertext []byte
	}{
		{"short ciphertext", &priv.PublicKey, ciphertext[1:]},
		{"long ciphertext", &priv.PublicKey, append(bytes.Clone(ciphertext), 0)},
		{"concatenated blocks", &priv.PublicKey, append(bytes.Clone(ciphertext), ciphertext...)},
		{"nil ciphertext", &priv.PublicKey, nil},
		{"ciphertext equals N", &priv.PublicKey, priv.N.FillBytes(make([]byte, priv.Size()))},
		{"ciphertext above N", &priv.PublicKey, bytes.Repeat([]byte{0xff}, priv.Size())},
		{"non RSA certificate", &ecdsaKey.PublicKey, ciphertext},
		{"nil RSA key", (*rsa.PublicKey)(nil), ciphertext},
		{"nil modulus", &rsa.PublicKey{E: 65537}, ciphertext},
		{"negative modulus", &rsa.PublicKey{N: new(big.Int).Neg(priv.N), E: 65537}, ciphertext},
		{"bad exponent", &rsa.PublicKey{N: priv.N, E: 1}, ciphertext},
		{"unsupported key size", &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 511), E: 65537}, make([]byte, 64)},
		{"RSA3072 unsupported by v1", &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 3071), E: 65537}, make([]byte, 384)},
		{"RSA4096 unsupported by v1", &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 4095), E: 65537}, make([]byte, 512)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := softwareKeySource(priv)
			source.cert = &x509.Certificate{PublicKey: tt.public}
			got, err := decryptOAEPFromKeySource(source, tt.ciphertext)
			if !errors.Is(err, rsa.ErrDecryption) || got != nil || source.privateCalls != 0 {
				t.Fatalf("got %x/%v, private calls %d", got, err, source.privateCalls)
			}
		})
	}
}

func TestDecryptProviderFailures(t *testing.T) {
	priv := newRSAControl(t, 2048)
	ciphertext := encryptOAEPControl(t, &priv.PublicKey, []byte("control"), nil)
	sentinel := errors.New("test key provider failed")
	wrong := newRSAControl(t, 2048)
	tests := []struct {
		name   string
		modify func(*testDecryptionKeySource)
		want   error
	}{
		{"attestation failure", func(s *testDecryptionKeySource) { s.attestErr = sentinel }, sentinel},
		{"nil certificate", func(s *testDecryptionKeySource) { s.cert = nil }, nil},
		{"nil public key", func(s *testDecryptionKeySource) { s.cert = &x509.Certificate{} }, nil},
		{"private key failure", func(s *testDecryptionKeySource) { s.privateErr = sentinel }, sentinel},
		{"not a decrypter", func(s *testDecryptionKeySource) { s.private = struct{}{} }, nil},
		{"mismatched private public key", func(s *testDecryptionKeySource) { s.private = wrong }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := softwareKeySource(priv)
			tt.modify(source)
			got, err := decryptOAEPFromKeySource(source, ciphertext)
			if err == nil || got != nil || (tt.want != nil && !errors.Is(err, tt.want)) {
				t.Fatalf("got %x/%v", got, err)
			}
		})
	}
}

func TestDecryptNilDevice(t *testing.T) {
	got, err := DecryptOAEP(nil, "unused", zeroSlot(), nil)
	if err == nil || got != nil {
		t.Fatalf("got %x/%v", got, err)
	}
}
