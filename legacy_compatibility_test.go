package goyubikey

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/go-piv/piv-go/piv"
)

// Compile-time bindings preserve the existing upstream PIV package identity.
var (
	_ func(bool) ([]*piv.YubiKey, error)                                        = ListCards
	_ func(*piv.YubiKey, piv.Slot) ([]*x509.Certificate, error)                 = Attest2
	_ func(*piv.YubiKey, string, piv.Slot, io.Reader) ([]byte, error)           = SignWithSHA256
	_ func(*piv.YubiKey, string, piv.Slot, []byte) ([]byte, error)              = Decrypt
	_ func(*piv.YubiKey, string, piv.Slot, []byte) ([]byte, error)              = DecryptLegacy
	_ func(*piv.YubiKey, string, ...ResetForPIVOption) error                    = ResetForPIV
	_ func(piv.Slot) ResetForPIVOption                                          = WithSlot
	_ func(*[24]byte) ResetForPIVOption                                         = WithManagementKeyOut
	_ func(*piv.YubiKey, [24]byte, [24]byte) error                              = (*piv.YubiKey).SetManagementKey
	_ func(*piv.YubiKey, [24]byte, piv.Slot, piv.Key) (crypto.PublicKey, error) = (*piv.YubiKey).GenerateKey
)

type historicalFixture struct {
	Name                                   string
	Bits                                   int
	PrivateKeyPKCS1, Plaintext, Ciphertext string
	SingleBlock                            bool
}

func loadHistoricalFixtures(t *testing.T) []historicalFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/historical-v6.2.1-rsa-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []historicalFixture
	if err = json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}
func historicalFixtureBytes(t *testing.T, s string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func installTestKeySource(t *testing.T, source decryptionKeySource) {
	t.Helper()
	previous := newDecryptionKeySource
	t.Cleanup(func() { newDecryptionKeySource = previous })
	newDecryptionKeySource = func(*piv.YubiKey, string, piv.Slot) decryptionKeySource { return source }
}

// These retained ciphertexts were generated once by the actual historical
// go-utils/v6 v6.2.1 RSAEncrypt used at 3ad2190. Keys and data are synthetic.
// The public API executes normally; only attestation/private-key acquisition
// are replaced with a software key. This does not validate physical hardware.
func TestHistoricalCiphertextPublicAPICompatibility(t *testing.T) {
	for _, f := range loadHistoricalFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			priv, err := x509.ParsePKCS1PrivateKey(historicalFixtureBytes(t, f.PrivateKeyPKCS1))
			if err != nil {
				t.Fatal(err)
			}
			cipher := historicalFixtureBytes(t, f.Ciphertext)
			want := historicalFixtureBytes(t, f.Plaintext)
			source := softwareKeySource(priv)
			calls := 0
			source.private = testDecrypter{public: &priv.PublicKey, decrypt: func(r io.Reader, c []byte, o crypto.DecrypterOpts) ([]byte, error) {
				calls++
				if o != nil {
					t.Fatalf("legacy options changed: %#v", o)
				}
				return priv.Decrypt(r, c, o)
			}}
			installTestKeySource(t, source)
			for _, api := range []struct {
				name string
				fn   func(*piv.YubiKey, string, piv.Slot, []byte) ([]byte, error)
			}{
				{"existing Decrypt", Decrypt}, {"explicit DecryptLegacy", DecryptLegacy},
			} {
				t.Run(api.name, func(t *testing.T) {
					got, err := api.fn(&piv.YubiKey{}, "unused", piv.SlotKeyManagement, cipher)
					if f.SingleBlock {
						if err != nil || !bytes.Equal(got, want) {
							t.Fatalf("historical data changed: %x/%v; want %x", got, err, want)
						}
					} else if err == nil || got != nil {
						t.Fatalf("unsupported historical empty/chunked input accepted: %x/%v", got, err)
					}
				})
			}
			if calls != 2 {
				t.Fatalf("legacy dispatch calls=%d, want 2", calls)
			}
		})
	}
}

func TestLegacyFailuresReturnNoPartialPlaintext(t *testing.T) {
	priv := newRSAControl(t, 2048)
	for _, cipher := range [][]byte{nil, {0}, make([]byte, priv.Size()), make([]byte, priv.Size()-1), make([]byte, priv.Size()+1)} {
		source := softwareKeySource(priv)
		source.private = priv
		got, err := decryptLegacyFromKeySource(source, cipher)
		if err == nil || got != nil {
			t.Fatalf("malformed legacy input returned %x/%v", got, err)
		}
	}
	sentinel := errors.New("legacy software operation failed")
	source := softwareKeySource(priv)
	source.private = testDecrypter{public: &priv.PublicKey, decrypt: func(io.Reader, []byte, crypto.DecrypterOpts) ([]byte, error) { return []byte("partial"), sentinel }}
	installTestKeySource(t, source)
	got, err := Decrypt(&piv.YubiKey{}, "unused", piv.SlotKeyManagement, make([]byte, priv.Size()))
	if !errors.Is(err, sentinel) || got != nil {
		t.Fatalf("partial legacy output %x/%v", got, err)
	}
}

func TestExplicitEncryptOAEPAndPublicDecrypt(t *testing.T) {
	for _, bits := range []int{1024, 2048} {
		priv := newRSAControl(t, bits)
		source := softwareKeySource(priv)
		installTestKeySource(t, source)
		for _, n := range []int{0, 16, priv.Size() - 66} {
			plain := bytes.Repeat([]byte{0x42}, n)
			cipher, err := EncryptOAEP(&priv.PublicKey, plain)
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecryptOAEP(&piv.YubiKey{}, "unused", piv.SlotKeyManagement, cipher)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("new API roundtrip %x/%v", got, err)
			}
			// RSA padding encodings are not self-identifying: a random OAEP
			// block can also satisfy PKCS checks. Verify explicit selection
			// against the PKCS control instead of inferring format from failure.
			control, controlErr := priv.Decrypt(rand.Reader, cipher, nil)
			calls := 0
			source.private = testDecrypter{public: &priv.PublicKey, decrypt: func(r io.Reader, c []byte, o crypto.DecrypterOpts) ([]byte, error) {
				calls++
				if o != nil {
					t.Fatalf("legacy operation changed padding: %#v", o)
				}
				return priv.Decrypt(r, c, o)
			}}
			legacy, legacyErr := Decrypt(&piv.YubiKey{}, "unused", piv.SlotKeyManagement, cipher)
			if calls != 1 || (controlErr == nil) != (legacyErr == nil) || !bytes.Equal(legacy, control) {
				t.Fatalf("legacy dispatch differs from PKCS control: %x/%v vs %x/%v calls%d", legacy, legacyErr, control, controlErr, calls)
			}
			source.private = testOAEPPrivateKey{priv}
		}
		cipher, err := EncryptOAEP(&priv.PublicKey, make([]byte, priv.Size()-65))
		if !errors.Is(err, rsa.ErrMessageTooLong) || cipher != nil {
			t.Fatalf("oversized OAEP %x/%v", cipher, err)
		}
		// A valid old ciphertext must be rejected by the explicit secure API.
		legacy, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, []byte("old control"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecryptOAEP(&piv.YubiKey{}, "unused", piv.SlotKeyManagement, legacy)
		if !errors.Is(err, rsa.ErrDecryption) || got != nil {
			t.Fatalf("OAEP silently selected legacy: %x/%v", got, err)
		}
	}
}

type noOAEPMarkerDecrypter struct{ crypto.Decrypter }
type falseOAEPMarkerDecrypter struct{ crypto.Decrypter }

func (falseOAEPMarkerDecrypter) SupportsRSAOAEP() bool { return false }
func TestOAEPRejectsUnreviewedDependency(t *testing.T) {
	priv := newRSAControl(t, 2048)
	cipher, err := EncryptOAEP(&priv.PublicKey, []byte("control"))
	if err != nil {
		t.Fatal(err)
	}
	for _, falseMarker := range []bool{false, true} {
		calls := 0
		d := testDecrypter{public: &priv.PublicKey, decrypt: func(io.Reader, []byte, crypto.DecrypterOpts) ([]byte, error) {
			calls++
			return nil, errors.New("unexpected decrypt")
		}}
		source := softwareKeySource(priv)
		if falseMarker {
			source.private = falseOAEPMarkerDecrypter{d}
		} else {
			source.private = noOAEPMarkerDecrypter{d}
		}
		installTestKeySource(t, source)
		got, err := DecryptOAEP(&piv.YubiKey{}, "unused", piv.SlotKeyManagement, cipher)
		if !errors.Is(err, ErrOAEPUnsupported) || got != nil || calls != 0 {
			t.Fatalf("unreviewed decrypt reached: %x/%v calls%d", got, err, calls)
		}
	}
}

func TestEncryptOAEPInvalidKeys(t *testing.T) {
	for _, key := range []*rsa.PublicKey{nil, {}, {E: 65537}, {N: newRSAControl(t, 2048).N, E: 1}} {
		cipher, err := EncryptOAEP(key, []byte("control"))
		if err == nil || cipher != nil {
			t.Fatalf("invalid key accepted %x/%v", cipher, err)
		}
	}
}
