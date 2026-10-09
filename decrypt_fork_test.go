package goyubikey

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/piv"
)

// TestDecryptConcretePIVBoundary invokes the real fork decrypter and stops before any
// device transaction at a deliberately failing test-only PIN callback.
// With unmodified upstream it must instead reject the missing capability before
// invoking that callback. External consumers run this same test in both graphs.
func TestDecryptConcretePIVBoundary(t *testing.T) {
	priv := newRSAControl(t, 2048)
	ciphertext := encryptOAEPControl(t, &priv.PublicKey, []byte("concrete fork control"), nil)
	prompts := 0
	sentinel := errors.New("test-only callback stops before device authentication")
	key, err := (&piv.YubiKey{}).PrivateKey(piv.SlotAuthentication, &priv.PublicKey, piv.KeyAuth{
		PINPolicy: piv.PINPolicyAlways,
		PINPrompt: func() (string, error) { prompts++; return "", sentinel },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := key.(crypto.Decrypter); !ok {
		t.Fatal("actual fork key does not implement crypto.Decrypter")
	}
	source := softwareKeySource(priv)
	source.private = key
	previous := newDecryptionKeySource
	t.Cleanup(func() { newDecryptionKeySource = previous })
	newDecryptionKeySource = func(*piv.YubiKey, string, piv.Slot) decryptionKeySource { return source }
	plain, err := DecryptOAEP(&piv.YubiKey{}, "unused", piv.SlotAuthentication, ciphertext)
	capable, ok := key.(interface{ SupportsRSAOAEP() bool })
	if !ok || !capable.SupportsRSAOAEP() {
		if !errors.Is(err, ErrOAEPUnsupported) || plain != nil || prompts != 0 || source.privateCalls != 1 {
			t.Fatalf("unmodified upstream reached PIN/decrypt: %x/%v prompts%d/private%d", plain, err, prompts, source.privateCalls)
		}
		t.Log("actual unmodified upstream rejected before its PIN callback/decryption")
		return
	}
	t.Log("actual reviewed fork selected; valid input stopped at test-only PIN callback")
	if err == nil || !strings.Contains(err.Error(), sentinel.Error()) || plain != nil || prompts != 1 || source.privateCalls != 1 {
		t.Fatalf("unexpected concrete fork boundary: %x/%v, prompts/private calls%d/%d", plain, err, prompts, source.privateCalls)
	}
	// Invalid framing must stop before acquiring the real private handle.
	source = softwareKeySource(priv)
	source.private = key
	plain, err = DecryptOAEP(&piv.YubiKey{}, "unused", piv.SlotAuthentication, make([]byte, priv.Size()-1))
	if !errors.Is(err, rsa.ErrDecryption) || plain != nil || prompts != 1 || source.privateCalls != 0 {
		t.Fatalf("invalid ciphertext reached real fork auth: %x/%v prompts/private calls%d/%d", plain, err, prompts, source.privateCalls)
	}
}
