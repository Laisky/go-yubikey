package goyubikey

import (
	"bytes"
	"crypto/rsa"
	"testing"

	gutils "github.com/Laisky/go-utils/v4"
	gcrypto "github.com/Laisky/go-utils/v4/crypto"
	"github.com/go-piv/piv-go/piv"
	"github.com/stretchr/testify/require"
)

func getCard(t *testing.T) *piv.YubiKey {
	// glog.Shared.ChangeLevel(glog.LevelDebug)
	cards, err := ListCards(true)
	require.NoError(t, err)
	require.Greater(t, len(cards), 0)
	return cards[0]
}

func getPin(t *testing.T) string {
	// v, err := InputPassword("pin")
	// require.NoError(t, err)

	// v := os.Getenv("PIN")

	v := "123456"
	return v
}

func TestAttest(t *testing.T) {
	card := getCard(t)
	defer card.Close()

	_, err := Attest(card, piv.SlotAuthentication)
	require.NoError(t, err)
}

func TestDecrypt(t *testing.T) {
	card := getCard(t)
	defer card.Close()

	plaintext := gutils.RandomStringWithLength(10)
	pin := getPin(t)

	cert, err := Attest(card, piv.SlotAuthentication)
	require.NoError(t, err)
	pubkey := cert.PublicKey

	cipher, err := gcrypto.RSAEncrypt(pubkey.(*rsa.PublicKey), []byte(plaintext))
	require.NoError(t, err)

	gotplain, err := Decrypt(card, pin, piv.SlotAuthentication, cipher)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(gotplain))
}

func TestSignWithSHA256(t *testing.T) {
	card := getCard(t)
	defer card.Close()

	plaintext := gutils.RandomStringWithLength(10)
	pin := getPin(t)

	sig, err := SignWithSHA256(card, pin, piv.SlotAuthentication, bytes.NewReader([]byte(plaintext)))
	require.NoError(t, err)

	cert, err := Attest(card, piv.SlotAuthentication)
	require.NoError(t, err)
	pubkey := cert.PublicKey

	err = gcrypto.VerifyByRSAWithSHA256(pubkey.(*rsa.PublicKey), []byte(plaintext), sig)
	require.NoError(t, err)
}
