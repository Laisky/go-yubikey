package goyubikey

import (
	"crypto/rsa"
	"testing"

	gutils "github.com/Laisky/go-utils/v4"
	gcrypto "github.com/Laisky/go-utils/v4/crypto"
	"github.com/go-piv/piv-go/piv"
	"github.com/stretchr/testify/require"
)

func TestResetForPIV(t *testing.T) {
	card := getCard(t)
	defer card.Close()

	testPin := "123456"
	err := ResetForPIV(card, testPin)
	require.NoError(t, err)

	cert, err := Attest(card, piv.SlotAuthentication)
	require.NoError(t, err)

	t.Run("non-init slot", func(t *testing.T) {
		_, err := Attest(card, piv.SlotSignature)
		require.ErrorContains(t, err, "data object or application not found")
	})

	t.Run("decrypt", func(t *testing.T) {
		plain := gutils.RandomStringWithLength(10)
		cipher, err := gcrypto.RSAEncrypt(cert.PublicKey.(*rsa.PublicKey), []byte(plain))
		require.NoError(t, err)

		plainGot, err := Decrypt(card, testPin, piv.SlotAuthentication, cipher)
		require.NoError(t, err)

		require.Equal(t, plain, string(plainGot))
	})
}
