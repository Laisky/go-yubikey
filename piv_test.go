package goyubikey

import (
	"crypto/rsa"
	"testing"

	gutils "github.com/Laisky/go-utils/v6"
	gcrypto "github.com/Laisky/go-utils/v6/crypto"
	"github.com/go-piv/piv-go/piv"
	"github.com/stretchr/testify/require"
)

func TestValidatePIN(t *testing.T) {
	tests := []struct {
		name    string
		pin     string
		wantErr bool
	}{
		{"valid 6 digits", "123456", false},
		{"valid 8 digits", "12345678", false},
		{"too short", "12345", true},
		{"too long", "123456789", true},
		{"empty", "", true},
		{"non-digit", "12345a", true},
		{"spaces", "123 56", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePIN(tt.pin)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestResetForPIV(t *testing.T) {
	card := getCard(t)
	defer card.Close()

	testPin := "123456"
	var mgmtKey [24]byte
	err := ResetForPIV(card, testPin, WithManagementKeyOut(&mgmtKey))
	require.NoError(t, err)
	require.NotEqual(t, [24]byte{}, mgmtKey, "management key should be randomized")

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
