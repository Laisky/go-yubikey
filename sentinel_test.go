package goyubikey

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyPIVCerts_Empty(t *testing.T) {
	err := VerifyPIVCerts(nil)
	require.ErrorContains(t, err, "no certificates provided")
}

func TestResetForPIV_ShortPIN(t *testing.T) {
	err := ResetForPIV(nil, "123")
	require.ErrorContains(t, err, "pin is too short")
}
