package goyubikey

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPIVForkPinMatchesGoMod verifies that ErrOAEPUnsupported and the docs
// tell applications to pin the same piv-go fork version this module builds and
// tests with. Replacements do not propagate, so applications copy that text.
func TestPIVForkPinMatchesGoMod(t *testing.T) {
	gomod, err := os.ReadFile("go.mod")
	require.NoError(t, err)
	m := regexp.MustCompile(`(?m)^replace github\.com/go-piv/piv-go => github\.com/Laisky/piv-go (\S+)$`).FindSubmatch(gomod)
	require.NotNil(t, m, "go.mod must replace piv-go with the Laisky fork")
	version := string(m[1])
	editArg := "-replace=github.com/go-piv/piv-go=github.com/Laisky/piv-go@" + version

	require.Contains(t, ErrOAEPUnsupported.Error(), editArg)

	mention := regexp.MustCompile(`github\.com/Laisky/piv-go[@ ](v\S+)`)
	for _, doc := range []string{"README.md", "COMPATIBILITY.md"} {
		data, err := os.ReadFile(doc)
		require.NoError(t, err)
		require.Contains(t, string(data), editArg, "%s must show the go mod edit command for the pinned fork", doc)
		for _, got := range mention.FindAllSubmatch(data, -1) {
			require.Equal(t, version, string(got[1]), "%s names a piv-go fork version other than go.mod's", doc)
		}
	}
}
