package goyubikey

import (
	"testing"

	"github.com/Laisky/errors/v2"
	"github.com/stretchr/testify/require"
)

// errFakeOpen is the error fakeOpener returns for a failing card.
var errFakeOpen = errors.New("fake open failure")

// fakeCard is a test double for an opened smart card that counts Close calls.
type fakeCard struct {
	name     string
	closed   int
	closeErr error
}

// Close records that the card was closed and returns closeErr.
func (c *fakeCard) Close() error {
	c.closed++
	return c.closeErr
}

// fakeOpener returns an open function that fails with errFakeOpen for the
// names in failing and records every card it opens, so tests can inspect
// which handles were closed.
func fakeOpener(failing map[string]bool, opened *[]*fakeCard) func(string) (*fakeCard, error) {
	return func(name string) (*fakeCard, error) {
		if failing[name] {
			return nil, errors.Wrapf(errFakeOpen, "cannot open %s", name)
		}
		c := &fakeCard{name: name}
		*opened = append(*opened, c)
		return c, nil
	}
}

// TestOpenYubiKeyCardsClosesOpenedCardsOnFailure verifies that a strict listing
// releases every handle it already opened when a later YubiKey fails to open.
func TestOpenYubiKeyCardsClosesOpenedCardsOnFailure(t *testing.T) {
	var opened []*fakeCard
	names := []string{"Yubico YubiKey OTP+FIDO+CCID 00", "Other Reader", "Yubico YubiKey OTP+FIDO+CCID 01", "Yubico YubiKey OTP+FIDO+CCID 02"}
	open := fakeOpener(map[string]bool{names[3]: true}, &opened)

	cards, err := openYubiKeyCards(names, open, false)
	require.ErrorIs(t, err, errFakeOpen)
	require.ErrorContains(t, err, names[3])
	require.Nil(t, cards)
	require.Len(t, opened, 2)
	for _, c := range opened {
		require.Equal(t, 1, c.closed, "card %q must be closed exactly once", c.name)
	}
}

// TestOpenYubiKeyCardsKeepsOpenErrorWhenCloseFails verifies that a failing
// Close during cleanup neither stops the remaining cards from being closed
// nor replaces the open error the caller receives.
func TestOpenYubiKeyCardsKeepsOpenErrorWhenCloseFails(t *testing.T) {
	var opened []*fakeCard
	names := []string{"Yubico YubiKey 00", "Yubico YubiKey 01", "Yubico YubiKey 02"}
	fakeOpen := fakeOpener(map[string]bool{names[2]: true}, &opened)
	errClose := errors.New("fake close failure")
	open := func(name string) (*fakeCard, error) {
		c, err := fakeOpen(name)
		if err == nil && name == names[0] {
			c.closeErr = errClose
		}
		return c, err
	}

	cards, err := openYubiKeyCards(names, open, false)
	require.ErrorIs(t, err, errFakeOpen)
	require.NotErrorIs(t, err, errClose)
	require.Nil(t, cards)
	require.Len(t, opened, 2)
	for _, c := range opened {
		require.Equal(t, 1, c.closed, "card %q must be closed exactly once", c.name)
	}
}

// TestOpenYubiKeyCardsSkipsInvalidCards verifies that a lenient listing keeps
// the cards that opened, leaves them open for the caller, and ignores
// readers that are not YubiKeys.
func TestOpenYubiKeyCardsSkipsInvalidCards(t *testing.T) {
	var opened []*fakeCard
	names := []string{"Yubico YubiKey 00", "Other Reader", "Yubico YubiKey 01", "Yubico YubiKey 02"}
	open := fakeOpener(map[string]bool{names[2]: true}, &opened)

	cards, err := openYubiKeyCards(names, open, true)
	require.NoError(t, err)
	require.Len(t, cards, 2)
	require.Equal(t, names[0], cards[0].name)
	require.Equal(t, names[3], cards[1].name)
	for _, c := range opened {
		require.Zero(t, c.closed, "card %q must stay open for the caller", c.name)
	}
}

// TestOpenYubiKeyCardsFailsOnFirstCard verifies that a failure on the first
// YubiKey returns the error without closing anything.
func TestOpenYubiKeyCardsFailsOnFirstCard(t *testing.T) {
	var opened []*fakeCard
	names := []string{"Yubico YubiKey 00"}

	cards, err := openYubiKeyCards(names, fakeOpener(map[string]bool{names[0]: true}, &opened), false)
	require.ErrorIs(t, err, errFakeOpen)
	require.Nil(t, cards)
	require.Empty(t, opened)
}

// TestKeepFirstCardClosesUnusedCards verifies that the hardware-test helper
// closes every card it does not hand to the test, so a host with several
// YubiKeys does not keep exclusive connections open across tests.
func TestKeepFirstCardClosesUnusedCards(t *testing.T) {
	cards := []*fakeCard{{name: "Yubico YubiKey 00"}, {name: "Yubico YubiKey 01"}, {name: "Yubico YubiKey 02"}}

	first := keepFirstCard(t, cards)
	require.Same(t, cards[0], first)
	require.Zero(t, first.closed, "the returned card stays open for the test")
	for _, c := range cards[1:] {
		require.Equal(t, 1, c.closed, "unused card %q must be closed exactly once", c.name)
	}
}
