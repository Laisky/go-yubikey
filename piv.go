package goyubikey

import (
	"crypto/rand"
	"math/big"

	"github.com/Laisky/errors"
	"github.com/go-piv/piv-go/piv"
)

type resetForPIVOption struct {
	slot         piv.Slot
	requireTouch bool
}

func (o *resetForPIVOption) fillDefault() *resetForPIVOption {
	o.slot = piv.SlotAuthentication
	return o
}

func (o *resetForPIVOption) applyOpts(opts ...ResetForPIVOption) (*resetForPIVOption, error) {
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, errors.Wrap(err, "apply opts")
		}
	}

	return o, nil
}

// ResetForPIVOption is option for ResetForPIV
type ResetForPIVOption func(*resetForPIVOption) error

// WithSlot (optional) set slot for PIV key
//
// default is piv.SlotAuthentication
func WithSlot(slot piv.Slot) ResetForPIVOption {
	return func(o *resetForPIVOption) error {
		o.slot = slot
		return nil
	}
}

// WithRequireTouch (optional) set require touch for PIV key
//
// default is false
func WithRequireTouch() ResetForPIVOption {
	return func(o *resetForPIVOption) error {
		o.requireTouch = true
		return nil
	}
}

// ResetForPIV will reset card and set PUK/PIN/PIV key
func ResetForPIV(card *piv.YubiKey, pin string, opts ...ResetForPIVOption) (err error) {
	opt, err := new(resetForPIVOption).fillDefault().applyOpts(opts...)
	if err != nil {
		return errors.Wrap(err, "apply opts")
	}

	if err = card.Reset(); err != nil {
		return errors.Wrap(err, "reset card")
	}

	//  set randon puk
	puk, err := NewPUK()
	if err != nil {
		return errors.Wrap(err, "gen puk")
	}
	if err = card.SetPUK(piv.DefaultPUK, puk); err != nil {
		return errors.Wrap(err, "set puk")
	}

	//  set pin
	if err = card.SetPIN(piv.DefaultPIN, pin); err != nil {
		return errors.Wrap(err, "set pin")
	}

	// generate private PIV key
	key := piv.Key{
		Algorithm:   piv.AlgorithmRSA2048,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: piv.TouchPolicyNever,
	}

	if opt.requireTouch {
		key.TouchPolicy = piv.TouchPolicyAlways
	}

	_, err = card.GenerateKey(piv.DefaultManagementKey, opt.slot, key)
	if err != nil {
		return errors.Wrap(err, "gen key")
	}

	return nil
}

// NewPUK will generate a random PUK
func NewPUK() (string, error) {
	ret := ""
	for i := 0; i < 8; i++ {
		puk, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", errors.Wrap(err, "gen puk")
		}

		ret += puk.String()
	}

	return ret, nil
}

// NewPIN will generate a random PIN
func NewPIN() (string, error) {
	ret := ""
	for i := 0; i < 8; i++ {
		pin, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", errors.Wrap(err, "gen pin")
		}

		ret += pin.String()
	}

	return ret, nil
}
