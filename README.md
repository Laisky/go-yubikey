# go-yubikey

Some utils wrap for <https://github.com/go-piv/piv-go>.

| Version | Supported Golang |
| ------- | ---------------- |
| v1      | 1.20+             |

[Installation](https://github.com/go-piv/piv-go/blob/1902689552e974ba88750e3ab71902d253172ead/README.md#installation)

## New Features

```go
// VerifyPIVCerts verify certs exported from yubikey PIV slots by Yubico PIV root ca
func VerifyPIVCerts(certs []*x509.Certificate) error

// ListCards function lists all Yubikey plugin cards.
//
// Note that Yubikey does not allow concurrent access,
// and attempting to do so will result in an error message
// "connecting to smart card: the smart card cannot be accessed
// because of other connections outstanding".
//
// Therefore, it is necessary to make sure that each card is
// properly closed after being used.
func ListCards(skipInvalidCard bool) (cards []*piv.YubiKey, err error)

// InputPassword reads password from stdin input
// and returns it as a string.
func InputPassword(hint string) (string, error)

// Attest attests a Yubikey slot by the Yubico root CA.
func Attest(yk *piv.YubiKey, slot piv.Slot) error

// Decrypt decrypt by slot's private key
func Decrypt(yk *piv.YubiKey,
    pin string,
    slot piv.Slot,
    cipher []byte) (plaintext []byte, err error)

// SignWithSHA256 signs the content using the private key present in the slot
// described by YubiKey.
// It returns the signature or an error in case of any failures.
func SignWithSHA256(yk *piv.YubiKey,
    pin string,
    slot piv.Slot,
    content io.Reader) (signature []byte, err error)


// ResetForPIV will reset card and set PUK/PIN/PIV key
func ResetForPIV(card *piv.YubiKey, pin string, opts ...ResetForPIVOption) (err error)
```
