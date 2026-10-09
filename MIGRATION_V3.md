# v3 release impact

Use the narrow v1-based PIV security fork. This change must still be released as
v3, not a v2 patch: the own-fork concrete public types and OAEP ciphertext
contract are intentional compatibility changes. No tag is created by this PR.

- Import github.com/Laisky/go-yubikey/v3 and github.com/Laisky/piv-go/piv together.
  Old upstream YubiKey/Slot types are not interchangeable with fork types.
- Decrypt accepts one RSA-1024/2048 OAEP SHA-256/MGF1 SHA-256/empty-label block.
  Existing PKCS #1 v1.5 and chunked ciphertext must be migrated from trusted
  original plaintext. No legacy fallback is enabled.
- v1 management APIs and 3DES behavior are preserved, including
  WithManagementKeyOut(*[24]byte). No AES or larger device-RSA expansion is added.
- The fork directly pins the reviewed decoder; no application replace is needed.
  Fork Go floor is 1.20; go-yubikey's existing Go 1.26 floor is unchanged.
- Direct crypto.Decrypter callers bypass the wrapper and must migrate their own
  nil options. Keep ECDH/ECIES protocols in their existing non-RSA paths.
- Consumer inventory is incomplete; source review and compile controls do not
  establish complete application acceptance.

Physical acceptance remains outstanding: positive OAEP controls through the
exported wrapper with existing approved RSA keys; full modulus-sized APDU/PCSC
results including leading zeros; PIN/touch policy, cancellation/retry behavior
and signing/attestation compatibility on supported firmware. Keep malformed or
legacy oracle negatives in software/APDU tests. No reset, key generation,
management/PIN/PUK changes, production probing or FIPS acceptance is performed.
