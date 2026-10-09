# v3 release impact

This change must be released as v3, not as a v2 patch. No release tag is created
by this PR.

- Import github.com/Laisky/go-yubikey/v3 and github.com/Laisky/piv-go/v2/piv.
  Exported concrete PIV types now come from the fork.
- Decrypt accepts only one RSA-OAEP SHA-256/MGF1 SHA-256/empty-label block.
  Existing PKCS #1 v1.5 ciphertext and chunked helper output are incompatible.
- WithManagementKeyOut still accepts *[24]byte. On firmware >=5.4 the fork selects
  AES-192 for this size; older firmware uses 3DES.
- The fork revision is directly pinned, so no application replace is needed.
  Upstream PR195 does not block use of the published fork commit.
- Physical-device/PIN/touch/firmware acceptance remains a separate outstanding
  validation. Default tests do not enumerate or modify devices.

Merge/release review must account for caller import changes, ciphertext migration,
management-tool algorithm expectations and physical-device qualification.
