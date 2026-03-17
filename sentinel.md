# Sentinel Security Journal

## 2026-03-17 - Missing input validation in VerifyPIVCerts
**Vulnerability:** `VerifyPIVCerts` panics on nil/empty certificate slice (index out of range on `certs[0]` and `certs[1:]`), causing DoS if called with unvalidated input.
**Learning:** Functions accessing slice indices should always validate bounds first, especially in security-critical certificate verification paths.
**Prevention:** Always add bounds checks before indexing into slices received as parameters.
