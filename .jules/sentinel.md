## 2025-05-14 - [Resource Leaks and Defensive Programming]
**Vulnerability:** Resource leaks in `ListCards` and potential panic in `VerifyPIVCerts`.
**Learning:** Even small utility wrappers should handle partial failures in loops to prevent resource exhaustion (like open smart card handles). Defensive checks for empty inputs are crucial even when "expected" use cases seem clear.
**Prevention:** Always implement cleanup logic for resources opened in a loop if a subsequent operation fails. Validate all external inputs/arguments for boundary conditions (like empty slices).
