# go-utils v6.4.0 consumer update

The v2 module stays on its existing major and preserves the application-required
piv-go replacement at c682bc1db34c. Only go-utils moves from the qualified
506ec9758d5f pseudo-version to release v6.4.0 (6a02887d3dbf60ecadf21a67b5d3b9449fd942e6).
No PIV identity, slot selection, management key or stored ciphertext migration
is part of the update.

Retained software-key public-API tests use historical v6.2.1 ciphertext fixtures,
single-block success, malformed/chunked/empty rejection, no partial plaintext,
and strict separation of explicit authenticated versus legacy decoding.
Certificate conversion and compile-time upstream PIV package identity are
checked by the ordinary suite. Hardware and destructive reset tests require
separate explicit approval; this task leaves both opt-in flags unset.
Software fixture acceptance does not establish physical-token behavior.

Local baseline/candidate and exact-head CI results are tracked in the PR
description. Rebuild a canary consumer without rewriting stored data; retain
the previous binary/dependency commit for rollback. No merge, token operation
or production rollout is performed by this task.
