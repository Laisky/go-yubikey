module github.com/Laisky/go-yubikey/v2

go 1.26.0

require (
	github.com/Laisky/errors/v2 v2.0.1
	github.com/Laisky/go-utils/v6 v6.4.1-0.20261105224149-8b2d8813f2ec
	github.com/Laisky/zap v1.27.1-0.20261010181908-c0039128a331
	github.com/go-piv/piv-go v1.11.0
	github.com/stretchr/testify v1.12.1
)

require (
	github.com/Laisky/fast-skiplist/v2 v2.0.1 // indirect
	github.com/Laisky/go-chaining v0.0.0-20180507092046-43dcdc5a21be // indirect
	github.com/Laisky/golang-fifo v1.0.1-0.20240403092208-1d90c6c33e11 // indirect
	github.com/Laisky/graphql v1.0.6 // indirect
	github.com/alexvec/go-bip39 v1.1.0 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/emmansun/gmsm v0.45.2 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/gammazero/deque v1.2.3 // indirect
	github.com/google/go-cpy v0.0.0-20211218193943-a9c933c06932 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/monnand/dhkx v0.0.0-20180522003156-9e5b033f1ac4 // indirect
	github.com/spiffe/go-spiffe/v2 v2.9.0 // indirect
	github.com/tailscale/hujson v0.0.0-20260727124030-b80ff77dac4f // indirect
	github.com/xlzd/gotp v0.1.0 // indirect
	go.dedis.ch/kyber/v3 v3.1.0 // indirect
	go.uber.org/automaxprocs v1.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/lint v0.0.0-20241112194109-818c5a804067 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/term v0.47.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
)

// Applications must copy this replacement; dependency replacements do not propagate.
replace github.com/go-piv/piv-go => github.com/Laisky/piv-go v1.11.1-0.20261107023153-21534d503c8c
