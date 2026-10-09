module github.com/Laisky/go-yubikey/v2

go 1.26.0

require (
	github.com/Laisky/errors/v2 v2.0.1
	github.com/Laisky/go-utils/v6 v6.3.2-0.20261008165128-506ec9758d5f
	github.com/Laisky/zap v1.27.1-0.20261006114731-55f41c2b5061
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
	github.com/emmansun/gmsm v0.45.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/gammazero/deque v1.2.1 // indirect
	github.com/google/go-cpy v0.0.0-20211218193943-a9c933c06932 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180228061459-e0a39a4cb421 // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/monnand/dhkx v0.0.0-20180522003156-9e5b033f1ac4 // indirect
	github.com/tailscale/hujson v0.0.0-20260302212456-ecc657c15afd // indirect
	github.com/xlzd/gotp v0.1.0 // indirect
	go.dedis.ch/kyber/v3 v3.1.0 // indirect
	go.uber.org/automaxprocs v1.6.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/term v0.46.0 // indirect
	golang.org/x/tools v0.1.5 // indirect
)

// Applications must copy this replacement; dependency replacements do not propagate.
replace github.com/go-piv/piv-go => github.com/Laisky/piv-go v1.11.1-0.20261009203706-c682bc1db34c
