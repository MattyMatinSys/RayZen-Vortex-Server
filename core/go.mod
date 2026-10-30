module github.com/rayzen/vortex53/core

go 1.26.3

require (
	golang.org/x/net v0.56.0
	stormdns-go v0.0.0
)

require (
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/pierrec/lz4/v4 v4.1.26 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace stormdns-go => ./engines/stormdns/src
