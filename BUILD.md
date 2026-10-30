# Build and verify Vortex Server 2.0.2

The source tree includes only the server command and the modified StormDNS packages required by that command. It does not contain the Android app or its client implementation. The upstream StormDNS base is `ca2eb481fddd4a80d26b3a1a7c714b5aecacecfc`; see `NOTICE` and the included StormDNS licence.

The release builds were made on Linux with Go 1.27.3, `CGO_ENABLED=0`, `-trimpath`, and the command below. Go module dependencies are pinned in `core/go.mod` and `core/go.sum`. The host needs Go 1.26.3 or later and access to the module dependencies; the target VPS only downloads the prebuilt release.

```bash
cd core
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false \
    -ldflags '-s -w -X stormdns-go/vortexsrv.Version=2.0.2' \
    -o "../vortex-server-linux-$arch" ./cmd/vortex-server
done
```

On a host matching the binary architecture, run `./vortex-server-linux-amd64 version` or `./vortex-server-linux-arm64 version`. Run the tests with `go test -race ./cmd/vortex-server` in `core`, and `go test -race ./internal/udpserver ./vortexsrv ./internal/security` in `core/engines/stormdns/src`. Some tests need loopback UDP and Unix-domain sockets.

Release installers are generated from `install.sh` by replacing `__VORTEX_VERSION__`, `__VORTEX_SHA256__`, and `__VORTEX_SHA256_ARM64__` with the release version and corresponding raw-binary SHA-256 digests. The release publishes both raw binaries for the installer and tar.gz archives for manual download.

A local session check proves only the path to the tested endpoint. DNS delegation, public resolvers, a real VPS, and mobile network conditions require separate checks. The downstream DNS response is not encrypted or authenticated by the legacy protocol; use application-layer TLS.

Run `test/installer-sim.sh` from the repository root to exercise the installer against a temporary simulated systemd environment. It uses unprivileged UDP port 15353 by default and does not test a real systemd installation.
