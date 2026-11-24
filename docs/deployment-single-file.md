# QIMEN production-style deployment (24 November 2026)

## Current two-node installation

RackNerd is restricted to **three QIMEN-managed files** and one numeric listening port:

```text
/usr/local/bin/qimen-server           # GitHub Actions-produced Linux amd64 binary
/etc/systemd/system/qimen.service      # the only QIMEN server service
/etc/qimen.json                        # token and PEM key embedded
```

The single service binds both **TCP 43** and **UDP 43**. TCP and UDP are different sockets, but share the same numeric port. `Environment=` is empty, no secret is passed by CLI flags, and no compiler/toolchain is installed by QIMEN on RackNerd.

On `dev`:

```text
/usr/local/bin/qimen-client
/etc/systemd/system/qimen-client.service
/etc/qimen-client.json
```

The client uses loopback-only `localhost:1080` SOCKS5 and `localhost:1081` HTTP proxy. Its upstream is `YOUR_SERVER_HOST:43`. Set `"transport_mode":"auto"` and `"tls_hello_split":"adaptive"` in the private client config. No application runtime environment variables.

## CI/CD

The public [Build and test Actions workflow](../.github/workflows/build.yml) performs `go test -race`, `go vet`, and static cross-builds on GitHub-hosted runners. The resulting `qimen-server_linux_amd64` and `qimen-client_linux_amd64` are in run artifacts / public `ci-N` prereleases with `SHA256SUMS`.

To upgrade a node, download **only the relevant Actions-built** binary, verify the expected checksum before replacement, restart **only** its QIMEN service, test a real HTTPS proxied request, then delete any temporary ZIP and rollback binary. Do not compile on the server or add another daemon for benchmark or protocol mutation. Every test uses the same QIMEN listener.

## Health and provenance checks

RackNerd:

```sh
systemctl status qimen.service --no-pager
systemctl show qimen.service -p MainPID -p ActiveState -p Environment
ss -lntup | grep qimen
sha256sum /usr/local/bin/qimen-server
```

Client:

```sh
systemctl status qimen-client.service --no-pager
curl --max-time 20 --proxy http://localhost:1081 https://example.com/
curl --max-time 20 --socks5-hostname localhost:1080 https://example.com/
```

## Actual protocol scope

- **Implemented for real proxy traffic:** raw TLS/TCP and authenticated streaming gRPC/HTTP/2/TLS/TCP with per-new-connection selection, fallback, and gRPC connection reuse
- **Experimental for reachability only:** UDP data probes with HMAC and arbitrary logical sequence order; the asymmetric UDP→TCP acknowledgment mechanism
- **Experimental for benchmark only:** QUIC/HTTP3 and gRPC echo tests
- **Optional first-connection mutation:** TLS ClientHello write segmentation (without kernel changes)
- **Not implemented:** REALITY wire compatibility, ECH server support, TCP SYN/ACK rewriting or true kernel TCP segment reordering, reliable QUIC-based SOCKS data forwarding, cross-protocol FEC, self-generating/evaluating arbitrary Python protocol code

Connecting with the server's IP SAN certificate suppresses **DNS SNI in ClientHello** but does not encrypt SNI using ECH. Neither this nor gRPC guarantees bypass of any particular network censor. The TLS private key and token must never be committed or logged. The current self-signed certificate is short-lived; renew before its December 2026 expiration and update the trusted client PEM together.

Historical migration from the original development tree has already been completed; do not attempt the former `/root/qimen-work` migration because those temporary files were intentionally removed.
