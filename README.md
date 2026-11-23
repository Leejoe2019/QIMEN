# QIMEN · 奇门

**Adaptive, self-evolving network transport (early MVP).**

QIMEN experiments with authenticated, two-ended network path discovery and proxying. The current MVP offers a TLS-protected TCP relay, SOCKS5 CONNECT, a local HTTP proxy (plain HTTP and HTTPS CONNECT), authenticated UDP round-trip probes, a UDP-uplink/TCP-downlink **control-plane** verification probe, periodic path measurement, and multi-server TCP failover/selection.

> **Current limitation:** UDP is **probe-only**, not a user-data path. An authenticated asymmetric **probe** is implemented, but reliable UDP-up/TCP-down payload transport, protocol mutation/evolution, traffic scheduling, and NAT-aware traversal are **not implemented**. SOCKS5 CONNECT, HTTP forward proxy, and HTTP CONNECT all relay user traffic over TLS/TCP.

## Builds

The [Build and test workflow](.github/workflows/build.yml) runs race-enabled integration tests and cross-compiles both `qimen-server` and `qimen-client` for Linux (amd64/arm64), Windows (amd64), and macOS (amd64/arm64). Download binaries from the GitHub Actions run's **Artifacts** section. Build locally with Go 1.23+:

```bash
go test ./...
go build -o qimen-server ./cmd/qimen-server
go build -o qimen-client ./cmd/qimen-client
```

## Quick start (single config file, no runtime environment variables)

Both endpoints use `--config` and read secrets directly from one permission-restricted JSON file. **The old `QIMEN_TOKEN` environment-variable and `--tls-cert`/`--tls-key` CLI startup options have been removed.**

On the server, install one binary at `/usr/local/bin/qimen-server`, one service unit at `/etc/systemd/system/qimen.service`, and one JSON configuration at `/etc/qimen.json` (`0600`). A shortened example:

```json
{
  "listen": "0.0.0.0:18443",
  "udp_listen": "107.173.181.158:18443",
  "token": "REPLACE_WITH_PRIVATE_SHARED_TOKEN",
  "tls_certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "tls_private_key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "dial_timeout": "12s"
}
```

Use actual PEM content escaped as JSON strings. TCP and UDP use **the same numeric port**. They remain separate transport sockets. To strictly use only one TCP listener, set `"udp_listen": "-"`; this disables UDP probes.

On the client, install `qimen-client` and a single private JSON config (for example `/etc/qimen-client.json`):

```json
{
  "listen": "127.0.0.1:1080",
  "http_listen": "127.0.0.1:1081",
  "servers": ["107.173.181.158:18443"],
  "token": "THE_SAME_PRIVATE_SHARED_TOKEN",
  "tls_ca_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "dial_timeout": "12s",
  "probe_interval": "30s",
  "asym_udp_address": "107.173.181.158:18443"
}
```

```bash
chmod 600 /etc/qimen.json
systemctl enable --now qimen

# Run on the client; do not set proxy environment variables:
chmod 600 /etc/qimen-client.json
qimen-client --config /etc/qimen-client.json
curl --proxy http://127.0.0.1:1081 https://example.com/
curl --socks5-hostname 127.0.0.1:1080 https://example.com/

# Optional one-way UDP uplink / TCP downlink control-plane test:
qimen-client --config /etc/qimen-client.json --asym-probe
```

For an exact device-local migration from the previous test deployment, see [single-file migration instructions](docs/deployment-single-file.md). Do not commit private JSON configurations to GitHub. No proxy traffic is carried over UDP yet.

## Security and operational notes

- **TLS 1.3 is mandatory** and verifies the server certificate; server requests also require a shared token. Use a fresh high-entropy token and keep it secret.
- Both local SOCKS5 and HTTP listeners are unauthenticated. **Keep them bound to loopback** (the default); binding either to a public interface creates an unauthenticated proxy entry point.
- The server can connect to any reachable TCP destination. Restrict outbound access with firewall rules if the relay is deployed in an untrusted environment.
- The current UDP probe HMAC prevents unauthorized probe replies. It does not constitute a UDP data transport.
- Discover only nodes and networks you own or are authorized to test. This MVP does not scan broad port ranges or execute generated code.

## Protocol outline

1. Client initiates a TLS 1.3 connection to server, sends a length-prefixed authenticated `ping` or `connect` control message.
2. Server validates token, then sends an acknowledgment or establishes the requested TCP connection.
3. For `connect`, raw TCP application bytes flow bidirectionally inside TLS. Half-closure propagates when possible.
4. Separately, clients send fixed-length HMAC-authenticated UDP probes, receiving same-size replies when UDP round trips work. The optional asymmetric control-plane probe receives its acknowledgment over the authenticated TLS/TCP connection.
5. The client periodically re-measures all configured servers; it selects the fastest TCP path for each new SOCKS CONNECT and falls back if needed.

## Field tests

See [2026-11-23 dev ↔ RackNerd field test](docs/field-tests-2026-11-23.md) for captured direction-specific connectivity, UDP packet-loss curves, TCP baselines, and limitations.

## Roadmap

- Reliable asymmetric UDP-up / TCP-down framing with sequencing, congestion control, loss recovery, encryption, and stateful failover.
- More path candidates (ports, interfaces, protocol families, direction-specific routes) and rate-limited exploration.
- Safe sandbox for AI-generated protocol candidates; reproducible experiments and policy learning.
- Observability, throughput benchmarks, adaptive multipath scheduling, and platform-specific TUN integration.

## License

No license has been selected yet. All rights reserved until the repository owner chooses one.
