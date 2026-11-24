# QIMEN · 奇门

**Adaptive, self-evolving network transport (early MVP).**

QIMEN experiments with authenticated, two-ended network path discovery and proxying. The MVP supports SOCKS5 and local HTTP CONNECT/forward proxying, **two real encrypted TCP user-data transports** (raw TLS 1.3 and full-duplex gRPC over HTTP/2), selection by periodic transport RTT with fallback, optional TLS ClientHello TCP-write segmentation on the raw-TLS path, authenticated UDP probes, and separate QUIC/HTTP3 and HMAC-UDP experiments.

> **Current limitation:** UDP is **probe-only**, not a user-data path. An authenticated asymmetric **probe** is implemented, but reliable UDP-up/TCP-down payload transport, protocol mutation/evolution, traffic scheduling, and NAT-aware traversal are **not implemented**. SOCKS5 CONNECT, HTTP forward proxy, and HTTP CONNECT relay user traffic using raw TLS/TCP or genuine HTTP/2 gRPC/TLS/TCP. UDP and HTTP/3 are probe/benchmark only.

## Builds

The [Build and test workflow](.github/workflows/build.yml) runs race-enabled integration tests and cross-compiles both `qimen-server` and `qimen-client` for Linux (amd64/arm64), Windows (amd64), and macOS (amd64/arm64). Download binaries from the GitHub Actions run's **Artifacts** section. Build locally with Go 1.23+:

```bash
go test ./...
go build -o qimen-server ./cmd/qimen-server
go build -o qimen-client ./cmd/qimen-client
```

## Quick start (single config file, no runtime environment variables)

Both endpoints use `--config` and read secrets directly from one JSON file. **The old `QIMEN_TOKEN` environment-variable and `--tls-cert`/`--tls-key` CLI startup options have been removed.**

On the server, install one binary at `/usr/local/bin/qimen-server`, one service unit at `/etc/systemd/system/qimen.service`, and one JSON configuration at `/etc/qimen.json` (restrict access if desired). A shortened example:

```json
{
  "listen": ":43",
  "udp_listen": "YOUR_SERVER_HOST:43",
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
  "listen": "localhost:1080",
  "http_listen": "localhost:1081",
  "servers": ["YOUR_SERVER_HOST:43"],
  "token": "THE_SAME_PRIVATE_SHARED_TOKEN",
  "tls_ca_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "dial_timeout": "12s",
  "probe_interval": "30s",
  "asym_udp_address": "YOUR_SERVER_HOST:43",
  "transport_mode": "auto",
  "tls_hello_split": "adaptive"
}
```

```bash
systemctl enable --now qimen

# Run on the client; do not set proxy environment variables:
qimen-client --config /etc/qimen-client.json
curl --proxy http://localhost:1081 https://example.com/
curl --socks5-hostname localhost:1080 https://example.com/

# Optional one-way UDP uplink / TCP downlink control-plane test:
qimen-client --config /etc/qimen-client.json --asym-probe
```

For an exact device-local migration from the previous test deployment, see [single-file migration instructions](docs/deployment-single-file.md). Do not commit private JSON configurations to GitHub. No proxy traffic is carried over UDP yet.

## Adaptive encrypted transports

- `transport_mode: "auto"` (default) probes raw TLS and gRPC/HTTP2 separately, uses a warmed gRPC channel when its measured latency is lower, and falls back if a new tunnel fails. `"tcp"` forces raw TLS and `"grpc"` forces real gRPC streaming.
- `tls_hello_split: "adaptive"` (default) retries the first raw TLS ClientHello as two write chunks (after bytes 5 or 1) if a normal handshake fails; `"off"`, `"split5"` and `"split1"` are also supported. This **does not** modify TCP sequence numbers, forge SYN/ACK, or guarantee distinct wire segments because kernel offload and middleboxes can coalesce writes.
- Both transports use a pinned self-signed certificate with an **IP subjectAltName**. With no `tls_server_name` override, the IP address is used for certificate validation and Go TLS omits a DNS SNI. **Omission is not ECH or REALITY**; IP, timing and TLS fingerprints remain observable.
- The optional `--bench udp-up --bench-udp-order reverse8` experiment sends authenticated UDP frames with sequence values reversed in 8-frame windows. It validates logical out-of-order packet handling, not raw TCP reordering. User payloads are **not** sent over UDP.
- HTTP/3 is a genuine QUIC implementation under the same UDP numeric port, currently for testing only; if the UDP return path fails, it is not a candidate for user-data proxying.

## Security and operational notes

- **TLS 1.3 is mandatory** and verifies the server certificate; server requests also require a shared token. Use a fresh high-entropy token and keep it secret.
- Both local SOCKS5 and HTTP listeners are unauthenticated. **Keep them bound to loopback** (the default); binding either to a public interface creates an unauthenticated proxy entry point.
- The server can connect to any reachable TCP destination. Restrict outbound access with firewall rules if the relay is deployed in an untrusted environment.
- The current UDP probe HMAC prevents unauthorized probe replies. It does not constitute a UDP data transport.
- Discover only nodes and networks you own or are authorized to test. This MVP does not scan broad port ranges or execute generated code.

## Protocol outline

1. Client initiates a TLS 1.3 connection to server, sends a length-prefixed authenticated `ping` or `connect` control message.
2. Server validates token, then sends an acknowledgment or establishes the requested TCP connection.
3. For `connect`, client TCP streams flow bidirectionally inside raw TLS or authenticated gRPC/HTTP2 streaming; client chooses the route per new connection.
4. Separately, clients send fixed-length HMAC-authenticated UDP probes, receiving same-size replies when UDP round trips work. The optional asymmetric control-plane probe receives its acknowledgment over the authenticated TLS/TCP connection.
5. The client periodically re-measures server and transport availability. It selects by measured RTT, uses gRPC connection reuse, and falls back to the other TCP transport if a new tunnel fails. This is not yet throughput-aware AI evolution.

## Field tests

See [2026-11-23 dev ↔ RackNerd field test](docs/field-tests-2026-11-23.md) for captured direction-specific connectivity, UDP packet-loss curves, TCP baselines, and limitations.

## Roadmap

- Reliable asymmetric UDP-up / TCP-down framing with sequencing, congestion control, loss recovery, encryption, and stateful failover.
- Throughput-aware scoring, additional independently verified protocol candidates, reproducible mutation experiments, rate-limited exploration and per-environment learning.
- Safe sandbox for AI-generated protocol candidates; reproducible experiments and policy learning.
- Observability, throughput benchmarks, adaptive multipath scheduling, and platform-specific TUN integration.

## License

No license has been selected yet. All rights reserved until the repository owner chooses one.
