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

## Quick start

Generate a private TLS certificate with an appropriate SAN matching your server name/IP (example for testing on localhost):

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server.key -out server.crt -days 30 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
export QIMEN_TOKEN="$(openssl rand -hex 32)"
```

Use the **same secret** on both endpoints; distribute it over a secure channel. On the server:

```bash
QIMEN_TOKEN='shared-long-random-secret' ./qimen-server \
  --listen 0.0.0.0:8443 \
  --tls-cert server.crt --tls-key server.key
```

On your client (use the real reachable server address, an appropriate certificate, and matching token):

```bash
QIMEN_TOKEN='shared-long-random-secret' ./qimen-client \
  --servers 'your-server.example:8443' --ca server.crt \
  --listen 127.0.0.1:1080 --http-listen 127.0.0.1:1081
```

Configure a SOCKS5 client for `127.0.0.1:1080`, or test via `curl --socks5-hostname 127.0.0.1:1080 https://example.com/`. For conventional proxy environment variables, use:

```bash
export http_proxy=http://127.0.0.1:1081
export https_proxy=http://127.0.0.1:1081
curl --proxy http://127.0.0.1:1081 https://example.com/
```

Both listeners default to **loopback only**. The HTTP proxy has no client authentication: do not expose it publicly.

### One-way UDP + TCP return experiment

Use a UDP listener on the server (for example `--udp-listen PUBLIC_IP:80`, where the port must be free and authorized). On the client:

```bash
QIMEN_TOKEN='your-secret' ./qimen-client \
  --asym-probe --servers PUBLIC_IP:18443 \
  --asym-udp-address PUBLIC_IP:80 --ca server.crt --dial-timeout 12s
```

The probe registers a random nonce over authenticated TLS/TCP, sends an HMAC-authenticated UDP datagram, and requests an acknowledgment **over TCP/TLS**. It does not carry user payloads over UDP. A successful probe proves one tested asymmetric path, not an optimized data transport.

For server IPs that do not match the certificate SAN, regenerate the certificate with that IP as an `IP:` SAN, or use a resolvable hostname with a matching SAN. Certificate verification is never disabled. `--tls-server-name` can override the expected name for special DNS/routing arrangements.

Both TCP and UDP port 8443 should be permitted for dual-protocol probes. If UDP cannot be bound, use `--udp-listen -` on the server to explicitly disable the UDP probe listener. For multiple relay nodes supply `--servers 'node1:8443,node2:8443'` (all should present certificates trusted under the client configuration). The client probes each server periodically, logs independent TCP/UDP path reachability and RTT, and routes new TCP sessions through the fastest currently responding TCP server, falling back if a connect fails.

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
