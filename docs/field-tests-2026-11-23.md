# QIMEN network field test — 2026-11-23

## Scope

Authorized two-ended test: `dev` client behind NAT and `racknerd` VPS. The test deliberately avoided existing service ports and did not publish credentials. Server TCP listener: `18443`; asymmetric UDP candidate ingress: `80` and `443`. Client local SOCKS5: `localhost:1080`; HTTP proxy: `localhost:1081`.

**Scope of evidence:** these are brief point-in-time measurements, not sustained capacity guarantees. No network-wide port scans were performed. QIMEN user payloads still flow over TLS/TCP only.

## Evidence of UDP directional asymmetry

An IPv4 UDP probe reached the RackNerd physical Ethernet interface (44-byte authenticated probe). Subsequent synthetic UDP probes on ports 80 and 443 were received by the server application, replied to by the server, and observed as outbound on `eth0` using `tcpdump`, but the client did not receive the replies. A loopback-independent, fixed-source IP echo experiment showed the same behavior. This narrows the failure to the UDP return path **after host transmit** or client ingress; it does not identify a specific censor, ISP, or firewall as the cause.

## Direct TCP observations

- Client-to-server TCP SYN connect (six samples per destination): median ~316 ms for QIMEN TCP 18443, ~326 ms for existing TCP 9443, and ~334 ms for TCP 8443. Outliers approached 1.3 s.
- Native TCP **server-to-client download**: 2,342,864 bytes in 30 s, 78,093 B/s (~0.625 Mb/s); 8 MiB download incomplete.
- QIMEN SOCKS5 TLS/TCP **server-to-client download** to a loopback HTTP benchmark target: 2,195,456 bytes in 30 s, 73,183 B/s (~0.585 Mb/s); incomplete. Different trials, so the small difference is not statistically conclusive.
- Native TCP **client-to-server upload**: 16 MiB posted; server measured 4.94 s for body receipt (~27.17 Mb/s), while curl measured 14.383 s end-to-end including connection setup and response (~9.33 Mb/s).
- The VPS route to the client's public address has `congctl lock brutal` set while global TCP default is cubic. This was **observed only**, not modified; it is not proven to cause the low throughput or high latency.
- The initially deployed client has a 4-second TCP dial timeout, causing intermittent HTTP 502. The code was updated to cap failed UDP probe waits separately, but the device restart with the revised 12-second client timeout was blocked by tool safety controls. The running client may still need a supervised restart.

## UDP synthetic uplink throughput

One-way synthetic datagrams, fixed 1200 bytes, client → server, UDP destination port 443. Server counted unique sequence numbers in received packets; no acknowledgments or reliability layer were used.

| Target offered Mbps | Duration | Sent packets | Received packets | Missing | Loss |
|---:|---:|---:|---:|---:|---:|
| 5 | ~2.88 s | 1500 | 1500 | 0 | 0% |
| 40 | ~0.96 s | 4000 | 3999 | 1 | 0.025% |
| 80 | ~0.48 s | 4000 | 4000 | 0 | 0% |
| 100 | 2 s | 20833 | 20822 | 11 | 0.053% |
| 150 | 2 s | 31250 | 31244 | 6 | 0.019% |
| 160 | 1.5 s | 25000 | 25000 | 0 | 0% |
| 170 | 1.5 s | 26562 | 20655 | 5907 | 22.24% |
| 180 | 1.5 s | 28125 | 15353 | 12772 | 45.41% |
| 200 | 2 s | 41666 | 24657 | 17009 | 40.82% |
| 240 | 2 s | 50000 | 20471 | 29529 | 59.06% |
| 300 | 1 s | 31250 | 24800 | 6450 | 20.64% |

Very short 4,000-packet bursts at 100, 150, 200 and 300 Mbps had almost no loss, but the longer high-rate trials expose severe packet loss. **The highest measured low-loss send rate in these trials was 160 Mbps for 1.5 seconds.** This is a preliminary, not a production-safe sustained rate. The observed rate transition around 160–170 Mbps warrants repetitions and pacing/congestion-control experiments.

**Important direction caveat:** fast UDP client→server transmission is not comparable with slow TCP server→client download. Same-direction TCP upload body receipt was ~27.17 Mb/s in one separate test. These figures cannot be used to claim reliable UDP proxy throughput, especially without acknowledgment, loss recovery, encryption or congestion control.

## Implementation status and next steps

1. **Implemented and CI-tested**: TLS 1.3 TCP relay, SOCKS5 CONNECT, HTTP forward proxy + HTTPS CONNECT, authenticated UDP round-trip probes, optional UDP-uplink/TCP-downlink *control-plane* probe, and multiple TCP server selection.
2. **Not yet implemented**: reliable encrypted UDP user-data uplink, sequencing/reassembly, anti-replay, acknowledgment over TCP, loss recovery, MTU discovery, pacing and congestion control, automatic port/protocol candidate enumeration, throughput-aware path scoring, and automated evolution.
3. **Operationally unverified**: the asymmetric control-plane probe has a passing local integration test, but its device-to-device invocation was blocked by safety controls; do not claim it succeeded across the two hosts.
4. Run longer repeatable tests with explicit upload/download direction and comparable duration; check host and upstream shaping before attempting higher UDP rates.
5. Keep production/user traffic on proven TLS/TCP paths while prototyping the asymmetric data plane in isolated, authenticated tests.

## Security and housekeeping

QIMEN client and server runtime tokens and TLS private keys were not committed or uploaded to public artifact services. The existing PAT file on dev was changed to mode `0600`; its contents were not used in the successful public-source build workflow. Temporary receiver programs were stopped after tests. Review relay outbound destination policy before production deployment.
