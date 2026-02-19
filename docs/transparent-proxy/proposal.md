# Transparent Proxy Mode — Proposal

## Problem

Gap's credential proxy (the existing CONNECT proxy) handles credential injection for cooperating HTTP clients. But a container/VM can make network calls that bypass the credential proxy entirely — subprocesses, libraries that ignore proxy settings, non-HTTP protocols. There's no way to know what the agent is doing outside the credential proxy channel.

## Proposal

Add a **transparent MITM proxy** that captures all network traffic not destined for the credential proxy. The two proxies serve different purposes and work together:

```
Container/VM
  │
  ├─ Traffic to gap:9443 ──→ Credential Proxy (existing CONNECT proxy)
  │   (allowed by network rules)   Credential injection, plugin transforms
  │
  └─ Everything else ──→ Transparent MITM Proxy (new)
      (iptables REDIRECT)   Inspect, log, allow/block — no credential injection
```

**The credential proxy is for enabling access.** The transparent proxy is for **preventing uncontrolled access** — a security boundary and audit layer.

### Core Design Principle

**Default-deny all.** The transparent proxy blocks all traffic by default — even protocol categories it knows how to handle. Each protocol category (HTTPS, generic TLS, DNS, QUIC, SSH) must be **explicitly enabled** in server configuration. An unconfigured transparent proxy is a brick wall.

Two layers of deny:
1. **Protocol category must be enabled** — even if gap can handle HTTPS, it won't until you turn it on
2. **Host must be on the allow-list** — even with HTTPS enabled, traffic to unlisted hosts is blocked

The container/VM can only communicate using protocols and hosts the operator has explicitly permitted. Everything else is dropped and logged.

V1 supports a single protocol category: **HTTPS (HTTP/1.1 + HTTP/2)**. Future phases add more categories that can be independently enabled.

### Authentication

Source IP → agent token mapping via CIDR ranges. Each container/VM gets an IP range associated with an agent identity for attribution in activity logs. Traffic from unmapped IPs is rejected.

```
172.17.0.2/32  →  agent-alpha
10.0.1.0/24   →  agent-beta
```

## Architecture

### Network Model

The network rules (iptables/pf) create two paths:

1. **Credential proxy port (9443)** — allowed through directly. The agent's HTTP client is configured to use this as an explicit proxy for API calls that need credential injection.
2. **Everything else** — redirected to the transparent MITM port (9444). Gap inspects the traffic, checks it against policy, and either forwards or drops it.

**Linux (iptables):**
```bash
# Allow traffic to the credential proxy port (don't redirect it)
iptables -t nat -A PREROUTING -i docker0 -p tcp --dport 9443 -j ACCEPT

# Redirect everything else to the transparent MITM port
iptables -t nat -A PREROUTING -i docker0 -p tcp -j REDIRECT --to-port 9444
```

**macOS (pf):**
```
# Allow credential proxy traffic through, redirect everything else
rdr on bridge0 proto tcp from 172.17.0.0/16 to any port != 9443 -> 127.0.0.1 port 9444
```

### Two Proxies, Shared Infrastructure

```
┌─────────────────────────────────────────────────────────┐
│                      gap-server                          │
│                                                          │
│  ┌────────────────────┐  ┌─────────────────────────┐    │
│  │ Credential Proxy    │  │ Transparent MITM Proxy   │    │
│  │ :9443 (TLS)         │  │ :9444 (raw TCP)          │    │
│  │                     │  │                          │    │
│  │ CONNECT-based       │  │ iptables/pf redirected   │    │
│  │ Bearer token auth   │  │ Source IP auth            │    │
│  │ Plugin transforms   │  │ Allow-list policy         │    │
│  │ Credential injection│  │ Inspect + log + forward   │    │
│  │ Credential scrubbing│  │ NO credential injection   │    │
│  └─────────┬───────────┘  └─────────────┬────────────┘    │
│            │                            │                 │
│            └──────────┬─────────────────┘                 │
│                       ▼                                   │
│  ┌──────────────────────────────────────────────────┐    │
│  │ Shared Infrastructure                             │    │
│  │ • CertificateAuthority (MITM cert generation)     │    │
│  │ • GapDatabase (activity logging, config)          │    │
│  │ • Activity broadcast (SSE)                        │    │
│  └──────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

The transparent proxy does NOT share the plugin transform pipeline, credential injection, or credential scrubbing with the credential proxy. It shares only the CA (for MITM cert generation) and the database (for activity logging and allow-list storage).

### Transparent Connection Flow

```
Raw TCP arrives (redirected by iptables/pf)
  │
  ├─ Recover original destination (SO_ORIGINAL_DST / getsockname)
  ├─ Look up agent identity from source IP
  │
  ├─ Detect protocol category from first bytes
  │   ├─ 0x16 (TLS ClientHello) → is "https" enabled? No → DROPPED
  │   │   ├─ Peek more bytes, extract SNI (hostname)
  │   │   ├─ Is hostname on allow-list? No → DROPPED
  │   │   ├─ MITM TLS handshake (dynamic cert for hostname)
  │   │   ├─ Detect H1/H2 via ALPN
  │   │   ├─ Bidirectional HTTP proxy to upstream
  │   │   └─ Log request/response metadata
  │   │
  │   ├─ HTTP method (GET, POST, etc.) → is "https" enabled? No → DROPPED
  │   │   ├─ Parse Host header
  │   │   ├─ Is hostname on allow-list? No → DROPPED
  │   │   ├─ Bidirectional HTTP proxy to upstream
  │   │   └─ Log request/response metadata
  │   │
  │   ├─ "SSH-2.0-..." → is "ssh" enabled? No → DROPPED (Phase 4)
  │   │
  │   └─ Unrecognised protocol → DROPPED (always)
  │
  └─ Log ActivityEntry (including drops — rejection reason + hostname if known)
```

### SNI Extraction

In transparent mode, the hostname comes from the TLS ClientHello's SNI extension (not from a CONNECT request). Gap peeks at the first ~1KB of a TLS connection, parses the ClientHello structure, and extracts the server_name extension. This happens before the TLS handshake, so the peeked bytes are prepended back to the stream using the existing `PrefixedStream` wrapper.

The SNI is used for:
- Allow-list matching (is this host permitted?)
- MITM certificate generation (what hostname goes on the fake cert?)
- Upstream TLS server name verification
- Activity logging

### Original Destination Recovery

When iptables/pf redirects a connection, the original destination (where the client intended to connect) is recoverable:

- **Linux**: `getsockopt(fd, SOL_IP, SO_ORIGINAL_DST)` returns the original `sockaddr_in`
- **macOS**: With pf `rdr-to`, `getsockname()` on the accepted socket returns the original destination

This is needed to know where to connect upstream (the client connected to `api.openai.com:443`, iptables redirected it to `localhost:9444`, gap needs to recover `api.openai.com:443`).

### Allow-List

The transparent proxy uses a **host allow-list** — not the plugin registry. A host being on the allow-list means "traffic to this host is permitted and forwarded." Unlike the credential proxy, there are no plugins, no transforms, no credential injection.

```
# Example allow-list entries
*.openai.com
api.github.com
*.s3.amazonaws.com
```

Wildcard matching follows the same single-level pattern as existing plugin host matching (`*.example.com` matches `sub.example.com` but not `a.b.example.com`).

Requests to hosts NOT on the allow-list are dropped and logged with the attempted hostname.

### Storage and Logging

**Allowed HTTPS traffic**: Log request/response metadata — method, URL, status code, headers, truncated body. One `ActivityEntry` per HTTP request. Similar to the credential proxy's activity logging but without credential-related fields.

**Dropped connections**: Log with rejection reason, protocol category, hostname (if extractable from SNI or Host header), source IP, agent identity.

**Future phases (generic TLS, UDP)**: Connection-level metadata only — hostname, duration, bytes transferred. No per-frame logging.

The existing libSQL database handles all of this.

## Protocol Categories and Configuration

Each protocol category is independently enabled. Disabled categories are dropped. This is the first gate — before allow-list matching.

```
# gap-server CLI flags
--transparent-port 9444
--transparent-protocols https        # V1: just HTTPS (H1 + H2)
# Future:
# --transparent-protocols https,tls,dns
```

| Category | Covers | Available |
|----------|--------|-----------|
| `https` | HTTPS (H1 + H2), plain HTTP, gRPC over HTTP | Phase 1 |
| `tls` | Generic TLS tunneling (non-HTTP TLS) | Phase 2 |
| `dns` | DNS queries (UDP port 53) | Phase 3 |
| `quic` | QUIC/HTTP3 (UDP) | Phase 3 |
| `ssh` | SSH tunneling | Phase 4 |

## Phased Rollout

### Phase 1: Transparent HTTPS (V1)

The `https` protocol category: HTTPS (H1 + H2), plain HTTP, and gRPC over HTTP. MITM TLS for visibility, allow-list for policy, activity logging for audit. This covers the vast majority of container traffic.

All other protocol categories are unavailable — connections are dropped regardless of configuration.

### Phase 2: Generic TLS Tunneling

The `tls` category. TLS connections are tunneled without MITM — gap sees the hostname (SNI) and applies the allow-list, but doesn't break TLS or parse the application protocol.

- `tokio::io::copy_bidirectional()` for stream splicing
- Enables: database connections (Postgres, MySQL, Redis over TLS), custom TLS protocols
- One `ActivityEntry` per connection (metadata only)

### Phase 3: UDP / DNS / QUIC

The `dns` and `quic` categories.

- UDP listener for transparent UDP capture
- **DNS**: Parse queries, apply domain allow/block policy. Prevents DNS-based exfiltration.
- **QUIC**: Parse SNI from QUIC Initial packet (unencrypted). Pragmatic v1: block QUIC, clients fall back to TCP/TLS. Full QUIC MITM via `quinn` possible later.

### Phase 4: SSH and Other Protocols

The `ssh` category.

- **Detection**: SSH starts with `SSH-2.0-...` ASCII banner
- **Tunnel mode**: See the banner, apply allow-list, splice streams
- **Full SSH MITM**: Deferred — different trust model, major undertaking
- Extensible protocol detector registry for future categories

## Comparison with mitmproxy

| Capability | mitmproxy | gap transparent (Phase 1) | gap transparent (all phases) |
|---|---|---|---|
| Transparent HTTPS | Yes | Yes | Yes |
| HTTP/2 | Yes | Yes | Yes |
| HTTP/3 / QUIC | Yes (v11+) | Blocked | Block or tunnel (Phase 3) |
| Generic TLS tunnel | Yes (`tcp_hosts`) | Blocked | Yes (Phase 2) |
| DNS | Yes | Blocked | Yes (Phase 3) |
| SSH | No | Blocked | Tunnel only (Phase 4) |
| WebSocket | Yes | Blocked | Future |
| Default-deny | No (default-allow) | **Yes (protocol + host)** | **Yes (protocol + host)** |
| Credential injection | No | No (separate proxy) | No (separate proxy) |
| Stable API | No | Yes (REST) | Yes (REST) |
| Storage | In-memory + files | libSQL (persisted) | libSQL (persisted) |

Gap's transparent proxy differentiates on: default-deny security model, two-layer policy (protocol + host), persistent audit logging, and clean separation from the credential injection proxy.

## Open Questions

1. **WireGuard mode**: Should gap support acting as a WireGuard server? Avoids iptables/pf setup — clients just connect to a VPN. More portable but adds dependency.

2. **Helper commands**: Should gap provide `gap transparent setup` to configure iptables/pf rules? Or documentation only?

3. **Docker integration**: Docker network plugin or sidecar container for automatic iptables setup?

4. **Certificate distribution**: The container still needs to trust gap's CA for HTTPS MITM. Inject at runtime or bake into container image?

5. **Allow-list discovery**: Dropped connection logs capture the hostname and protocol of every blocked attempt. This provides a natural discovery mechanism — run the container, review the drop logs, build the allow-list from what it tried to reach. No special "observe mode" needed.
