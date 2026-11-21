# Lumzel Relay

[![CI & Docker](https://github.com/lumzel/relay/actions/workflows/ci.yml/badge.svg)](https://github.com/lumzel/relay/actions/workflows/ci.yml)
[![Docker Image](https://img.shields.io/badge/docker-ghcr.io%2Flumzel%2Frelay-blue)](https://github.com/lumzel/relay/pkgs/container/relay)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)

Official zero-retention, end-to-end encrypted WebSocket relay, STUN server, and Bot MCP reverse-proxy gateway for [Lumzel](https://github.com/lumzel).

---

## Features

- 🔒 **Zero Data Retention**  
  No database, no disk persistence. All routing tables and temporary admission tickets (30-second TTL) live strictly in volatile memory. Disconnection or reboot clears everything immediately.
- 🛡️ **End-to-End Encryption**  
  Direct clients (mobile companion, another Lumzel workbench) use Noise IK handshakes and ChaCha20-Poly1305 encrypted frames. The relay acts as a blind forwarding pipe that only inspects plaintext routing headers (`host_id`, `sid`, sequence numbers). The relay never holds encryption keys and cannot decrypt payloads.
- 🤖 **Bot MCP Gateway**  
  Enables cloud-based LLM platforms (ChatGPT, Grok) to invoke local Mac MCP tools over public HTTPS without exposing local ports. The relay terminates TLS and proxies HTTP JSON-RPC to your Mac through an authenticated `/host` WebSocket connection.
- 🎯 **Built-in STUN Server**  
  RFC 5389 compliant two-port STUN server for NAT mapping discovery and direct UDP hole punching (QUIC direct path).
- ⚡ **Multi-Architecture Support**  
  Official CI builds and publishes native Docker images for both `linux/amd64` and `linux/arm64`.

---

## Quick Start

### 1. Run with Docker

```bash
docker run -d \
  --name lumzel-relay \
  --restart unless-stopped \
  -p 8080:8080 \
  -p 3478:3478/udp \
  -p 3479:3479/udp \
  -e RELAY_BIND=0.0.0.0:8080 \
  -e RELAY_STUN_BIND=0.0.0.0:3478,0.0.0.0:3479 \
  ghcr.io/lumzel/relay:latest
```

### 2. Run with Docker Compose

```yaml
services:
  relay:
    image: ghcr.io/lumzel/relay:latest
    container_name: lumzel-relay
    restart: unless-stopped
    environment:
      - RELAY_BIND=0.0.0.0:8080
      - RELAY_STUN_BIND=0.0.0.0:3478,0.0.0.0:3479
      - RELAY_NODE_ID=main
    ports:
      - "8080:8080"
      - "3478:3478/udp"
      - "3479:3479/udp"
```

---

## Reverse Proxy & TLS Configuration

Relay listens for plain HTTP and WebSocket connections on port `8080`. Public deployments should terminate TLS using a reverse proxy such as Caddy or Nginx.

### Caddy (Recommended)

```caddyfile
relay.example.com {
    reverse_proxy localhost:8080
}
```

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name relay.example.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
    }
}
```

---

## Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `RELAY_BIND` | `0.0.0.0:8080` | TCP listen address for HTTP & WebSockets |
| `RELAY_STUN_BIND` | *(empty)* | Comma-separated UDP addresses for STUN, e.g. `0.0.0.0:3478,0.0.0.0:3479` |
| `RELAY_NODE_ID` | `local` | Node identifier for multi-relay routing |
| `RELAY_MAX_CONNS` | `1024` | Maximum total concurrent connections |
| `RELAY_OPS_TOKEN` | *(empty)* | Bearer token required for `/drain` endpoint (graceful shutdown) |
| `LUMZEL_RELAY_PASSWORD` | *(empty)* | Optional access password (`--password`, alias `RELAY_PASSWORD`) for private deployments; rejects unauthenticated requests with `401` |
| `RELAY_TRUST_FORWARDED_FOR` | `0` | Set to `1` when behind a trusted reverse proxy (Nginx/Caddy) to parse `X-Forwarded-For` |

---

## Security & Privacy Guardrails

1. **Host-Controlled Tokens**: OAuth tokens for Bot MCP clients are issued and validated exclusively by your local Mac. The relay never stores tokens and does not persist requests.
2. **Permission Caps**: Sessions initiated by external Bots are capped at the `auto-edit` tier on the Host. Sensitive tools requiring human approval (e.g., shell command execution) will prompt on your Mac or Phone; the Bot cannot approve on your behalf.
3. **Emergency Stop**: You can revoke any Bot token or trigger an instant emergency stop directly from the Lumzel desktop application.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
