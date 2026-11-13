# Lumzel Relay

[![CI & Docker](https://github.com/lumzel/relay/actions/workflows/ci.yml/badge.svg)](https://github.com/lumzel/relay/actions/workflows/ci.yml)
[![Docker Image](https://img.shields.io/badge/docker-ghcr.io%2Flumzel%2Frelay-blue)](https://github.com/lumzel/relay/pkgs/container/relay)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)

Official zero-retention, end-to-end encrypted WebSocket relay, STUN server, and Bot MCP reverse-proxy gateway for [Lumzel](https://github.com/lumzel).

Lumzel 官方中继服务：专为 Lumzel 打造的零留存、端到端加密 WebSocket 盲转路由、STUN 打洞服务及 Grok / ChatGPT 外部 Bot MCP 反向代理网关。

---

## Features · 核心特性

- 🔒 **Zero Data Retention · 零数据留存**  
  No database, no disk persistence. All routing tables and temporary admission tickets (30s TTL) live strictly in volatile memory. Disconnect or reboot clears everything.  
  无数据库，无磁盘落盘，所有路由与临时票据（30 秒有效）纯内存驻留，断开或重启即清空。
- 🛡️ **End-to-End Encryption · 端到端加密**  
  Clients (Phones, another Lumzel instance) use Noise IK handshakes and ChaCha20-Poly1305 encrypted frames. Relay acts as a blind pipe that only inspects plaintext routing headers (`host_id`, `sid`, sequence numbers). Relay has no access to encryption keys.  
  客户端采用 Noise IK 握手与 ChaCha20-Poly1305 密文帧，中继仅根据明文路由头盲转，无密钥亦无法解密内容。
- 🤖 **Bot MCP Gateway · 外部 Bot MCP 网关**  
  Enables ChatGPT and Grok to invoke local Mac MCP tools without public IPs. Relay terminates TLS and proxies HTTP JSON-RPC to your Mac over an authenticated `/host` WebSocket.  
  使 ChatGPT / Grok 等公网 Bot 能够直接访问你个人 Mac 上的本地 MCP 服务（终端会话、工具调用），在 Relay 终结 TLS 并通过已验证的 `/host` WebSocket 穿透到本地。
- 🎯 **Built-in STUN Server · 内置 STUN 探测**  
  RFC 5389 compliant two-port STUN server for NAT mapping discovery and direct UDP hole punching (QUIC direct path).  
  支持 RFC 5389 双端口 STUN 探测，助力客户端快速识别 NAT 拓扑并建立 UDP 直连。
- ⚡ **Multi-Architecture Support · 多架构原生镜像**  
  Automated CI builds for both `linux/amd64` and `linux/arm64`.  
  官方 CI 自动构建并发布 `amd64` 与 `arm64` 双架构 Docker 镜像。

---

## Quick Start · 快速开始

### 1. Run with Docker · Docker 快速运行

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

### 2. Run with Docker Compose · 容器编排运行

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

## Reverse Proxy & TLS Configuration · 反向代理与证书

Relay runs plain HTTP and WebSocket on `8080`. Public deployments should terminate TLS using Caddy or Nginx.

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

## Environment Variables · 环境变量

| Variable | Default | Description |
| :--- | :--- | :--- |
| `RELAY_BIND` | `0.0.0.0:8080` | TCP listen address for HTTP & WebSockets |
| `RELAY_STUN_BIND` | *(empty)* | Comma-separated UDP addresses for STUN, e.g. `0.0.0.0:3478,0.0.0.0:3479` |
| `RELAY_NODE_ID` | `local` | Node identifier for multi-relay routing |
| `RELAY_MAX_CONNS` | `1024` | Maximum total concurrent connections |
| `RELAY_OPS_TOKEN` | *(empty)* | Bearer token required for `/drain` endpoint (graceful shutdown) |
| `RELAY_TRUST_FORWARDED_FOR` | `0` | Set to `1` when behind a trusted reverse proxy (Nginx/Caddy) to parse `X-Forwarded-For` |

---

## Security & Privacy · 安全与隐私

1. **Host-Controlled Tokens**: OAuth tokens for Bot MCP clients are issued and validated exclusively by your local Mac. Relay never stores tokens and does not persist requests.
2. **Permission Caps**: Sessions initiated by external Bots are capped at `auto-edit` tier on the Host. Tools requiring human approval (e.g., terminal commands) will prompt on your Mac / Phone; the Bot cannot approve on your behalf.
3. **Emergency Stop**: You can revoke any Bot token or trigger an instant emergency stop directly from the Lumzel desktop app.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
