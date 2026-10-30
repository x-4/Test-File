# 套用 Cloudflare（cloudflared / 橙云代理）部署指南

本节点是**纯 HTTP 的 XHTTP 服务端**（默认 HTTP/1.1 监听），因此可以被 Cloudflare 以两种方式加速：
`cloudflared` Tunnel（无需公网入口）或直接橙云代理 DNS。两者都不需要改协议。

---

## 一、三种拓扑，按你的环境选一种

### A. cloudflared 与节点同机（最简单）

节点监听 `127.0.0.1:8100`，cloudflared 直接回源到本机：

```yaml
# /etc/cloudflared/config.yml
tunnel: <TUNNEL_ID>
credentials-file: /root/.cloudflared/<TUNNEL_ID>.json
ingress:
  - hostname: node.example.com
    service: http://127.0.0.1:8100
    originRequest:
      httpHostHeader: node.example.com
      connectTimeout: 10s
      noTLSVerify: false
      disableChunkedEncoding: false     # 必须保持 false，否则 SSE/流式会被破坏
  - service: http_status:404
```

```bash
cloudflared tunnel create node
cloudflared tunnel route dns node node.example.com
cloudflared service install && systemctl enable --now cloudflared
```

### B. cloudflared 在别处，回源到 PaaS 的 HTTPS 地址（**适用于 Alwaysdata**）

PaaS 通常不允许你长期跑自定义二进制，此时让 cloudflared 跑在你自己的机器/小主机上，
回源到 PaaS 分配的域名即可（PaaS 仍然终结 TLS，节点代码无需改动）：

```yaml
ingress:
  - hostname: node.example.com
    service: https://<你的应用>.alwaysdata.net
    originRequest:
      httpHostHeader: <你的应用>.alwaysdata.net
      originServerName: <你的应用>.alwaysdata.net   # SNI
      connectTimeout: 10s
  - service: http_status:404
```

> 代价：流量链路变为 `客户端 → CF → 你的 cloudflared 主机 → PaaS`，那台主机成为带宽瓶颈，
> 但仍然享受 CF 的全球就近接入与抗封锁能力。

### C. 不用 cloudflared，直接橙云（Cloudflare 代理 DNS）

DNS 记录指向 PaaS 域名/IP 并开启小黄云即可，节点代码无需任何改动。
前提：PaaS 允许 Cloudflare 回源（多数允许），且只走 443。

---

## 二、必须保持的节点配置

| 配置 | 取值 | 原因 |
|---|---|---|
| `H2C_ONLY` | **不要开**（默认 h1.1） | cloudflared 回源使用 HTTP/1.1；开了 h2c-only 会直接连不上 |
| `ALPN` | 保持 `h2,http/1.1` | 客户端与 CF 边缘协商；CF 支持 h2 |
| `UDP_MODE` | `auto` / `doh` | CF 层不关心 UDP；UDP 是在 TCP 隧道内承载，由节点自己出网 |
| `TRUST_PROXY` | 保持默认（信任代理头） | 限速需要用真实客户端 IP（见下） |

### 客户端侧**不要**开启的两项（会被 Cloudflare 限制打断）

| 客户端参数 | 原因 |
|---|---|
| `uplinkDataPlacement: header` / `xPaddingPlacement: header` | CF 对请求头总大小有限制（约 32KB），`X-Data-N` 分片会超限被 400/414 |
| `mode: stream-one`（在 CF 后） | 单流双向对中间层缓冲最敏感，出问题难定位；建议用默认 `auto`(packet-up) |

---

## 三、推荐订阅链接

`<UUID>` 替换为你的值，域名替换为 CF 上的主机名：

```
vless://<UUID>@node.example.com:443?encryption=none&security=tls&sni=node.example.com
&fp=chrome&alpn=h2%2Chttp%2F1.1&type=xhttp&mode=auto&path=%2Fxh#CF-XHTTP
```

节点自带订阅输出（`GET /<UUID>`）会自动使用请求的 `Host` 头，**经 CF 访问时生成的链接就是 CF 域名**，
无需手工改动。

---

## 四、已知限制（务必了解）

1. **空闲流会被 CF 断开（约 100s 无数据）**
   - 活跃传输不受影响；普通网页/DNS 请求是短连接，无感。
   - 长时间静默的长连接（如挂着的 SSH）可能被重置，客户端会自动重连。
   - XHTTP 的下行流**无法插入保活字节**（会被当成 VLESS 载荷破坏数据），所以这是协议层
     无法规避的限制；节点已用 TCP keep-alive 尽量维持，但 CF 在边缘终结 TCP，效果有限。

2. **请求头体积受限**：见上方「不要开启 header 放置」。

3. **CF 免费版 ToS 2.8**：Cloudflare 服务条款限制把 CDN 用于大量非 HTML 内容（视频/大文件）。
   代理流量属于灰色地带，存在被风控/要求升级 Business 的风险。请自行评估。

4. **源站暴露**：PaaS 的原始域名仍然可被直接访问。若担心绕过 CF 的直连，可在 PaaS 侧做
   Cloudflare IP 白名单，或把节点放到只允许 cloudflared 访问的内网。

5. **限速是按 IP 的**：节点已优先读取 `CF-Connecting-IP`（其次 `X-Forwarded-For` 最右侧），
   经 CF 时能正确按真实客户端 IP 分桶。若你把服务直接暴露在公网，请设 `TRUST_PROXY=0`，
   否则攻击者可伪造该头绕过限速。

---

## 五、上线自查清单

```bash
# 1) 流式是否被缓冲（关键）：应立即打印响应头，并在 <1s 内返回 200
curl -N -sS -D- -o /dev/null --max-time 3 https://node.example.com/xh/probe \
  -H 'Referer: https://node.example.com/?x_padding=XXXX'
#   期望：HTTP/2 200、content-type: text/event-stream、cache-control: no-store, no-transform
#   若迟迟不返回头 → CF 在缓冲，检查 disableChunkedEncoding 是否为 false

# 2) 订阅链接域名是否正确
curl -s https://node.example.com/<UUID> | base64 -d; echo

# 3) 伪装页是否正常（不应被 CF 错误页替换）
curl -sS -o /dev/null -w '%{http_code}\n' https://node.example.com/

# 4) 未知路径应为本地 404（不是 CF 的 404 页）
curl -sS -o /dev/null -w '%{http_code}\n' https://node.example.com/anything
```

客户端侧用 `xray -test` 或直接在 v2rayN / Mihomo 里测「延迟 + 下载 10MB」即可确认链路。

---

## 六、排错对照表

| 现象 | 可能原因 | 处理 |
|---|---|---|
| CF 522 / 1033 | cloudflared 未连上 | `systemctl status cloudflared`、`cloudflared tunnel info` |
| 握手成功但无数据 | `disableChunkedEncoding: true` 导致缓冲 | 改回 false |
| 大流量中断 | CF 请求头超限（用了 header 放置） | 客户端改回 `uplinkDataPlacement: body`（默认） |
| 每隔 1~2 分钟断一次 | CF 空闲流超时 | 属已知限制；缩短客户端 keepalive 或接受重连 |
| 全部 403 | CF WAF/防火墙规则误伤 | 关闭 Managed Rules 或加 skip 规则（`/xh/*`） |
| 限速误伤同一出口 | 未取到 CF-Connecting-IP | 确认 `TRUST_PROXY` 未设为 0 |
