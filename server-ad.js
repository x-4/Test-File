// ====================================================================
// Void AI Matrix Service (XHTTP / SplitHTTP Alwaysdata Edition)
//
// 纯 XHTTP（Xray SplitHTTP）传输的 VLESS 服务端，无 WebSocket 依赖。
// 环境变量：
//   UUID        必填，节点鉴权 ID（同时作为订阅路径 /<UUID>）
//   PORT        监听端口，默认 8100
//   IP          监听地址，默认 0.0.0.0
//   XHTTP_PATH  XHTTP 传输路径，默认 /xh
// ====================================================================

const http = require('http');
const net = require('net');
const https = require('https');
const crypto = require('crypto');

const ENV = { 
    S_TKN: process.env.UUID || '00000000-0000-0000-0000-000000000000', 
    S_ORIGIN: 'https://www.microsoft.com',
    // 【核心修复1】适配 Alwaysdata 注入的内部 IP 和端口
    PORT: process.env.PORT || 8100,
    IP: process.env.IP || '0.0.0.0',
    XHTTP_PATH: process.env.XHTTP_PATH || '/xh'
};

process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});

// ====================================================================
// 核心调度注册表 (防静态分析)
// ====================================================================

const Registry = new Map();

const initToken = () => {
    const b = new Uint8Array(16);
    const h = c => (c > 64 ? c + 9 : c) & 0xF;
    for (let i = 0, p = 0; i < 16; i++) { 
        let c = ENV.S_TKN.charCodeAt(p++); if (c === 45) c = ENV.S_TKN.charCodeAt(p++); 
        const hi = h(c); c = ENV.S_TKN.charCodeAt(p++); if (c === 45) c = ENV.S_TKN.charCodeAt(p++); 
        b[i] = (hi << 4) | h(c); 
    }
    return b;
};

const _S_KEY = initToken();

Registry.set('validate', (buf) => {
    if (!buf || buf.length < 17) return false;
    for (let i = 0; i < 16; i++) if (buf[i + 1] !== _S_KEY[i]) return false;
    return true;
});

Registry.set('resolve', (type, buf) => {
    if (type === 1) return `${buf[0]}.${buf[1]}.${buf[2]}.${buf[3]}`;
    if (type === 3) return buf.toString('utf8');
    const ipv6 = [];
    for (let i = 0; i < 8; i++) ipv6.push(((buf[i * 2] << 8) | buf[i * 2 + 1]).toString(16));
    return ipv6.join(':'); 
});

Registry.set('parse', (buf) => {
    if (buf.length < 24 || !Registry.get('validate')(buf)) return null; 
    const mLen = buf[17]; 
    const prot = buf[18 + mLen]; 
    const port = (buf[19 + mLen] << 8) | buf[20 + mLen]; 
    let type = buf[21 + mLen]; if (type !== 1) type += 1; 
    let aLen = 0, aOff = 22 + mLen;
    if (type === 3) { aLen = buf[aOff]; aOff++; } 
    else if (type === 1) aLen = 4; 
    else if (type === 4) aLen = 16; 
    const pOff = aOff + aLen;
    if (pOff > buf.length) return null; 
    return { prot, type, port, clusterId: buf.subarray(aOff, pOff), pOff };
});

// ====================================================================
// 好莱坞级 AI 控制台界面 (前端伪装)
// ====================================================================

const renderAIMatrix = (res) => {
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>LLM Node Edge Control</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
            body { background: #050505; color: #e2e8f0; font-family: 'JetBrains Mono', monospace; overflow-x: hidden; }
            .grid-bg { background-image: linear-gradient(rgba(25, 25, 30, 0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(25, 25, 30, 0.5) 1px, transparent 1px); background-size: 30px 30px; }
            .glass { background: rgba(15, 20, 25, 0.6); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.05); }
            .glow-text { text-shadow: 0 0 10px rgba(56, 189, 248, 0.6); }
            .terminal { max-height: 250px; overflow-y: auto; font-size: 0.85rem; }
            ::-webkit-scrollbar { width: 6px; }
            ::-webkit-scrollbar-thumb { background: #333; border-radius: 3px; }
        </style>
    </head>
    <body class="grid-bg min-h-screen p-6 md:p-12">
        <div class="max-w-7xl mx-auto">
            <header class="flex justify-between items-end mb-10 border-b border-gray-800 pb-4">
                <div>
                    <h1 class="text-3xl font-bold text-sky-400 glow-text tracking-wider">AETHER<span class="text-white">_NODE</span></h1>
                    <p class="text-gray-500 text-sm mt-1">Distributed Tensor Inference Cluster</p>
                </div>
                <div class="flex items-center gap-3">
                    <span class="relative flex h-3 w-3"><span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span><span class="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span></span>
                    <span class="text-emerald-500 text-sm font-bold tracking-widest">LIVE</span>
                </div>
            </header>

            <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                <div class="glass p-5 rounded-lg border-l-4 border-l-sky-500">
                    <p class="text-gray-500 text-xs mb-1">GPU VRAM USAGE</p>
                    <div class="text-2xl font-bold text-sky-400" id="vram">-- GB</div>
                </div>
                <div class="glass p-5 rounded-lg border-l-4 border-l-indigo-500">
                    <p class="text-gray-500 text-xs mb-1">TOKENS / SEC</p>
                    <div class="text-2xl font-bold text-indigo-400" id="tps">--</div>
                </div>
                <div class="glass p-5 rounded-lg border-l-4 border-l-rose-500">
                    <p class="text-gray-500 text-xs mb-1">INFERENCE LATENCY</p>
                    <div class="text-2xl font-bold text-rose-400" id="latency">-- ms</div>
                </div>
                <div class="glass p-5 rounded-lg border-l-4 border-l-amber-500">
                    <p class="text-gray-500 text-xs mb-1">ACTIVE STREAMS</p>
                    <div class="text-2xl font-bold text-amber-400" id="streams">--</div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div class="lg:col-span-2 glass p-6 rounded-lg relative h-80">
                    <p class="absolute top-4 left-6 text-xs text-gray-500 z-10">REAL-TIME TENSOR THROUGHPUT</p>
                    <canvas id="mainChart"></canvas>
                </div>
                <div class="glass p-6 rounded-lg flex flex-col">
                    <p class="text-xs text-gray-500 mb-4 border-b border-gray-800 pb-2">CLUSTER EVENT LOGS</p>
                    <div class="terminal flex-1 text-gray-400" id="terminal">
                        <div class="text-sky-500">>> INITIALIZING AETHER ENGINE v4.2...</div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            const ctx = document.getElementById('mainChart').getContext('2d');
            const gradient = ctx.createLinearGradient(0, 0, 0, 400);
            gradient.addColorStop(0, 'rgba(56, 189, 248, 0.4)');
            gradient.addColorStop(1, 'rgba(56, 189, 248, 0)');

            const chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: Array(30).fill(''),
                    datasets: [{
                        data: Array(30).fill(50),
                        borderColor: '#38bdf8', borderWidth: 2, backgroundColor: gradient,
                        fill: true, pointRadius: 0, tension: 0.3
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, animation: false, scales: { y: { display: false, min: 0, max: 200 }, x: { display: false } }, plugins: { legend: { display: false } } }
            });

            const logs = [
                "Allocating 4096MB VRAM for transformer blocks...",
                "KV cache synced across distributed nodes.",
                "Attention mechanism optimized: FlashAttention-2 active.",
                "Inference stream #2940 established.",
                "Garbage collection executed. Freed 120MB.",
                "Received embedding vector [dim=8192]. Processing...",
                "Router: Forwarding request to GPU worker 02.",
                "CUDA Core temperature stable at 68°C."
            ];

            const term = document.getElementById('terminal');
            
            setInterval(() => {
                document.getElementById('vram').innerText = (Math.random() * 2 + 14).toFixed(1) + ' GB';
                document.getElementById('tps').innerText = Math.floor(Math.random() * 50 + 150);
                document.getElementById('latency').innerText = Math.floor(Math.random() * 20 + 35) + ' ms';
                document.getElementById('streams').innerText = Math.floor(Math.random() * 5 + 12);
                
                const nextVal = chart.data.datasets[0].data[29] + (Math.random() * 40 - 20);
                const safeVal = Math.max(20, Math.min(180, nextVal));
                chart.data.datasets[0].data.push(safeVal);
                chart.data.datasets[0].data.shift();
                chart.update();

                if(Math.random() > 0.6) {
                    const log = document.createElement('div');
                    const time = new Date().toISOString().split('T')[1].slice(0,-1);
                    log.innerHTML = \`<span class="text-gray-600">[\${time}]</span> \${logs[Math.floor(Math.random()*logs.length)]}\`;
                    term.appendChild(log);
                    term.scrollTop = term.scrollHeight;
                }
            }, 800);
        </script>
    </body>
    </html>
    `;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
};

// ====================================================================
// 路由代理与订阅分发
// ====================================================================

const mirrorOrigin = (req, res) => {
    const options = {
        hostname: new URL(ENV.S_ORIGIN).hostname,
        port: 443, path: req.url, method: req.method,
        headers: { ...req.headers, host: new URL(ENV.S_ORIGIN).hostname }
    };
    const proxyReq = https.request(options, proxyRes => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res, { end: true });
    });
    proxyReq.on('error', () => { res.writeHead(503); res.end(); });
    req.pipe(proxyReq, { end: true });
};

const generateSubscription = (req, res) => {
    const rawHost = (req.headers.host || '').trim();
    // 去掉 Host 中的端口，端口缺省视为 443（生产环境走 CDN/反代）
    const hostNoPort = rawHost.replace(/:\d+$/, '');
    const hostPort = /:(\d+)$/.test(rawHost) ? rawHost.match(/:(\d+)$/)[1] : '443';
    const port = hostPort === String(ENV.PORT) ? '443' : hostPort;
    const tag = encodeURIComponent('Alwaysdata-XHTTP-Node');
    const encPath = encodeURIComponent(ENV.XHTTP_PATH.replace(/\/+$/, '') || '/');
    // 标准 XHTTP (SplitHTTP) VLESS 分享链接
    const link = `vless://${ENV.S_TKN}@${hostNoPort}:${port}?encryption=none&security=tls&sni=${hostNoPort}&fp=chrome&type=xhttp&mode=auto&path=${encPath}#${tag}`;
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(Buffer.from(link).toString('base64'));
};

// ====================================================================
// XHTTP (SplitHTTP) 核心引擎
// ====================================================================

const DOH_ENDPOINTS = ['aHR0cHM6Ly8xLjEuMS4xL2Rucy1xdWVyeQ==','aHR0cHM6Ly9kbnMuZ29vZ2xlL2Rucy1xdWVyeQ==','aHR0cHM6Ly85LjkuOS45L2Rucy1xdWVyeQ=='].map(b64 => Buffer.from(b64, 'base64').toString('utf8'));

// 会话表：sessionId -> Session
const SESSIONS = new Map();
// 无 sessionId 的 stream-one 单流会话（按连接标识）
const streamOneSessions = new Map();

const SESSION_TTL = 30000;        // 客户端必须在 30 秒内建立关联
const SESSION_TIMEOUT = 120000;   // 已建立关联后的空闲超时
const MAX_REASSEMBLY = 128;       // packet-up 乱序重排缓冲上限

class Session {
    constructor(id) {
        this.id = id;
        this.res = null;             // 下行 GET 的响应流
        this.edgeSocket = null;      // 目标 TCP Socket
        this.isFirstPacket = true;
        this.isUDP = false;
        this.udpBuffer = Buffer.alloc(0);
        this.closed = false;
        this.pending = new Map();    // seq -> Buffer
        this.pendingDown = [];       // 下行尚未建立时的临时缓冲
        this.pendingDownBytes = 0;
        this.nextSeq = 0n;
        this.lastActive = Date.now();
    }

    touch() {
        this.lastActive = Date.now();
    }

    attachDownstream(res) {
        if (this.closed) { try { res.end(); } catch (e) {} return false; }
        // 同一会话只允许一条下行流；旧流被新流替换时关闭旧流
        if (this.res && this.res !== res) { try { this.res.end(); } catch (e) {} }
        this.res = res;
        this.touch();

        // 冲刷下行建立前缓存的数据（客户端可能先发上行包）
        if (this.pendingDown.length) {
            const buffered = this.pendingDown;
            this.pendingDown = [];
            this.pendingDownBytes = 0;
            for (const b of buffered) { try { res.write(b); } catch (e) {} }
        }

        res.on('close', () => {
            if (this.res === res) {
                this.res = null;
                this.destroy();
            }
        });
        res.on('error', () => {
            if (this.res === res) { this.res = null; this.destroy(); }
        });
        return true;
    }

    sendDownstream(buf) {
        if (this.closed) return;
        this.touch();

        // 下行流尚未建立：先缓存（上限 256KB，防止恶意堆积）
        if (!this.res || this.res.writableEnded) {
            if (this.res === null && this.pendingDownBytes < 262144) {
                this.pendingDown.push(buf);
                this.pendingDownBytes += buf.length;
            }
            return;
        }

        try { this.res.write(buf); } catch (e) { this.destroy(); }
    }

    pushPacket(seq, payload) {
        if (this.closed) return;
        this.touch();
        let n;
        try { n = BigInt(seq); } catch (e) { return; }
        if (n < this.nextSeq) return;           // 重复包直接丢弃
        this.pending.set(n, payload);
        if (this.pending.size > MAX_REASSEMBLY) { this.destroy(); return; }
        this.drainPackets();
    }

    drainPackets() {
        while (!this.closed && this.pending.has(this.nextSeq)) {
            const chunk = this.pending.get(this.nextSeq);
            this.pending.delete(this.nextSeq);
            this.nextSeq++;
            this.feed(chunk);
        }
    }

    // 处理 VLESS 明文数据（首包负责握手与建连）
    feed(buf) {
        if (this.closed || !buf || buf.length === 0) return;
        this.touch();

        if (this.isFirstPacket) {
            this.isFirstPacket = false;
            const meta = Registry.get('parse')(buf);
            if (!meta) { this.destroy(); return; }

            // VLESS 服务端握手响应：[version, 0]
            this.sendDownstream(Buffer.from([buf[0], 0]));

            const initial = buf.subarray(meta.pOff);

            if (meta.prot === 2) {           // UDP（仅 DoH 处理 53 端口）
                this.isUDP = true;
                if (meta.port !== 53) { this.destroy(); return; }
                if (initial.length > 0) {
                    this.udpBuffer = initial;
                    this.processUDP();
                }
                return;
            }

            // TCP 直连目标
            const host = Registry.get('resolve')(meta.type, meta.clusterId);
            this.edgeSocket = net.createConnection({ host: host, port: meta.port }, () => {
                if (initial.length > 0 && this.edgeSocket && !this.edgeSocket.destroyed) {
                    this.edgeSocket.write(initial);
                }
            });

            this.edgeSocket.setNoDelay(true);
            this.edgeSocket.on('data', chunk => this.sendDownstream(chunk));
            this.edgeSocket.on('error', () => this.destroy());
            this.edgeSocket.on('close', () => this.destroy());
            return;
        }

        if (this.isUDP) {
            this.udpBuffer = Buffer.concat([this.udpBuffer, buf]);
            this.processUDP();
        } else if (this.edgeSocket && !this.edgeSocket.destroyed) {
            this.edgeSocket.write(buf);
        }
    }

    // UDP 帧格式：[2 字节长度][DNS 报文]，通过 DoH 转发
    processUDP() {
        while (!this.closed && this.udpBuffer.length >= 2) {
            const len = (this.udpBuffer[0] << 8) | this.udpBuffer[1];
            if (this.udpBuffer.length < 2 + len) break;
            const query = this.udpBuffer.subarray(2, 2 + len);
            this.udpBuffer = this.udpBuffer.subarray(2 + len);
            this.resolveDoH(query);
        }
    }

    async resolveDoH(query) {
        for (const endpoint of DOH_ENDPOINTS) {
            if (this.closed) return;
            try {
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Accept': 'application/dns-message', 'Content-Type': 'application/dns-message' },
                    body: query
                });
                if (response.ok) {
                    const respArray = new Uint8Array(await response.arrayBuffer());
                    const frame = Buffer.alloc(2 + respArray.length);
                    frame[0] = respArray.length >> 8;
                    frame[1] = respArray.length & 0xFF;
                    frame.set(respArray, 2);
                    this.sendDownstream(frame);
                    return;
                }
            } catch (e) { /* 尝试下一个 DoH 节点 */ }
        }
    }

    destroy() {
        if (this.closed) return;
        this.closed = true;
        if (SESSIONS.get(this.id) === this) SESSIONS.delete(this.id);
        if (streamOneSessions.get(this.id) === this) streamOneSessions.delete(this.id);
        if (this.edgeSocket) { this.edgeSocket.destroy(); this.edgeSocket = null; }
        this.pending.clear();
        this.pendingDown = [];
        this.pendingDownBytes = 0;
        const res = this.res;
        this.res = null;
        if (res && !res.writableEnded) { try { res.end(); } catch (e) {} }
    }
}

const getSession = (id) => {
    let s = SESSIONS.get(id);
    if (!s || s.closed) {
        s = new Session(id);
        SESSIONS.set(id, s);
    }
    return s;
};

// 统一回收僵死会话：未建立下行时用较短 TTL，已建立后按空闲活动判断
const sweep = () => {
    const now = Date.now();
    for (const s of SESSIONS.values()) {
        const idle = now - s.lastActive;
        const limit = s.res ? SESSION_TIMEOUT : SESSION_TTL;
        if (idle > limit) s.destroy();
    }
    for (const s of streamOneSessions.values()) {
        if (now - s.lastActive > SESSION_TIMEOUT) s.destroy();
    }
};
const sweeper = setInterval(sweep, 5000);
if (sweeper.unref) sweeper.unref();

// ====================================================================
// XHTTP 请求处理（下行 GET / 上行 POST|GET+seq）
// ====================================================================

const writeStreamHeaders = (res) => {
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-store, no-transform',
        'X-Accel-Buffering': 'no',
        'Connection': 'keep-alive'
    });
    if (typeof res.flushHeaders === 'function') res.flushHeaders();
};

// 收集 packet-up 上行数据：header(X-Data-N) + cookie(x_data_N) + body
const collectUplinkPayload = (req, body) => {
    const parts = [];

    const headerChunks = [];
    for (let i = 0; ; i++) {
        const v = req.headers[('x-data-' + i).toLowerCase()];
        if (!v) break;
        headerChunks.push(Array.isArray(v) ? v.join('') : v);
    }
    if (headerChunks.length) parts.push(Buffer.from(headerChunks.join(''), 'base64'));

    const cookieChunks = [];
    const rawCookie = req.headers.cookie || '';
    for (let i = 0; ; i++) {
        const name = 'x_data_' + i;
        const hit = rawCookie.split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
        if (!hit) break;
        cookieChunks.push(hit.slice(name.length + 1));
    }
    if (cookieChunks.length) parts.push(Buffer.from(cookieChunks.join(''), 'base64'));

    if (body && body.length) parts.push(body);

    return parts.length > 1 ? Buffer.concat(parts) : (parts[0] || Buffer.alloc(0));
};

const readBody = (req, cb) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => cb(Buffer.concat(chunks)));
    req.on('error', () => cb(Buffer.alloc(0)));
};

// ---------- stream-one：单个请求同时承载上下行 ----------
const handleStreamOne = (req, res) => {
    writeStreamHeaders(res);
    const id = 'one-' + crypto.randomUUID();
    const session = new Session(id);
    streamOneSessions.set(id, session);
    session.attachDownstream(res);
    req.on('data', chunk => session.feed(chunk));
    req.on('end', () => session.destroy());
    req.on('error', () => session.destroy());
};

// ---------- 下行流（stream-down / stream-one） ----------
const handleDownstream = (req, res, sessionId) => {
    if (!sessionId) return handleStreamOne(req, res);

    writeStreamHeaders(res);
    const session = getSession(sessionId);
    session.attachDownstream(res);

    // 兼容 stream-one 变体：GET 携带 body 时同样作为上行数据
    req.on('data', chunk => session.feed(chunk));
    req.on('error', () => session.destroy());
};

// ---------- 上行流（stream-up） ----------
const handleStreamUp = (req, res, sessionId) => {
    const session = getSession(sessionId);

    res.writeHead(200, {
        'Cache-Control': 'no-store',
        'X-Accel-Buffering': 'no',
        'Content-Type': 'text/plain'
    });
    if (typeof res.flushHeaders === 'function') res.flushHeaders();

    // 防止下行尚未建立时连接被中间设备判定为静默超时
    const keepAlive = setInterval(() => {
        if (res.writableEnded || session.closed) { clearInterval(keepAlive); return; }
        try { res.write(Buffer.from('X')); } catch (e) { clearInterval(keepAlive); }
    }, 20000);
    if (keepAlive.unref) keepAlive.unref();

    const cleanup = () => { clearInterval(keepAlive); if (!res.writableEnded) { try { res.end(); } catch (e) {} } };

    req.on('data', chunk => session.feed(chunk));
    req.on('end', cleanup);
    req.on('close', cleanup);
    req.on('error', cleanup);
};

// ---------- 上行包（packet-up） ----------
const handlePacketUp = (req, res, sessionId, seqStr) => {
    const session = getSession(sessionId);

    readBody(req, body => {
        const payload = collectUplinkPayload(req, body);
        if (payload.length) session.pushPacket(seqStr, payload);
        if (!res.writableEnded) {
            res.writeHead(200, { 'Cache-Control': 'no-store' });
            res.end();
        }
    });
};

// ====================================================================
// HTTP 主路由
// ====================================================================

const XHTTP_PREFIX = (ENV.XHTTP_PATH || '/xh').replace(/\/+$/, '') || '/xh';

const applyCors = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
};

const handleXHTTP = (req, res, pathname) => {
    applyCors(req, res);

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return true;
    }

    // 解析子路径：/xh | /xh/<sessionId> | /xh/<sessionId>/<seq>
    const rest = pathname.slice(XHTTP_PREFIX.length).replace(/^\/+/, '');
    const parts = rest.length ? rest.split('/') : [];
    const sessionId = parts[0] || '';
    const seqStr = parts[1] || '';

    if (req.method === 'GET') {
        if (seqStr !== '') {
            // packet-up 的 GET 变体（uplinkHTTPMethod=GET）
            handlePacketUp(req, res, sessionId, seqStr);
            return true;
        }
        handleDownstream(req, res, sessionId);
        return true;
    }

    if (req.method === 'POST') {
        if (!sessionId) return handleStreamOne(req, res), true;
        if (seqStr === '') {
            handleStreamUp(req, res, sessionId);
        } else {
            handlePacketUp(req, res, sessionId, seqStr);
        }
        return true;
    }

    res.writeHead(405, { 'Content-Type': 'text/plain' });
    res.end('Method Not Allowed');
    return true;
};

const server = http.createServer((req, res) => {
    let url;
    try {
        url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    } catch (e) {
        res.writeHead(400);
        return res.end();
    }
    const pathname = url.pathname;

    // 订阅输出
    if (req.method === 'GET' && pathname === '/' + ENV.S_TKN) {
        return generateSubscription(req, res);
    }

    // 伪装首页
    if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
        return renderAIMatrix(res);
    }

    // XHTTP 协议入口
    if (pathname === XHTTP_PREFIX || pathname.startsWith(XHTTP_PREFIX + '/')) {
        return handleXHTTP(req, res, pathname);
    }

    // 其他请求反代真实站点，规避主动探测
    return mirrorOrigin(req, res);
});

// 关闭 Nagle 以降低 XHTTP 小包延迟，并放宽头部/超时限制
server.keepAliveTimeout = 65000;
server.headersTimeout = 70000;
server.requestTimeout = 0;
server.on('clientError', (err, socket) => {
    try { socket.destroy(); } catch (e) {}
});

// 【核心修复2】强制绑定 ENV.IP，否则 Alwaysdata 反向代理无法找到你的服务
server.listen(ENV.PORT, ENV.IP, () => {
    console.log(`Aether Node Operations Active on ${ENV.IP}:${ENV.PORT} (XHTTP/SplitHTTP)`);
    console.log(`XHTTP path: ${XHTTP_PREFIX}`);
});

