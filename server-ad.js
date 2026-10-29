// ====================================================================
// Void AI Matrix Service (XHTTP / SplitHTTP Alwaysdata Edition)
//
// 纯 XHTTP（Xray SplitHTTP）传输的 VLESS 服务端，无 WebSocket 依赖。
// 环境变量：
//   UUID                   必填，节点鉴权 ID（同时作为订阅路径 /<UUID>）
//   PORT                   监听端口，默认 8100
//   IP                     监听地址，默认 0.0.0.0
//   XHTTP_PATH             XHTTP 传输路径，默认 /xh（需与订阅链接 path 一致）
//   SC_MAX_EACH_POST_BYTES packet-up 单次 POST 上限，默认 1000000（对齐 Xray 默认）
//   SC_MAX_BUFFERED_POSTS  乱序重排缓冲包数，默认 30（对齐 Xray 默认）
//   MAX_SESSIONS           并发会话上限，默认 4096（Node 侧保护）
//   SESSION_MAX_IDLE_MS    已建立下行的会话兜底回收时间，默认 1800000
//   DEBUG                  设为 1 输出 XHTTP 调试日志
//
// 未知路径一律由本地静态伪装站响应，不存在任何第三方站点转发/跳转能力。
// ====================================================================

const http = require('http');
const net = require('net');
const crypto = require('crypto');

const ENV = { 
    S_TKN: process.env.UUID || '', 
    // 【核心修复1】适配 Alwaysdata 注入的内部 IP 和端口
    PORT: process.env.PORT || 8100,
    IP: process.env.IP || '0.0.0.0',
    XHTTP_PATH: process.env.XHTTP_PATH || '/xh',
    // 与 Xray 服务端默认值保持一致（splithttp.GetNormalized*）
    SC_MAX_EACH_POST_BYTES: parseInt(process.env.SC_MAX_EACH_POST_BYTES || '1000000', 10),
    SC_MAX_BUFFERED_POSTS: parseInt(process.env.SC_MAX_BUFFERED_POSTS || '30', 10),
    // 进程保护：未通过 UUID 校验的会话上限（Xray 无此限制，Node 需要）
    MAX_SESSIONS: parseInt(process.env.MAX_SESSIONS || '4096', 10)
};

// Xray 客户端 GetNormalizedPath()：path 必须以 '/' 开头，且不含查询串
if (!/^\//.test(ENV.XHTTP_PATH) || /[?#\s]/.test(ENV.XHTTP_PATH)) {
    console.error('[FATAL] XHTTP_PATH 必须是形如 /xh 的绝对路径（不能包含查询串或空格）。');
    process.exit(1);
}

// 缺少或非法 UUID 时直接退出：避免以可预测的空凭证对外提供服务
if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(ENV.S_TKN)) {
    console.error('[FATAL] 环境变量 UUID 缺失或格式非法（需为标准 UUID，如 8-4-4-4-12 十六进制）。');
    process.exit(1);
}

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
// ====================================================================
// AI 控制台界面 (前端伪装) —— 完全自包含，无任何外部 CDN/字体依赖
// ====================================================================

const BASE_CSS = `
:root{--bg:#050505;--panel:rgba(15,20,25,.6);--line:#1f2937;--dim:#6b7280;--txt:#cbd5e1;--sky:#38bdf8;--indigo:#818cf8;--emerald:#34d399;--amber:#fbbf24}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;min-height:100vh;display:flex;flex-direction:column;
background-image:linear-gradient(rgba(25,25,30,.5) 1px,transparent 1px),linear-gradient(90deg,rgba(25,25,30,.5) 1px,transparent 1px);background-size:30px 30px}
a{color:inherit;text-decoration:none}
nav{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);padding:16px 24px}
.brand{color:var(--sky);font-weight:700;letter-spacing:.18em;text-shadow:0 0 10px rgba(56,189,248,.45)}
.navlinks{font-size:12px;color:var(--dim);display:flex;gap:16px}
.navlinks a:hover{color:var(--sky)}
main{flex:1;max-width:1100px;margin:0 auto;width:100%;padding:24px}
footer{border-top:1px solid var(--line);padding:20px 24px;font-size:11px;color:#4b5563}
h1{font-size:20px;color:#f3f4f6;margin-bottom:14px}
.glass{background:var(--panel);backdrop-filter:blur(10px);border:1px solid rgba(255,255,255,.05);border-radius:10px}
.grid{display:grid;gap:16px}
.g4{grid-template-columns:repeat(auto-fit,minmax(180px,1fr))}
.g2{grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}
.card{padding:16px}
.label{font-size:11px;color:var(--dim);letter-spacing:.08em}
.metric{font-size:22px;font-weight:700;margin-top:4px}
.bar{height:3px;background:#111827;border-radius:2px;margin-top:12px;overflow:hidden}
.bar>i{display:block;height:100%;width:60%}
.sky{color:var(--sky)}.indigo{color:var(--indigo)}.emerald{color:var(--emerald)}.amber{color:var(--amber)}
.bg-sky{background:var(--sky)}.bg-indigo{background:var(--indigo)}.bg-emerald{background:var(--emerald)}.bg-amber{background:var(--amber)}
.dim{color:var(--dim)}.small{font-size:12px}
.terminal{font-size:11px;line-height:1.45;height:170px;overflow:hidden;color:#9ca3af}
.chart{width:100%;height:230px;display:block}
ul.docs{list-style:none;font-size:13px}
ul.docs li{padding:6px 0;border-bottom:1px dashed #1f2937}
code{color:#e5e7eb}
`;

const DASH_JS = `
(function(){
  var cv=document.getElementById('chart');if(!cv)return;
  var ctx=cv.getContext('2d');
  var data=[];for(var i=0;i<48;i++)data.push(50+Math.random()*30);
  function resize(){cv.width=cv.clientWidth*devicePixelRatio;cv.height=cv.clientHeight*devicePixelRatio;}
  function draw(){
    var w=cv.width,h=cv.height;ctx.clearRect(0,0,w,h);
    var g=ctx.createLinearGradient(0,0,0,h);
    g.addColorStop(0,'rgba(56,189,248,.35)');g.addColorStop(1,'rgba(56,189,248,0)');
    var step=w/(data.length-1);
    ctx.beginPath();
    for(var i=0;i<data.length;i++){var x=i*step,y=h-(data[i]/200)*h;i?ctx.lineTo(x,y):ctx.moveTo(x,y);}
    ctx.strokeStyle='#38bdf8';ctx.lineWidth=2*devicePixelRatio;ctx.stroke();
    ctx.lineTo(w,h);ctx.lineTo(0,h);ctx.closePath();ctx.fillStyle=g;ctx.fill();
  }
  var logs=['Allocating 4096MB VRAM for transformer blocks...','KV cache synced across distributed nodes.','Attention mechanism optimized: FlashAttention-2 active.','Inference stream #2940 established.','Garbage collection executed. Freed 120MB.','Received embedding vector [dim=8192]. Processing...','Router: Forwarding request to GPU worker 02.','CUDA Core temperature stable at 68C.'];
  var term=document.getElementById('term');
  function id(n){return document.getElementById(n);}
  function tick(){
    var next=data[data.length-1]+(Math.random()*40-20);
    data.push(Math.max(20,Math.min(180,next)));data.shift();draw();
    if(id('vram'))id('vram').textContent=(Math.random()*2+14).toFixed(1)+' GB';
    if(id('tps'))id('tps').textContent=Math.floor(Math.random()*50+150);
    if(id('lat'))id('lat').textContent=Math.floor(Math.random()*20+35)+' ms';
    if(id('str'))id('str').textContent=Math.floor(Math.random()*5+12);
    if(term&&Math.random()>.55){
      var d=document.createElement('div'),t=new Date().toISOString().split('T')[1].slice(0,-1);
      var s=document.createElement('span');s.style.color='#4b5563';s.textContent='['+t+'] ';
      d.appendChild(s);d.appendChild(document.createTextNode(logs[Math.floor(Math.random()*logs.length)]));
      term.appendChild(d);
      while(term.childNodes.length>14)term.removeChild(term.firstChild);
    }
  }
  resize();window.addEventListener('resize',function(){resize();draw();});
  draw();setInterval(tick,800);
})();
`;

const renderAIMatrix = (res) => {
    const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LLM Node Edge Control</title>
<style>${BASE_CSS}</style>
</head><body>
<nav>
  <div class="brand">AETHER//MATRIX-CORE</div>
  <div class="navlinks"><a href="/about">About</a><a href="/docs">Docs</a></div>
</nav>
<main>
  <div class="grid g4" style="margin-bottom:16px">
    <div class="glass card"><div class="label">VRAM ALLOCATION</div><div class="metric sky" id="vram">15.2 GB</div><div class="bar"><i class="bg-sky" style="width:65%"></i></div></div>
    <div class="glass card"><div class="label">THROUGHPUT (TPS)</div><div class="metric indigo" id="tps">184</div><div class="bar"><i class="bg-indigo" style="width:80%"></i></div></div>
    <div class="glass card"><div class="label">QUANT TIME LATENCY</div><div class="metric emerald" id="lat">42 ms</div><div class="bar"><i class="bg-emerald" style="width:30%"></i></div></div>
    <div class="glass card"><div class="label">INFERENCE STREAMS</div><div class="metric amber" id="str">14</div><div class="bar"><i class="bg-amber" style="width:45%"></i></div></div>
  </div>
  <div class="grid g2">
    <div class="glass card" style="grid-column:span 2">
      <div class="label" style="padding-bottom:8px;border-bottom:1px solid var(--line);margin-bottom:12px">TENSOR PIPELINE EFFICIENCY (REAL-TIME)</div>
      <canvas id="chart" class="chart"></canvas>
    </div>
    <div class="glass card"><div class="label" style="padding-bottom:8px;border-bottom:1px solid var(--line);margin-bottom:8px">CLUSTER EVENT LOGS</div>
      <div class="terminal" id="term"></div>
    </div>
  </div>
</main>
<footer>© ${new Date().getFullYear()} Aether Matrix Core — build 4.2.0-prod</footer>
<script>${DASH_JS}</script>
</body></html>`;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(html);
};


// ====================================================================
// 本地静态伪装站 / 订阅分发
// ====================================================================

const NO_STORE = { 'Cache-Control': 'no-store', 'Content-Type': 'text/plain; charset=utf-8' };

// ---------- 本地伪装站（全部本地渲染，无第三方资源）----------
const PAGE_SHELL = (title, inner) => `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>${BASE_CSS}</style>
</head><body>
<nav>
  <div class="brand">AETHER//MATRIX-CORE</div>
  <div class="navlinks"><a href="/about">About</a><a href="/docs">Docs</a></div>
</nav>
<main>${inner}</main>
<footer>© ${new Date().getFullYear()} Aether Matrix Core. All rights reserved.</footer>
</body></html>`;

const DECOY_PAGES = {
    '/about': () => PAGE_SHELL('About — Aether Matrix Core', `
        <h1>About</h1>
        <p class="small dim" style="margin-bottom:12px">Aether Matrix Core is an internal inference control plane used to schedule
        transformer workloads across distributed GPU nodes. The console at the root path exposes live telemetry for
        cluster utilisation, KV-cache synchronisation and stream routing.</p>
        <p class="small dim">The service is operated for research and development purposes in a private environment.
        Public endpoints only expose aggregated, non-personal metrics.</p>`),
    '/docs': () => PAGE_SHELL('Docs — Aether Matrix Core', `
        <h1>Documentation</h1>
        <ul class="docs">
          <li><span class="sky">GET /</span> — live cluster console</li>
          <li><span class="sky">GET /about</span> — service overview</li>
          <li><span class="sky">GET /docs</span> — this page</li>
          <li><span class="sky">GET /robots.txt</span> — crawler policy</li>
        </ul>
        <p class="small dim" style="margin-top:14px">All telemetry is refreshed every 800 ms from the edge aggregator.</p>`)
};

const renderNotFound = (res, pathname) => {
    const safe = String(pathname || '/').replace(/[<>&"']/g, '');
    const html = PAGE_SHELL('404 — Not Found', `
        <h1>404</h1>
        <p class="small dim">The resource <code>${safe}</code> was not found on this server.</p>
        <p class="small" style="margin-top:18px"><a href="/" class="sky">Return to console</a></p>`);
    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(html);
};

const ROBOTS_TXT = 'User-agent: *\nDisallow: /\n';
const DECOY_ICON = Buffer.from(
    'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+' +
    'PHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiByeD0iOCIgZmlsbD0iIzA1MDUwNSIvPjxwYXRoIGQ9Ik0xNiA2TDI2IDE2TDE2IDI2IDYgMTZaIiBmaWxsPSIjMzhiZGY4Ii8+PC9zdmc+',
    'base64');

const serveDecoy = (req, res, pathname) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { ...NO_STORE, Allow: 'GET, HEAD' });
        return res.end('Method Not Allowed');
    }
    if (pathname === '/robots.txt') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'public, max-age=3600' });
        return res.end(ROBOTS_TXT);
    }
    if (pathname === '/favicon.ico' || pathname === '/favicon.svg') {
        res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' });
        return res.end(DECOY_ICON);
    }
    const page = DECOY_PAGES[pathname];
    if (page) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(page());
    }
    renderNotFound(res, pathname);
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

const SESSION_TTL = 30000;        // 官方：GET 未连上时 30 秒回收会话
// 官方对已建立下行的会话不做空闲回收（会话与 GET 同生命周期）。
// 这里只设一个很长的兜底上限，避免半开连接永久占用内存，同时不误杀长时间静默的隧道
// （例如 SSH / 数据库长连接）。可用 SESSION_MAX_IDLE_MS 覆盖。
const SESSION_MAX_IDLE = parseInt(process.env.SESSION_MAX_IDLE_MS || '1800000', 10);
// 官方 scMaxBufferedPosts 默认 30，超限即断开重排缓冲
const MAX_REASSEMBLY = ENV.SC_MAX_BUFFERED_POSTS > 0 ? ENV.SC_MAX_BUFFERED_POSTS : 30;

// 调试日志（默认关闭，排查链路时设 DEBUG=1）
const DEBUG = process.env.DEBUG === '1';
const dbg = (...args) => { if (DEBUG) console.log('[xh]', ...args); };

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
        dbg('sess', this.id, 'close');
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

// 官方无会话上限（Go 侧开销极低）；Node 需要防止未经 UUID 校验的 GET 耗尽内存
const getSession = (id) => {
    let s = SESSIONS.get(id);
    if (!s || s.closed) {
        if (SESSIONS.size >= ENV.MAX_SESSIONS) {
            // 先做一次回收再判定
            sweep();
            if (SESSIONS.size >= ENV.MAX_SESSIONS) return null;
        }
        s = new Session(id);
        SESSIONS.set(id, s);
    }
    return s;
};

// 统一回收僵死会话：未建立下行时用官方 30s TTL；已建立下行时仅做超长兜底回收
const sweep = () => {
    const now = Date.now();
    for (const s of SESSIONS.values()) {
        const idle = now - s.lastActive;
        const limit = s.res ? SESSION_MAX_IDLE : SESSION_TTL;
        if (idle > limit) { dbg('sess', s.id, 'reap idle=' + idle, s.res ? 'down' : 'no-down'); s.destroy(); }
    }
    for (const s of streamOneSessions.values()) {
        if (now - s.lastActive > SESSION_MAX_IDLE) s.destroy();
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

// 会话数达到 MAX_SESSIONS 时的快速失败（官方无此分支，Node 侧保护）
const overloaded = (res) => {
    if (!res.headersSent) {
        res.writeHead(503, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store', 'Retry-After': '5' });
    }
    try { res.end('Service Unavailable'); } catch (e) {}
};

// Xray 客户端使用 base64.RawURLEncoding（URL 安全、无填充）编码 header/cookie 分片
const decodeB64 = (str) => {
    const s = String(str).replace(/-/g, '+').replace(/_/g, '/');
    const pad = s.length % 4 === 0 ? s : s + '='.repeat(4 - (s.length % 4));
    return Buffer.from(pad, 'base64');
};

// 收集 packet-up 上行数据：官方顺序 header(X-Data-N) + cookie(x_data_N) + body
const collectUplinkPayload = (req, body) => {
    const parts = [];

    const headerChunks = [];
    for (let i = 0; ; i++) {
        const v = req.headers['x-data-' + i];
        if (!v) break;
        headerChunks.push(Array.isArray(v) ? v.join('') : v);
    }
    if (headerChunks.length) parts.push(decodeB64(headerChunks.join('')));

    const cookieChunks = [];
    const rawCookie = req.headers.cookie || '';
    for (let i = 0; ; i++) {
        const name = 'x_data_' + i;
        const hit = rawCookie.split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
        if (!hit) break;
        cookieChunks.push(hit.slice(name.length + 1));
    }
    if (cookieChunks.length) parts.push(decodeB64(cookieChunks.join('')));

    if (body && body.length) parts.push(body);

    return parts.length > 1 ? Buffer.concat(parts) : (parts[0] || Buffer.alloc(0));
};

// 读取请求体并强制 scMaxEachPostBytes 上限（官方超限返回 413）
const readBodyLimited = (req, max, cb) => {
    const declared = Number(req.headers['content-length'] || 0);
    if (declared > max) return cb(new Error('too-large'), null);

    const chunks = [];
    let size = 0;
    let done = false;
    const finish = (err, buf) => { if (done) return; done = true; cb(err, buf); };

    req.on('data', c => {
        size += c.length;
        if (size > max) {
            try { req.destroy(); } catch (e) {}
            return finish(new Error('too-large'), null);
        }
        chunks.push(c);
    });
    req.on('end', () => finish(null, Buffer.concat(chunks)));
    req.on('error', () => finish(new Error('aborted'), null));
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

    const session = getSession(sessionId);
    if (!session) { dbg('down', sessionId, '->503'); return overloaded(res); }
    dbg('down', sessionId, 'open');

    writeStreamHeaders(res);
    session.attachDownstream(res);

    // 兼容 stream-one 变体：GET 携带 body 时同样作为上行数据
    req.on('data', chunk => session.feed(chunk));
    req.on('error', () => session.destroy());
};

// ---------- 上行流（stream-up） ----------
const handleStreamUp = (req, res, sessionId) => {
    const session = getSession(sessionId);
    if (!session) return overloaded(res);

    dbg('up', sessionId, 'stream-up open');
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
    // 官方第 326 行：strconv.ParseUint(seqStr) 失败即报错，这里回 400 而不是静默丢弃
    if (!/^\d+$/.test(seqStr)) {
        res.writeHead(400, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
        return res.end('Invalid sequence');
    }

    const session = getSession(sessionId);
    if (!session) return overloaded(res);

    readBodyLimited(req, ENV.SC_MAX_EACH_POST_BYTES, (err, body) => {
        if (err) {
            // 超限 413 / 中断 400，与官方 StatusRequestEntityTooLarge 对齐
            const code = err.message === 'too-large' ? 413 : 400;
            if (!res.writableEnded) {
                res.writeHead(code, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
                res.end(code === 413 ? 'Request Entity Too Large' : 'Bad Request');
            }
            return;
        }

        const payload = collectUplinkPayload(req, body);
        dbg('post', sessionId, 'seq', seqStr, 'bytes', payload.length);
        // 即使 payload 为空也占用该 seq，保证重排窗口能推进（对齐官方 uploadQueue）
        session.pushPacket(seqStr, payload);

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

// 解析 Xray 默认放置方式生成的子路径：<path> | <path>/<sessionId> | <path>/<sessionId>/<seq>
// 对照官方：GetNormalizedPath() 会在 session/seq 位于 path 时补尾部 '/'，
// 提取方式为 strings.Split(req.URL.Path[len(path):], "/")，空段必须保留。
const parseXhttpPath = (pathname) => {
    const rest = pathname.slice(XHTTP_PREFIX.length);
    const parts = rest.split('/');
    if (parts[0] === '') parts.shift();                        // 去掉 path 后的第一个 '/'
    if (parts.length && parts[parts.length - 1] === '') parts.pop();  // 去掉 GetNormalizedPath 补的尾部 '/'
    if (parts.length > 2) return null;                        // 非法层级
    return { sessionId: parts[0] || '', seqStr: parts[1] || '' };
};

const handleXHTTP = (req, res, pathname) => {
    applyCors(req, res);

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return true;
    }

    const parsed = parseXhttpPath(pathname);
    if (!parsed) {
        // 与官方一致：路径不匹配即 404（这里渲染本地伪装 404 页）
        renderNotFound(res, pathname);
        return true;
    }
    const { sessionId, seqStr } = parsed;

    // seq 必须与 sessionId 同时出现（seq 位置在 path 时）
    if (seqStr !== '' && sessionId === '') {
        renderNotFound(res, pathname);
        return true;
    }

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

    res.writeHead(405, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store', Allow: 'GET, POST, OPTIONS' });
    res.end('Method Not Allowed');
    return true;
};

// ====================================================================
// 未知路径兜底 + 扫描型滥用限速
// ====================================================================

const SCAN_WINDOW_MS = 60000;
const SCAN_MAX_HITS = 40;        // 单 IP 每分钟允许的未知路径请求数
const SCAN_TABLE_MAX = 20000;
const scanTable = new Map();     // ip -> { count, resetAt }

// PaaS/CDN 会终结 TLS 并使用自身 IP 回源，因此优先取 XFF 最右侧（由可信代理追加）以保证
// 限速的按客户端粒度；缺失时退回 socket 地址。
const clientIp = (req) => {
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff.length) {
        const last = xff.split(',').pop().trim();
        if (last) return last;
    }
    return (req.socket && req.socket.remoteAddress) || 'unknown';
};

const isScanAbuser = (ip) => {
    const now = Date.now();
    let e = scanTable.get(ip);
    if (!e || e.resetAt <= now) {
        if (scanTable.size >= SCAN_TABLE_MAX) scanTable.clear();
        e = { count: 0, resetAt: now + SCAN_WINDOW_MS };
        scanTable.set(ip, e);
    }
    e.count++;
    return e.count > SCAN_MAX_HITS;
};

const scanSweeper = setInterval(() => {
    const now = Date.now();
    for (const [ip, e] of scanTable) if (e.resetAt <= now) scanTable.delete(ip);
}, 60000);
if (scanSweeper.unref) scanSweeper.unref();

const handleUnknownPath = (req, res, pathname) => {
    // 扫描器/爬虫对未知路径高频探测时，直接断开比返回内容更省资源
    if (isScanAbuser(clientIp(req))) {
        try { res.writeHead(429, { ...NO_STORE, 'Retry-After': '60' }); res.end('Too Many Requests'); } catch (e) {}
        return;
    }

    // 全部未知路径仅由本地伪装站渲染，不再有任何外部站点转发/跳转
    return serveDecoy(req, res, pathname);
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

    // 其余请求全部由本地伪装站渲染（无任何第三方转发）
    return handleUnknownPath(req, res, pathname);
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

