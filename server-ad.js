// ====================================================================
// Void AI Matrix Service (XHTTP / SplitHTTP Alwaysdata Edition)
//
// 纯 XHTTP（Xray SplitHTTP）传输的 VLESS 服务端，无 WebSocket 依赖。
// 环境变量（★ = 留空即自适应，通常无需配置）：
//   UUID                   必填，节点鉴权 ID（同时作为订阅路径 /<UUID>）
//   PORT                   监听端口，默认 8100（PaaS 通常自动注入）
//   IP                     监听地址，默认 0.0.0.0（PaaS 通常自动注入）
//   XHTTP_PATH             XHTTP 传输路径，默认 /xh（需与订阅链接 path 一致）
//   SC_MAX_EACH_POST_BYTES packet-up 单次 POST 上限，默认 1000000（对齐 Xray 默认）
//   SC_MAX_BUFFERED_POSTS  乱序重排缓冲包数，默认 30（对齐 Xray 默认）
//   MAX_SESSIONS         ★ 并发会话上限，留空按内存自动推算（256–8192）
//   SESSION_MAX_IDLE_MS    已建立下行的会话兜底回收时间，默认 1800000
//   ALPN                 ★ 订阅里的 ALPN，默认 h2,http/1.1（按边缘能力调整）
//   UDP_MODE             ★ auto 默认：自动探测出网 UDP，可用则 53 也走真实 UDP，否则 DNS 走 DoH
//   UDP_PROBE_TARGET       出网探测目标，默认 1.1.1.1:53
//   TCP_KEEPALIVE_MS     ★ 入站/出站 TCP keep-alive，默认 30000（按 PaaS 空闲阈值调）
//   STREAM_UP_KEEPALIVE_MS ★ stream-up 上行保活，默认 20000
//   DEBUG                  设为 1 输出 XHTTP 调试日志
//
// 运行时要求：
//   Node.js >= 16（推荐 18/20 LTS）。仅使用内置模块（http/https/net/dgram/crypto/fs/os），
//   无 npm 依赖、无原生扩展，因此在 x86_64 / arm64 / armv7 / 其他 Node 支持的架构上行为一致；
//   Linux / macOS / Windows 均可运行（cgroup 内存上限仅 Linux 读取，其余回退 os.totalmem()）。
//   H2C_ONLY=1 可切换为明文 HTTP/2 监听：仅用于「平台以 h2 回源到应用」的场景，
//   因为 Node 的明文 h2 服务无法与 HTTP/1.1 共用同一端口。
//
// 未知路径一律由本地静态伪装站响应，不存在任何第三方站点转发/跳转能力。
// 唯一的外部出站是可选 DoH（UDP 被封时的 DNS 兜底），且仅访问公共 DNS 解析器。
// ====================================================================

const http = require('http');
const https = require('https');
const net = require('net');
const dgram = require('dgram');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');

const ENV = { 
    S_TKN: process.env.UUID || '', 
    // 【核心修复1】适配 Alwaysdata 注入的内部 IP 和端口
    PORT: process.env.PORT || 8100,
    IP: process.env.IP || '0.0.0.0',
    XHTTP_PATH: process.env.XHTTP_PATH || '/xh',
    // 与 Xray 服务端默认值保持一致（splithttp.GetNormalized*）
    SC_MAX_EACH_POST_BYTES: parseInt(process.env.SC_MAX_EACH_POST_BYTES || '1000000', 10),
    SC_MAX_BUFFERED_POSTS: parseInt(process.env.SC_MAX_BUFFERED_POSTS || '30', 10),
    // 进程保护：未通过 UUID 校验的会话上限；0 / 未设置时按内存自动推算
    MAX_SESSIONS: parseInt(process.env.MAX_SESSIONS || '0', 10) || 0,
    // 订阅链接中的 ALPN，默认同时提供 h2 与 http/1.1
    ALPN: process.env.ALPN || 'h2,http/1.1',
    // UDP 出口：auto（默认，探测出网能力后决定）| direct（强制真实 UDP）| doh（强制 HTTPS DNS）
    UDP_MODE: (process.env.UDP_MODE || 'auto').toLowerCase()
};

// --------------------------------------------------------------------
// 自适应：内存上限（容器 cgroup 优先）→ 并发会话上限
// --------------------------------------------------------------------
const readCgroupLimit = (path) => {
    try {
        const raw = fs.readFileSync(path, 'utf8').trim();
        if (raw === 'max') return 0;
        const n = parseInt(raw, 10);
        return Number.isFinite(n) && n > 0 ? n : 0;
    } catch (e) { return 0; }
};

const MEM_LIMIT = (() => {
    const v2 = readCgroupLimit('/sys/fs/cgroup/memory.max');
    if (v2 > 0) return v2;
    const v1 = readCgroupLimit('/sys/fs/cgroup/memory/memory.limit_in_bytes');
    if (v1 > 0 && v1 < Number.MAX_SAFE_INTEGER) return v1;
    return os.totalmem();
})();

// 每个活跃会话按最多 ~2MB（1MB 上行分片 + 256KB 下行缓冲 + 排序窗口）保守估算
const MAX_SESSIONS = ENV.MAX_SESSIONS > 0
    ? ENV.MAX_SESSIONS
    : Math.min(8192, Math.max(256, Math.floor(MEM_LIMIT / (2 * 1024 * 1024))));

// --------------------------------------------------------------------
// 自适应：UDP 出网能力探测（决定 auto 模式下 :53 走真实 UDP 还是 DoH）
// 探测本身不改行为，未完成/失败时统一按“不可用”处理，即 DNS 走 DoH（更稳）
// --------------------------------------------------------------------
const UDP_PROBE_TARGET = process.env.UDP_PROBE_TARGET || '1.1.1.1';
let UDP_EGRESS = false;

const probeUdpEgress = () => new Promise(resolve => {
    let sock;
    let settled = false;
    const done = (ok) => {
        if (settled) return;
        settled = true;
        try { sock && sock.close(); } catch (e) {}
        resolve(ok);
    };
    try { sock = dgram.createSocket('udp4'); } catch (e) { return done(false); }

    sock.once('error', () => done(false));
    sock.once('message', () => done(true));
    const timer = setTimeout(() => done(false), 1500);
    if (timer.unref) timer.unref();

    // 最小的 DNS 查询（example.com A）
    const q = Buffer.from('abcd01000001000000000000076578616d706c6503636f6d0000010001', 'hex');
    try {
        sock.send(q, 53, UDP_PROBE_TARGET, err => { if (err) done(false); });
    } catch (e) { done(false); }
});

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

// 进程级异常：保持存活（单连接故障不应拖垮节点），但必须留下日志，不能静默吞掉
let _errWindowStart = Date.now();
let _errInWindow = 0;

const reportError = (kind, err) => {
    const now = Date.now();
    if (now - _errWindowStart > 60000) { _errWindowStart = now; _errInWindow = 0; }
    if (_errInWindow++ > 20) return;   // 限流，避免日志风暴拖慢进程
    const msg = err && (err.stack || err.message) ? (err.stack || err.message) : String(err);
    console.error(`[${kind}]`, msg);
};

process.on('uncaughtException', (err) => reportError('uncaughtException', err));
process.on('unhandledRejection', (err) => reportError('unhandledRejection', err));

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
    if (buf.length < 19 || !Registry.get('validate')(buf)) return null;
    const mLen = buf[17];
    const prot = buf[18 + mLen];

    // cmd=3 为 Mux(XUDP)：官方该请求头只有 version+uuid+addons+command，
    // 目标地址在 XUDP 帧内，因此不能沿用 port/address 的偏移。
    if (prot === 3) {
        return { prot, type: 0, port: 0, clusterId: null, pOff: 19 + mLen };
    }

    if (buf.length < 24 + mLen) return null;
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
    const encAlpn = encodeURIComponent(ENV.ALPN);
    // 标准 XHTTP (SplitHTTP) VLESS 分享链接
    const link = `vless://${ENV.S_TKN}@${hostNoPort}:${port}?encryption=none&security=tls&sni=${hostNoPort}&fp=chrome&alpn=${encAlpn}&type=xhttp&mode=auto&path=${encPath}#${tag}`;
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(Buffer.from(link).toString('base64'));
};

// ====================================================================
// XHTTP (SplitHTTP) 核心引擎
// ====================================================================

const DOH_ENDPOINTS = ['aHR0cHM6Ly8xLjEuMS4xL2Rucy1xdWVyeQ==','aHR0cHM6Ly9kbnMuZ29vZ2xlL2Rucy1xdWVyeQ==','aHR0cHM6Ly85LjkuOS45L2Rucy1xdWVyeQ=='].map(b64 => Buffer.from(b64, 'base64').toString('utf8'));

// DoH 单次查询（内置 https，无第三方依赖；带连接/响应超时，避免挂死会话）
const DOH_TIMEOUT_MS = parseInt(process.env.DOH_TIMEOUT_MS || '5000', 10);

const dohQuery = (endpoint, body) => new Promise((resolve, reject) => {
    let url;
    try { url = new URL(endpoint); } catch (e) { return reject(e); }
    if (url.protocol !== 'https:') return reject(new Error('doh endpoint must be https'));

    const req = https.request({
        protocol: 'https:',
        hostname: url.hostname,
        port: url.port || 443,
        path: (url.pathname || '/') + (url.search || ''),
        method: 'POST',
        timeout: DOH_TIMEOUT_MS,
        headers: {
            'Host': url.host,
            'Accept': 'application/dns-message',
            'Content-Type': 'application/dns-message',
            'Content-Length': body.length
        }
    }, res => {
        if (res.statusCode !== 200) { res.resume(); return reject(new Error('doh status ' + res.statusCode)); }
        const chunks = [];
        let size = 0;
        res.on('data', c => {
            size += c.length;
            if (size > 65535) { try { res.destroy(); } catch (e) {} return reject(new Error('doh response too large')); }
            chunks.push(c);
        });
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
    });

    req.on('timeout', () => req.destroy(new Error('doh timeout')));
    req.on('error', reject);
    req.end(body);
});

// 会话表：sessionId -> Session
const SESSIONS = new Map();
// 无 sessionId 的 stream-one 单流会话（按连接标识）
const streamOneSessions = new Map();

// ---- XUDP（Xray 的 UDP over Mux 封装）：VLESS cmd=3 + 帧结构 ----
// 帧： [2B metaLen][2B sessionID][status][opt][cmd=2][2B port][atyp][addr][8B globalID?][2B dataLen][data]
// 回包：[2B metaLen=4][2B sessionID][status=2][opt=1][2B dataLen][data]
const readAddrPort = (buf, off) => {
    if (off + 3 > buf.length) return null;
    const port = (buf[off] << 8) | buf[off + 1];
    const atyp = buf[off + 2];
    let p = off + 3;
    let host;
    if (atyp === 1) {
        if (p + 4 > buf.length) return null;
        host = `${buf[p]}.${buf[p + 1]}.${buf[p + 2]}.${buf[p + 3]}`;
        p += 4;
    } else if (atyp === 2) {
        const len = buf[p]; p += 1;
        if (p + len > buf.length) return null;
        host = buf.toString('utf8', p, p + len);
        p += len;
    } else if (atyp === 3) {
        if (p + 16 > buf.length) return null;
        const seg = [];
        for (let i = 0; i < 8; i++) seg.push(buf.readUInt16BE(p + i * 2).toString(16));
        host = seg.join(':');
        p += 16;
    } else {
        return null;
    }
    return { host, port };
};

const SESSION_TTL = 30000;        // 官方：GET 未连上时 30 秒回收会话
// 官方对已建立下行的会话不做空闲回收（会话与 GET 同生命周期）。
// 这里只设一个很长的兜底上限，避免半开连接永久占用内存，同时不误杀长时间静默的隧道
// （例如 SSH / 数据库长连接）。可用 SESSION_MAX_IDLE_MS 覆盖。
const SESSION_MAX_IDLE = parseInt(process.env.SESSION_MAX_IDLE_MS || '1800000', 10);
// 官方 scMaxBufferedPosts 默认 30，超限即断开重排缓冲
const MAX_REASSEMBLY = ENV.SC_MAX_BUFFERED_POSTS > 0 ? ENV.SC_MAX_BUFFERED_POSTS : 30;

// UDP 出口模式（direct：真实 UDP 中继；doh：HTTPS DNS；auto：direct 失败时 53 端口回退 DoH）
const UDP_MODE = ENV.UDP_MODE;
// stream-up 上行保活间隔：客户端会丢弃响应体，用 'X' 防止中间层判定静默
const STREAM_UP_KEEPALIVE_MS = Math.max(5000, parseInt(process.env.STREAM_UP_KEEPALIVE_MS || '20000', 10));
// TCP 层保活：不产生任何应用层字节，因此不会破坏 VLESS 流，是空闲下行的唯一合法保活方式
const TCP_KEEPALIVE_MS = Math.max(5000, parseInt(process.env.TCP_KEEPALIVE_MS || '30000', 10));
// 目标 TCP 连接阶段超时（不影响已建立连接的空闲时长）
const EDGE_CONNECT_TIMEOUT_MS = Math.max(2000, parseInt(process.env.EDGE_CONNECT_TIMEOUT_MS || '10000', 10));

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
        this.udpSocket = null;
        this.udpHost = '';
        this.udpPort = 0;
        this.isXudp = false;
        this.edgePaused = false;
        this.inputPaused = false;
        this.input = null;
        this.xudpBuffer = Buffer.alloc(0);
        this.xudpSid = null;
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

        let ok = true;
        try { ok = this.res.write(buf); } catch (e) { return this.destroy(); }

        // 背压：客户端读得慢时暂停读取目标 socket，避免 Node 侧无限缓冲吃光内存
        if (ok === false) this.pauseEdge();
    }

    pauseEdge() {
        const s = this.edgeSocket;
        if (!s || s.destroyed || this.edgePaused) return;
        this.edgePaused = true;
        try { s.pause(); } catch (e) {}
        const resume = () => {
            this.edgePaused = false;
            if (this.edgeSocket && !this.edgeSocket.destroyed) {
                try { this.edgeSocket.resume(); } catch (e) {}
            }
        };
        if (this.res && !this.res.writableEnded) this.res.once('drain', resume);
        else resume();
    }

    // 上行写入目标 socket；写不动时暂停读取入站请求，等 drain 再恢复
    writeEdge(buf) {
        const s = this.edgeSocket;
        if (this.closed || !s || s.destroyed) return;
        let ok = true;
        try { ok = s.write(buf); } catch (e) { return this.destroy(); }
        if (ok === false) this.pauseInput(s);
    }

    pauseInput(sock) {
        const req = this.input;
        if (!req || this.inputPaused || sock.destroyed) return;
        this.inputPaused = true;
        try { req.pause(); } catch (e) { this.inputPaused = false; return; }
        sock.once('drain', () => {
            this.inputPaused = false;
            try { req.resume(); } catch (e) {}
        });
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
            dbg('first-packet', 'len=' + buf.length, 'cmd=' + meta.prot, 'port=' + meta.port, 'type=' + meta.type);
            if (!meta) { this.destroy(); return; }

            // VLESS 服务端握手响应：[version, 0]
            this.sendDownstream(Buffer.from([buf[0], 0]));

            const initial = buf.subarray(meta.pOff);

            if (meta.prot === 3) {           // XUDP：Xray 的 UDP over Mux（cmd=3）
                this.isUDP = true;
                this.isXudp = true;
                dbg('xudp open');
                if (initial.length > 0) {
                    this.xudpBuffer = initial;
                    this.processXudp();
                }
                return;
            }

            if (meta.prot === 2) {           // UDP：VLESS 数据在 TCP(XHTTP) 内承载，服务端用 dgram 中继
                this.isUDP = true;
                this.udpHost = Registry.get('resolve')(meta.type, meta.clusterId);
                this.udpPort = meta.port;
                dbg('udp open', this.udpHost + ':' + this.udpPort, 'mode=' + UDP_MODE);
                if (initial.length > 0) {
                    this.udpBuffer = initial;
                    this.processUDP();
                }
                return;
            }

            // TCP 直连目标
            const host = Registry.get('resolve')(meta.type, meta.clusterId);
            let edgeConnected = false;
            this.edgeSocket = net.createConnection({ host: host, port: meta.port }, () => {
                edgeConnected = true;
                clearTimeout(connectTimer);
                if (initial.length > 0) this.writeEdge(initial);
            });

            // 连接阶段超时：目标被黑洞/不可达时不能一直占着会话（不影响已建立连接的空闲时长）
            const connectTimer = setTimeout(() => {
                if (!edgeConnected) { dbg('edge connect timeout', host + ':' + meta.port); this.destroy(); }
            }, EDGE_CONNECT_TIMEOUT_MS);
            if (connectTimer.unref) connectTimer.unref();
            this.edgeSocket.once('close', () => clearTimeout(connectTimer));

            this.edgeSocket.setNoDelay(true);
            try { this.edgeSocket.setKeepAlive(true, TCP_KEEPALIVE_MS); } catch (e) {}
            this.edgeSocket.on('data', chunk => this.sendDownstream(chunk));
            this.edgeSocket.on('error', () => this.destroy());
            this.edgeSocket.on('close', () => this.destroy());
            return;
        }

        if (this.isUDP) {
            if (this.isXudp) {
                this.xudpBuffer = Buffer.concat([this.xudpBuffer, buf]);
                this.processXudp();
            } else {
                this.udpBuffer = Buffer.concat([this.udpBuffer, buf]);
                this.processUDP();
            }
        } else {
            this.writeEdge(buf);
        }
    }

    // XUDP 解帧：可在一个 TCP 流中连续解析多个数据报
    processXudp() {
        while (!this.closed && this.xudpBuffer.length >= 4) {
            const metaLen = this.xudpBuffer.readUInt16BE(0);
            if (metaLen < 4) { this.destroy(); return; }
            if (this.xudpBuffer.length < 2 + metaLen + 2) return;   // 元信息 + dataLen 尚未到齐
            const meta = this.xudpBuffer.subarray(2, 2 + metaLen);
            const status = meta[2];
            const opt = meta[3];

            const dataLenOff = 2 + metaLen;
            const dataLen = this.xudpBuffer.readUInt16BE(dataLenOff);
            const dataOff = dataLenOff + 2;
            if (this.xudpBuffer.length < dataOff + dataLen) return;

            const datagram = this.xudpBuffer.subarray(dataOff, dataOff + dataLen);
            this.xudpBuffer = this.xudpBuffer.subarray(dataOff + dataLen);

            // 记录 sessionID，回包时原样带回
            if (!this.xudpSid) this.xudpSid = [meta[0], meta[1]];

            // meta 中携带目标地址（New 必带；Keep 在 cone/变更目的地址时带）
            if (metaLen > 6) {
                const cmd = meta[4];
                if (cmd !== 2) {           // 只支持 UDP，不实现 Mux 里的 TCP 复用
                    dbg('xudp unsupported cmd', cmd);
                    this.destroy();
                    return;
                }
                const dest = readAddrPort(meta, 5);
                if (dest) { this.udpHost = dest.host; this.udpPort = dest.port; }
            }

            if (opt === 1 && dataLen > 0) {
                if (!this.udpHost) { this.destroy(); return; }
                dbg('xudp datagram', this.udpHost + ':' + this.udpPort, dataLen + 'B', 'status=' + status);
                this.dispatchUdp(datagram);
            }
        }
    }

    // XUDP 回包：[2B metaLen=4][2B sessionID][status=2 Keep][opt=1][2B len][data]
    sendXudp(datagram) {
        const sid = this.xudpSid || [0, 0];
        const frame = Buffer.allocUnsafe(2 + 4 + 2 + datagram.length);
        frame.writeUInt16BE(4, 0);         // metaLen
        frame[2] = sid[0];
        frame[3] = sid[1];
        frame[4] = 2;                      // status: Keep
        frame[5] = 1;                      // opt: 带数据
        frame.writeUInt16BE(datagram.length, 6);
        datagram.copy(frame, 8);
        this.sendDownstream(frame);
    }

    // 普通 VLESS UDP 帧格式：[2 字节长度][数据报]（mihomo / sing-box 等客户端）
    processUDP() {
        while (!this.closed && this.udpBuffer.length >= 2) {
            const len = (this.udpBuffer[0] << 8) | this.udpBuffer[1];
            if (this.udpBuffer.length < 2 + len) break;
            const datagram = this.udpBuffer.subarray(2, 2 + len);
            this.udpBuffer = this.udpBuffer.subarray(2 + len);
            this.dispatchUdp(datagram);
        }
    }

    // auto：探测到本机可出 UDP 时，:53 也走真实 UDP；否则 DNS 改走 DoH（多数 PaaS 禁 UDP 出网）。
    // 其余端口没有 HTTP 层替代方案，始终走真实 UDP 中继。
    shouldUseDoh() {
        if (UDP_MODE === 'doh') return true;
        if (UDP_MODE === 'direct') return false;
        return this.udpPort === 53 && !UDP_EGRESS;
    }

    dispatchUdp(datagram) {
        const viaDoh = this.shouldUseDoh();
        dbg('udp via', viaDoh ? 'DoH' : 'direct', this.udpHost + ':' + this.udpPort);
        if (viaDoh) return this.resolveDoH(datagram);
        this.sendUdp(datagram);
    }

    // 直连 UDP：UDP 报文封装在 TCP 里穿过 XHTTP，服务端再以真实 UDP 发往目标
    sendUdp(datagram) {
        const sock = this.ensureUdpSocket();
        if (!sock) return this.udpDowngrade(datagram);
        try {
            sock.send(datagram, 0, datagram.length, this.udpPort, this.udpHost, err => {
                if (err) this.udpDowngrade(datagram);
            });
        } catch (e) {
            this.udpDowngrade(datagram);
        }
    }

    ensureUdpSocket() {
        if (this.udpSocket) return this.udpSocket;
        if (this.closed) return null;

        const family = this.udpHost && this.udpHost.includes(':') ? 'udp6' : 'udp4';
        let sock;
        try { sock = dgram.createSocket(family); } catch (e) { return null; }

        sock.on('message', msg => {
            if (this.closed) return;
            if (this.isXudp) return this.sendXudp(msg);
            const frame = Buffer.allocUnsafe(2 + msg.length);
            frame[0] = (msg.length >> 8) & 0xFF;
            frame[1] = msg.length & 0xFF;
            msg.copy(frame, 2);
            this.sendDownstream(frame);
        });
        sock.on('error', e => {
            dbg('udp error', e && e.message);
            this.udpSocket = null;
            try { sock.close(); } catch (_) {}
            // 出错后对该会话后续报文走回退路径（DoH 仅对 53 端口）
            this.udpBroken = true;
        });
        sock.unref && sock.unref();

        this.udpSocket = sock;
        return sock;
    }

    // 直连 UDP 不可用时的回退：auto 模式下仅对 DNS(53) 走 DoH，其余断开
    udpDowngrade(datagram) {
        if (UDP_MODE === 'auto' && this.udpPort === 53) return this.resolveDoH(datagram);
        dbg('udp unsupported', this.udpHost + ':' + this.udpPort);
        this.destroy();
    }

    // DoH：用内置 https 客户端实现，避免依赖全局 fetch（Node <18 无 fetch，且 fetch 无超时会挂住）
    async resolveDoH(query) {
        for (const endpoint of DOH_ENDPOINTS) {
            if (this.closed) return;
            try {
                const answer = await dohQuery(endpoint, query);
                if (!answer || answer.length === 0) continue;
                const frame = Buffer.allocUnsafe(2 + answer.length);
                frame[0] = (answer.length >> 8) & 0xFF;
                frame[1] = answer.length & 0xFF;
                answer.copy(frame, 2);
                this.sendDownstream(frame);
                return;
            } catch (e) { /* 尝试下一个 DoH 节点 */ }
        }
        dbg('doh all endpoints failed for', this.udpHost + ':' + this.udpPort);
    }

    destroy() {
        if (this.closed) return;
        this.closed = true;
        dbg('sess', this.id, 'close');
        if (SESSIONS.get(this.id) === this) SESSIONS.delete(this.id);
        if (streamOneSessions.get(this.id) === this) streamOneSessions.delete(this.id);
        if (this.edgeSocket) { this.edgeSocket.destroy(); this.edgeSocket = null; }
        if (this.udpSocket) { try { this.udpSocket.close(); } catch (e) {} this.udpSocket = null; }
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
        if (SESSIONS.size >= MAX_SESSIONS) {
            // 先做一次回收再判定
            sweep();
            if (SESSIONS.size >= MAX_SESSIONS) return null;
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
    // 注意：不设置 Connection 等逐跳首部（HTTP/1.1 默认长连接），
    // 避免经过 h2 终结层/反向代理时出现非法首部。
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-store, no-transform',
        'X-Accel-Buffering': 'no'
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
    session.input = req;
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
    session.input = req;

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
    session.input = req;
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
    }, STREAM_UP_KEEPALIVE_MS);
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
// 真实客户端 IP：Cloudflare(CF-Connecting-IP) → XFF 最右侧（由可信代理追加）→ socket 地址
// TRUST_PROXY=0 时忽略代理头（仅在 service 直接暴露于公网、无前置代理时使用）
const TRUST_PROXY = process.env.TRUST_PROXY !== '0';

const clientIp = (req) => {
    if (TRUST_PROXY) {
        const cf = req.headers['cf-connecting-ip'];
        if (typeof cf === 'string' && cf.trim()) return cf.trim();

        const xff = req.headers['x-forwarded-for'];
        if (typeof xff === 'string' && xff.length) {
            const last = xff.split(',').pop().trim();
            if (last) return last;
        }
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

const handleRequest = (req, res) => {
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
};

// 传输层选择：默认 HTTP/1.1（PaaS 回源绝大多数是 h1.1）。
// H2C_ONLY=1 时改为明文 HTTP/2 监听——仅用于「平台确实以 h2 回源到应用」的少数场景，
// 因为 Node 的 http2 明文服务不支持与 h1.1 共用同一端口（allowHTTP1 只对 TLS+ALPN 生效）。
const H2C_ONLY = process.env.H2C_ONLY === '1';
const server = H2C_ONLY
    ? require('http2').createServer(handleRequest)
    : http.createServer(handleRequest);

// H2C 模式下 http2 服务没有这些 http1 专有属性，赋值前先判断，避免行为差异
if (!H2C_ONLY) {
    server.keepAliveTimeout = 75000;   // 空闲 keep-alive 连接（无进行中请求）保留时间
    server.headersTimeout = 80000;     // 必须大于 keepAliveTimeout
    server.requestTimeout = 0;         // 关闭整请求超时，否则 stream-up 长 POST 会被切断
    server.maxRequestsPerSocket = 0;   // 不限制单连接复用次数（packet-up 会频繁复用）
    server.timeout = 0;                // 不因 socket 空闲而关闭（空闲下行由 TCP keep-alive 维持）
}

// 入站连接：关闭 Nagle + 开启 TCP keep-alive
// TCP keep-alive 只发 ACK 级探测包，不产生应用层字节，因此不会破坏 VLESS 流，
// 是保持空闲下行（SSE）不被 PaaS/中间设备按空闲超时掐断的唯一合法手段。
server.on('connection', socket => {
    try { socket.setNoDelay(true); } catch (e) {}
    try { socket.setKeepAlive(true, TCP_KEEPALIVE_MS); } catch (e) {}
});

server.on('clientError', (err, socket) => {
    try { socket.destroy(); } catch (e) {}
});

// 监听失败（EADDRINUSE / EACCES 等）必须显式退出并打印，否则会被 uncaughtException 静默吃掉
server.on('error', (err) => {
    console.error('[FATAL] server error:', err && (err.code || err.message));
    process.exit(1);
});

// 优雅停机：PaaS 重部署会发 SIGTERM，先停止接收再主动关闭隧道，避免连接悬挂
let shuttingDown = false;
const shutdown = (sig) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[shutdown] ${sig}, closing ${SESSIONS.size} session(s)`);
    try { server.close(); } catch (e) {}
    for (const s of SESSIONS.values()) s.destroy();
    for (const s of streamOneSessions.values()) s.destroy();
    const t = setTimeout(() => process.exit(0), 500);
    if (t.unref) t.unref();
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// 【核心修复2】强制绑定 ENV.IP，否则 Alwaysdata 反向代理无法找到你的服务
server.listen(ENV.PORT, ENV.IP, () => {
    console.log(`Aether Node Operations Active on ${ENV.IP}:${ENV.PORT} (XHTTP/SplitHTTP)`);
    console.log(`XHTTP path: ${XHTTP_PREFIX}`);

    // 自适应：内存上限 → 会话上限；UDP 出网能力 → auto 模式 DNS 路径
    console.log(`mem limit: ${(MEM_LIMIT / 1048576).toFixed(0)} MB, max sessions: ${MAX_SESSIONS}${ENV.MAX_SESSIONS > 0 ? ' (env)' : ' (auto)'}`);
    console.log(`udp mode: ${UDP_MODE}${UDP_MODE === 'auto' ? ' (probing outbound UDP...)' : ''}`);

    if (UDP_MODE === 'auto') {
        probeUdpEgress().then(ok => {
            UDP_EGRESS = ok;
            console.log(`udp egress: ${ok ? 'available -> :53 via real UDP' : 'blocked -> :53 via DoH'}`);
        });
    } else {
        UDP_EGRESS = UDP_MODE === 'direct';
        console.log(`udp egress: forced ${UDP_MODE}`);
    }
});

