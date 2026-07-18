/**
 * 小猪码收集 - Node.js 反代服务(Render.com 部署)
 * =====================================================
 *
 * 用途:
 *   服务器(阿里云)被 52pojie 和 MT 论坛按 IP 段封锁,
 *   通过 Render.com 反代绕过(IP 不被封锁,render.com 国内可直连)。
 *
 * 调用方式:
 *   GET https://你的项目.onrender.com/proxy?url=<目标URL>
 *   Header: X-Proxy-Token: <你的-token>
 *
 * 部署方式:
 *   1. 打开 https://render.com → Sign Up → 用 GitHub 登录
 *   2. New + → Web Service → 选择 jitianOvo/pigma-proxy 仓库
 *   3. 配置(已写在仓库的 render.yaml):
 *      - Build Command: npm install
 *      - Start Command: node server.js
 *   4. 点击 Create Web Service
 *   5. 等待部署完成,拿到 URL:https://pigma-proxy.onrender.com
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

// ==================== 配置区 ====================
const PROXY_TOKEN = process.env.PROXY_TOKEN || "pigma-proxy-2026";
const PORT = process.env.PORT || 10000;

const ALLOWED_HOSTS = [
  "www.52pojie.cn",
  "bbs.binmt.cc",
];

const BROWSER_HEADERS = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
  "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
  "Sec-Ch-Ua": '"Chromium";v="136", "Not.A/Brand";v="99", "Google Chrome";v="136"',
  "Sec-Ch-Ua-Mobile": "?0",
  "Sec-Ch-Ua-Platform": '"Windows"',
  "Sec-Fetch-Dest": "document",
  "Sec-Fetch-Mode": "navigate",
  "Sec-Fetch-Site": "none",
  "Sec-Fetch-User": "?1",
  "Upgrade-Insecure-Requests": "1",
};
// ==================== 配置区结束 ====================


function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'X-Proxy-Token, Content-Type',
  });
  res.end(body);
}

function handler(req, res) {
  // CORS 预检
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'X-Proxy-Token, Content-Type',
    });
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host}`);

  // 健康检查
  if (url.pathname === '/' || url.pathname === '/health') {
    return sendJson(res, 200, {
      status: 'ok',
      service: 'pigma-node-proxy',
      allowed_hosts: ALLOWED_HOSTS,
    });
  }

  // 鉴权
  const token = req.headers['x-proxy-token'] || url.searchParams.get('token');
  if (token !== PROXY_TOKEN) {
    return sendJson(res, 403, { error: 'token 无效' });
  }

  // 提取目标 URL
  let targetUrl = url.searchParams.get('url');
  if (!targetUrl) {
    const m = url.pathname.match(/^\/proxy\/(.+)$/);
    if (m) {
      try {
        targetUrl = decodeURIComponent(m[1]);
      } catch (e) {
        targetUrl = m[1];
      }
    }
  }

  if (!targetUrl) {
    return sendJson(res, 400, {
      error: '缺少目标 URL',
      usage: 'GET /proxy?url=<目标URL>',
    });
  }

  let target;
  try {
    target = new URL(targetUrl);
  } catch (e) {
    return sendJson(res, 400, { error: '目标 URL 无效' });
  }

  // 域名白名单
  if (!ALLOWED_HOSTS.includes(target.hostname)) {
    return sendJson(res, 403, {
      error: '域名不在白名单',
      host: target.hostname,
      allowed: ALLOWED_HOSTS,
    });
  }

  // 构造转发 headers
  const forwardHeaders = { ...BROWSER_HEADERS };
  forwardHeaders['Referer'] = target.origin + '/';
  forwardHeaders['Sec-Fetch-Site'] = 'same-origin';
  if (req.headers.cookie) {
    forwardHeaders['Cookie'] = req.headers.cookie;
  }

  // 发起请求
  const options = {
    hostname: target.hostname,
    port: target.port || 443,
    path: target.pathname + target.search,
    method: req.method,
    headers: forwardHeaders,
    // 自动处理 gzip/deflate
    decompress: true,
  };

  const proxyReq = https.request(options, (proxyRes) => {
    const respHeaders = { ...proxyRes.headers };
    respHeaders['Access-Control-Allow-Origin'] = '*';
    respHeaders['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    respHeaders['Access-Control-Allow-Headers'] = 'X-Proxy-Token, Content-Type';
    respHeaders['X-Proxied-By'] = 'pigma-node';

    res.writeHead(proxyRes.statusCode, proxyRes.statusMessage, respHeaders);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (e) => {
    sendJson(res, 502, { error: '上游请求失败', detail: String(e) });
  });

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    req.pipe(proxyReq);
  } else {
    proxyReq.end();
  }
}

const server = http.createServer(handler);
server.listen(PORT, () => {
  console.log(`pigma-proxy listening on port ${PORT}`);
});
