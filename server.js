/**
 * 小猪码收集 - Node.js 反代服务(Render.com 部署)
 * v2: 增加 cookie 持久化池 + 瑞数 WAF 自动重试
 *
 * 调用方式:
 *   GET https://你的项目.onrender.com/proxy?url=<目标URL>
 *   Header: X-Proxy-Token: <你的-token>
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
  "binmt.cc",
  "www.kanxue.com",
  "bbs.kanxue.com",
];

// Cookie 池:每个 host 保存最近拿到的 cookie
// {host: {cookie: "xxx", updatedAt: 1234567890}}
const cookiePool = new Map();
const COOKIE_TTL_MS = 30 * 60 * 1000;  // 30 分钟

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

function parseSetCookies(setCookieHeaders) {
  const cookies = [];
  if (!setCookieHeaders) return cookies;
  if (!Array.isArray(setCookieHeaders)) {
    setCookieHeaders = [setCookieHeaders];
  }
  for (const sc of setCookieHeaders) {
    const m = sc.match(/^([^=]+)=([^;]*)/);
    if (m) cookies.push(`${m[1]}=${m[2]}`);
  }
  return cookies;
}

function getCookieForHost(host) {
  const entry = cookiePool.get(host);
  if (!entry) return null;
  if (Date.now() - entry.updatedAt > COOKIE_TTL_MS) {
    cookiePool.delete(host);
    return null;
  }
  return entry.cookie;
}

function setCookieForHost(host, setCookieHeaders) {
  const newCookies = parseSetCookies(setCookieHeaders);
  if (newCookies.length === 0) return;
  const existing = getCookieForHost(host);
  const all = existing ? `${existing}; ${newCookies.join('; ')}` : newCookies.join('; ');
  cookiePool.set(host, { cookie: all, updatedAt: Date.now() });
}

function doRequest(target, method, headers, body, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: target.hostname,
      port: target.port || 443,
      path: target.pathname + target.search,
      method: method,
      headers: headers,
    };
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          statusText: res.statusMessage,
          headers: res.headers,
          body: Buffer.concat(chunks),
        });
      });
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error('timeout'));
    });
    if (body) req.write(body);
    req.end();
  });
}


async function fetchThroughProxy(target, req) {
  const host = target.hostname;

  // 构造转发 headers
  const forwardHeaders = { ...BROWSER_HEADERS };
  forwardHeaders['Referer'] = target.origin + '/';
  forwardHeaders['Sec-Fetch-Site'] = 'same-origin';

  // 用 cookie 池里的 cookie
  const cookie = getCookieForHost(host);
  if (cookie) {
    forwardHeaders['Cookie'] = cookie;
  } else if (req.headers.cookie) {
    forwardHeaders['Cookie'] = req.headers.cookie;
  }

  // 第一次请求
  let response = await doRequest(target, req.method, forwardHeaders);
  // 保存 set-cookie
  if (response.headers['set-cookie']) {
    setCookieForHost(host, response.headers['set-cookie']);
  }

  // 检测瑞数 WAF:返回 54 字节的 <script src="/_guard/html.js">
  const bodyStr = response.body.toString('utf8');
  const isRuiShuWaf = bodyStr.includes('/_guard/') && bodyStr.includes('html.js');

  if (isRuiShuWaf && response.status === 200) {
    // 瑞数 WAF:先请求 html.js,获取 cookie,然后重试
    const guardMatch = bodyStr.match(/src="([^"]*\/_guard\/[^"]+)"/);
    if (guardMatch) {
      const guardUrl = new URL(guardMatch[1], target.origin);
      const guardHeaders = { ...BROWSER_HEADERS };
      guardHeaders['Referer'] = target.href;
      guardHeaders['Sec-Fetch-Site'] = 'same-origin';
      const savedCookie = getCookieForHost(host);
      if (savedCookie) guardHeaders['Cookie'] = savedCookie;

      // 请求 guard JS
      const guardResp = await doRequest(guardUrl, 'GET', guardHeaders);
      if (guardResp.headers['set-cookie']) {
        setCookieForHost(host, guardResp.headers['set-cookie']);
      }

      // 重试原请求
      const retryHeaders = { ...forwardHeaders };
      const newCookie = getCookieForHost(host);
      if (newCookie) retryHeaders['Cookie'] = newCookie;
      response = await doRequest(target, req.method, retryHeaders);
      if (response.headers['set-cookie']) {
        setCookieForHost(host, response.headers['set-cookie']);
      }
    }
  }

  // 检测 503/502:重试一次
  if (response.status >= 500 && response.status < 600) {
    const retryHeaders = { ...forwardHeaders };
    const newCookie = getCookieForHost(host);
    if (newCookie) retryHeaders['Cookie'] = newCookie;
    await new Promise(r => setTimeout(r, 1000));
    response = await doRequest(target, req.method, retryHeaders);
    if (response.headers['set-cookie']) {
      setCookieForHost(host, response.headers['set-cookie']);
    }
  }

  return response;
}


async function handler(req, res) {
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
      service: 'pigma-node-proxy-v2',
      allowed_hosts: ALLOWED_HOSTS,
      cookie_pool_hosts: Array.from(cookiePool.keys()),
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

  if (!ALLOWED_HOSTS.includes(target.hostname)) {
    return sendJson(res, 403, {
      error: '域名不在白名单',
      host: target.hostname,
      allowed: ALLOWED_HOSTS,
    });
  }

  try {
    const response = await fetchThroughProxy(target, req);

    const respHeaders = { ...response.headers };
    respHeaders['Access-Control-Allow-Origin'] = '*';
    respHeaders['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    respHeaders['Access-Control-Allow-Headers'] = 'X-Proxy-Token, Content-Type';
    respHeaders['X-Proxied-By'] = 'pigma-node-v2';

    res.writeHead(response.status, response.statusText, respHeaders);
    res.end(response.body);
  } catch (e) {
    sendJson(res, 502, { error: '上游请求失败', detail: String(e) });
  }
}


const server = http.createServer(handler);
server.listen(PORT, () => {
  console.log(`pigma-proxy v2 listening on port ${PORT}`);
});
