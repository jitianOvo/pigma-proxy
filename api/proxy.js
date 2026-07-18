/**
 * 小猪码收集 - Vercel Serverless 反代
 * =====================================================
 *
 * 用途:
 *   服务器(阿里云)被 52pojie 和 MT 论坛按 IP 段封锁,
 *   通过 Vercel Serverless Function 反代绕过(Vercel 的 IP 段不被封锁,
 *   且国内访问有边缘节点,比 workers.dev 稳定)。
 *
 * 调用方式:
 *   GET https://你的项目.vercel.app/api/proxy?url=<目标URL>
 *   Header: X-Proxy-Token: <你的-token>
 *
 * 部署方式:
 *   1. 注册 Vercel 账号:https://vercel.com(可用 GitHub 登录)
 *   2. New Project → Import 一个空的 GitHub 仓库(或用 Vercel CLI)
 *   3. 上传本文件到 api/proxy.js
 *   4. 部署完成后拿到 URL
 *
 * 免费额度:
 *   - 100GB/月流量(本项目每月最多几 GB,够用)
 *   - Serverless Function 调用次数不限(Go 计划)
 */

// ==================== 配置区 ====================
// 鉴权 token,必须与服务器 PIGMA_PROXY_TOKEN 一致
const PROXY_TOKEN = process.env.PROXY_PROXY_TOKEN || "pigma-proxy-2026";

// 允许反代的目标域名白名单(只允许这两个站点,防止被滥用做开放代理)
const ALLOWED_HOSTS = [
  "www.52pojie.cn",
  "bbs.binmt.cc",
];

// 模拟真实 Chrome 浏览器
const BROWSER_HEADERS = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
  "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
  "Accept-Encoding": "gzip, deflate, br",
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


export default async function handler(req, res) {
  // 处理 CORS 预检
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "X-Proxy-Token, Content-Type");
    return res.status(204).end();
  }

  const url = new URL(req.url, `http://${req.headers.host}`);

  // 健康检查
  if (url.pathname === "/api/health" || url.pathname === "/health") {
    return res.status(200).json({
      status: "ok",
      service: "pigma-vercel-proxy",
      allowed_hosts: ALLOWED_HOSTS,
    });
  }

  // 鉴权
  const token = req.headers["x-proxy-token"] || url.searchParams.get("token");
  if (token !== PROXY_TOKEN) {
    return res.status(403).json({ error: "token 无效" });
  }

  // 提取目标 URL
  let targetUrl = url.searchParams.get("url");
  if (!targetUrl) {
    // 兼容路径式:/api/proxy/<URL>
    const m = url.pathname.match(/^\/api\/proxy\/(.+)$/);
    if (m) {
      try {
        targetUrl = decodeURIComponent(m[1]);
      } catch (e) {
        targetUrl = m[1];
      }
    }
  }

  if (!targetUrl) {
    return res.status(400).json({
      error: "缺少目标 URL",
      usage: "GET /api/proxy?url=<目标URL>",
    });
  }

  let target;
  try {
    target = new URL(targetUrl);
  } catch (e) {
    return res.status(400).json({ error: "目标 URL 无效" });
  }

  // 域名白名单检查
  const targetHost = target.hostname;
  if (!ALLOWED_HOSTS.includes(targetHost)) {
    return res.status(403).json({
      error: "域名不在白名单",
      host: targetHost,
      allowed: ALLOWED_HOSTS,
    });
  }

  // 构造转发 headers
  const forwardHeaders = new Headers(BROWSER_HEADERS);
  forwardHeaders.set("Referer", target.origin + "/");
  forwardHeaders.set("Sec-Fetch-Site", "same-origin");
  // 转发客户端的 Cookie(如果有)
  const clientCookie = req.headers["cookie"];
  if (clientCookie) {
    forwardHeaders.set("Cookie", clientCookie);
  }

  try {
    const response = await fetch(targetUrl, {
      method: req.method,
      headers: forwardHeaders,
      redirect: "follow",
      // Vercel Node.js runtime 支持
      ...(req.method !== "GET" && req.method !== "HEAD" && {
        body: req.body,
      }),
    });

    // 透传响应
    const respHeaders = new Headers(response.headers);
    respHeaders.set("Access-Control-Allow-Origin", "*");
    respHeaders.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    respHeaders.set("Access-Control-Allow-Headers", "X-Proxy-Token, Content-Type");
    respHeaders.set("X-Proxied-By", "pigma-vercel");

    // 把 Headers 转成 plain object(Next.js/Vercel 要求)
    const headersObj = {};
    respHeaders.forEach((v, k) => { headersObj[k] = v; });

    const body = await response.arrayBuffer();
    res.status(response.status);
    for (const [k, v] of Object.entries(headersObj)) {
      res.setHeader(k, v);
    }
    return res.end(Buffer.from(body));
  } catch (e) {
    return res.status(502).json({
      error: "上游请求失败",
      detail: String(e),
    });
  }
}
