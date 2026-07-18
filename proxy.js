/**
 * 小猪码收集 - Deno Deploy 反代
 * =====================================================
 *
 * 用途:
 *   服务器(阿里云)被 52pojie 和 MT 论坛按 IP 段封锁,
 *   通过 Deno Deploy 反代绕过(Deno Deploy 的 IP 不被封锁,
 *   且 deno.dev 在国内可正常访问)。
 *
 * 调用方式:
 *   GET https://你的项目.deno.dev/proxy?url=<目标URL>
 *   Header: X-Proxy-Token: <你的-token>
 *
 * 部署方式:
 *   1. 打开 https://dash.deno.com → Sign Up(用 GitHub 登录)
 *   2. New Project → 从 GitHub 仓库 jitianOvo/pigma-proxy 导入
 *   3. Entrypoint 选择 proxy.js
 *   4. 点击 Link → 等待部署完成
 *   5. 拿到 URL:https://pigma-proxy.deno.dev(或类似)
 */

// ==================== 配置区 ====================
const PROXY_TOKEN = "pigma-proxy-2026";

const ALLOWED_HOSTS = [
  "www.52pojie.cn",
  "bbs.binmt.cc",
];

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


import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);

  // CORS 预检
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "X-Proxy-Token, Content-Type",
      },
    });
  }

  // 健康检查
  if (url.pathname === "/" || url.pathname === "/health") {
    return new Response(JSON.stringify({
      status: "ok",
      service: "pigma-deno-proxy",
      allowed_hosts: ALLOWED_HOSTS,
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 鉴权
  const token = req.headers.get("X-Proxy-Token") || url.searchParams.get("token");
  if (token !== PROXY_TOKEN) {
    return new Response(JSON.stringify({ error: "token 无效" }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 提取目标 URL
  let targetUrl = url.searchParams.get("url");
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
    return new Response(JSON.stringify({
      error: "缺少目标 URL",
      usage: "GET /proxy?url=<目标URL>",
    }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  let target: URL;
  try {
    target = new URL(targetUrl);
  } catch (e) {
    return new Response(JSON.stringify({ error: "目标 URL 无效" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 域名白名单
  const targetHost = target.hostname;
  if (!ALLOWED_HOSTS.includes(targetHost)) {
    return new Response(JSON.stringify({
      error: "域名不在白名单",
      host: targetHost,
      allowed: ALLOWED_HOSTS,
    }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 构造转发 headers
  const forwardHeaders = new Headers(BROWSER_HEADERS);
  forwardHeaders.set("Referer", target.origin + "/");
  forwardHeaders.set("Sec-Fetch-Site", "same-origin");
  const clientCookie = req.headers.get("Cookie");
  if (clientCookie) {
    forwardHeaders.set("Cookie", clientCookie);
  }

  try {
    const response = await fetch(targetUrl, {
      method: req.method,
      headers: forwardHeaders,
      redirect: "follow",
    });

    const respHeaders = new Headers(response.headers);
    respHeaders.set("Access-Control-Allow-Origin", "*");
    respHeaders.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    respHeaders.set("Access-Control-Allow-Headers", "X-Proxy-Token, Content-Type");
    respHeaders.set("X-Proxied-By", "pigma-deno");

    const body = await response.arrayBuffer();
    return new Response(body, {
      status: response.status,
      statusText: response.statusText,
      headers: respHeaders,
    });
  } catch (e) {
    return new Response(JSON.stringify({
      error: "上游请求失败",
      detail: String(e),
    }), {
      status: 502,
      headers: { "Content-Type": "application/json" },
    });
  }
}

serve(handler, { port: 8000 });
