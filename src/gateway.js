import baseWorker from "./index.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cookies = parseCookies(request.headers.get("Cookie") || "");
    const session = await readToken(cookies.math_session, env.SESSION_SECRET, "session");

    if (request.method === "GET" && url.pathname === "/" && session) {
      if (!env.SCRAMJET_ORIGIN || !env.SCRAMJET_SHARED_SECRET) {
        return new Response("Scramjet is not configured", { status: 503 });
      }
      const destination = new URL("/auth", env.SCRAMJET_ORIGIN);
      if (destination.protocol !== "https:") {
        return new Response("SCRAMJET_ORIGIN must use HTTPS", { status: 500 });
      }
      const token = await makeToken({
        kind: "handoff",
        exp: now() + 60,
        nonce: crypto.randomUUID()
      }, env.SCRAMJET_SHARED_SECRET);
      destination.searchParams.set("token", token);
      return new Response(null, {
        status: 303,
        headers: {
          Location: destination.toString(),
          "Cache-Control": "no-store, private",
          "Referrer-Policy": "no-referrer"
        }
      });
    }

    // Cloudflare can expose the public custom-domain origin differently from
    // request.url during a form POST. Normalize it before the base Worker runs
    // its same-origin check.
    if (request.method === "POST" && url.pathname === "/") {
      const headers = new Headers(request.headers);
      headers.set("Origin", url.origin);
      request = new Request(request, { headers });
    }

    return baseWorker.fetch(request, env, ctx);
  }
};

function now() { return Math.floor(Date.now() / 1000); }

async function makeToken(payload, secret) {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  return `${body}.${await sign(body, secret)}`;
}

async function readToken(token, secret, kind) {
  if (!token || !secret) return null;
  const [body, signature, extra] = token.split(".");
  if (!body || !signature || extra) return null;
  const expected = await sign(body, secret);
  if (!safeEqual(signature, expected)) return null;
  try {
    const payload = JSON.parse(dec.decode(unb64url(body)));
    return payload.kind === kind && Number.isFinite(payload.exp) && payload.exp >= now() ? payload : null;
  } catch {
    return null;
  }
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(value))));
}

function safeEqual(a, b) {
  const aa = enc.encode(String(a));
  const bb = enc.encode(String(b));
  let diff = aa.length ^ bb.length;
  const length = Math.max(aa.length, bb.length);
  for (let i = 0; i < length; i++) diff |= (aa[i] || 0) ^ (bb[i] || 0);
  return diff === 0;
}

function parseCookies(header) {
  const out = {};
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function b64url(bytes) {
  let s = "";
  for (const byte of bytes) s += String.fromCharCode(byte);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function unb64url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(normalized), c => c.charCodeAt(0));
}
