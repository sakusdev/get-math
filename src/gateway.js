import baseWorker from "./index.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cookies = parseCookies(request.headers.get("Cookie") || "");
    const session = await verifyToken(
      cookies.math_session,
      env.SESSION_SECRET,
      "session"
    );

    // Once authenticated, hand the browser to the separate Scramjet server.
    // The short-lived token prevents direct unauthenticated access.
    if (request.method === "GET" && url.pathname === "/" && session) {
      if (!env.SCRAMJET_ORIGIN || !env.SCRAMJET_SHARED_SECRET) {
        return new Response("Scramjet is not configured", { status: 503 });
      }

      const origin = new URL(env.SCRAMJET_ORIGIN);
      if (origin.protocol !== "https:") {
        return new Response("SCRAMJET_ORIGIN must use HTTPS", { status: 500 });
      }

      const handoff = await createToken(
        {
          kind: "handoff",
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce: crypto.randomUUID()
        },
        env.SCRAMJET_SHARED_SECRET
      );

      origin.pathname = "/auth";
      origin.search = `?token=${encodeURIComponent(handoff)}`;

      return new Response(null, {
        status: 303,
        headers: {
          Location: origin.toString(),
          "Cache-Control": "no-store, private",
          "Referrer-Policy": "no-referrer"
        }
      });
    }

    return baseWorker.fetch(request, env, ctx);
  }
};

async function createToken(payload, secret) {
  const body = base64url(encoder.encode(JSON.stringify(payload)));
  return `${body}.${await sign(body, secret)}`;
}

async function verifyToken(token, secret, requiredKind) {
  if (!token || !secret) return null;
  const [body, signature, extra] = token.split(".");
  if (!body || !signature || extra) return null;

  const expected = await sign(body, secret);
  if (!safeEqual(signature, expected)) return null;

  try {
    const payload = JSON.parse(decoder.decode(fromBase64url(body)));
    if (payload.kind !== requiredKind) return null;
    if (!Number.isFinite(payload.exp)) return null;
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return base64url(new Uint8Array(signature));
}

function safeEqual(a, b) {
  const left = encoder.encode(String(a));
  const right = encoder.encode(String(b));
  let diff = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i++) diff |= (left[i] || 0) ^ (right[i] || 0);
  return diff === 0;
}

function parseCookies(header) {
  const result = {};
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    result[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
  }
  return result;
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function fromBase64url(value) {
  const normalized = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(normalized), char => char.charCodeAt(0));
}
