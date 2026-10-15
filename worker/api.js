const MAX_BODY = 65536;
const SESS_TTL = 604800;
const PBKDF2_IT = 100000;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Expose-Headers": "Location",
};

function json(body, status, extra) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: Object.assign({
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    }, CORS, extra || {}),
  });
}

function raw(headers) {
  return new Response(null, {
    status: 200,
    headers: Object.assign({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }, CORS, headers || {}),
  });
}

function genId() {
  return crypto.randomUUID().replace(/-/g, "");
}

function toHex(buf) {
  const v = new Uint8Array(buf);
  let h = "";
  for (let i = 0; i < v.length; i++) h += v[i].toString(16).padStart(2, "0");
  return h;
}

function fromHex(s) {
  const b = new Uint8Array(s.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(s.substr(i * 2, 2), 16);
  return b;
}

async function pbkdf2(pin, saltHex, it) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: fromHex(saltHex), iterations: it, hash: "SHA-256" },
    key,
    256
  );
  return toHex(bits);
}

function ctEq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

async function readBody(request) {
  const text = await request.text();
  if (text.length > MAX_BODY) return { error: 413 };
  let body;
  try {
    body = JSON.parse(text);
  } catch (e) {
    return { error: 400 };
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return { error: 400 };
  return { body };
}

async function rateLimit(env, bucket, ip, limit) {
  const k = "rl:" + bucket + ":" + (ip || "x");
  const n = parseInt((await env.BT_STORE.get(k)) || "0", 10) + 1;
  await env.BT_STORE.put(k, String(n), { expirationTtl: 60 });
  return n <= limit;
}

async function getAuth(env) {
  const v = await env.BT_STORE.get("auth");
  if (!v) return null;
  try {
    return JSON.parse(v);
  } catch (e) {
    return null;
  }
}

async function makeSession(env) {
  const tok = genId() + genId();
  await env.BT_STORE.put("sess:" + tok, String(Date.now()), { expirationTtl: SESS_TTL });
  return tok;
}

function bearer(request) {
  const h = request.headers.get("Authorization") || "";
  const m = h.match(/^Bearer ([A-Za-z0-9]+)$/);
  return m ? m[1] : "";
}

async function isAuthed(env, request) {
  const t = bearer(request);
  if (!t) return false;
  return (await env.BT_STORE.get("sess:" + t)) !== null;
}

const ACCESS_COOKIE = "CF_Authorization";
let JWKS_CACHE = { team: "", keys: null, exp: 0 };

function b64urlDecode(s) {
  const p = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = p.length % 4 === 0 ? "" : "=".repeat(4 - (p.length % 4));
  const bin = atob(p + pad);
  const b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  return b;
}

function b64urlStr(s) {
  return new TextDecoder().decode(b64urlDecode(s));
}

function normTeam(v) {
  const s = String(v || "").trim().replace(/\/+$/, "").toLowerCase();
  return /^https:\/\/[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(s) ? s : "";
}

function accessTokens(request) {
  const out = [];
  const h = request.headers.get("Cf-Access-Jwt-Assertion");
  if (h) out.push(h.trim());
  const c = request.headers.get("Cookie") || "";
  const m = c.match(/(?:^|;\s*)CF_Authorization=([^;]+)/);
  if (m) {
    let v = m[1];
    try {
      v = decodeURIComponent(v);
    } catch (e) {}
    out.push(v);
  }
  return out;
}

async function accessKeys(team) {
  const now = Date.now();
  if (JWKS_CACHE.keys && JWKS_CACHE.team === team && JWKS_CACHE.exp > now) return JWKS_CACHE.keys;
  const res = await fetch(team + "/cdn-cgi/access/certs", { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error("jwks " + res.status);
  const doc = await res.json();
  const keys = doc && Array.isArray(doc.keys) ? doc.keys : [];
  if (!keys.length) throw new Error("jwks empty");
  JWKS_CACHE = { team: team, keys: keys, exp: now + 300000 };
  return keys;
}

async function verifyAccessToken(token, team, aud) {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  let header, payload;
  try {
    header = JSON.parse(b64urlStr(parts[0]));
    payload = JSON.parse(b64urlStr(parts[1]));
  } catch (e) {
    return false;
  }
  if (!header || header.alg !== "RS256" || !header.kid) return false;
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp < now - 30) return false;
  if (typeof payload.nbf === "number" && payload.nbf > now + 30) return false;
  if (!payload.iss || String(payload.iss).toLowerCase().replace(/\/+$/, "") !== team) return false;
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (auds.indexOf(aud) === -1) return false;
  const keys = await accessKeys(team);
  let jwk = null;
  for (let i = 0; i < keys.length; i++) {
    if (keys[i] && keys[i].kid === header.kid && keys[i].kty === "RSA") {
      jwk = keys[i];
      break;
    }
  }
  if (!jwk || !jwk.n || !jwk.e) return false;
  const clean = { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RSASSA-PKCS1-v1_5" };
  const key = await crypto.subtle.importKey("jwk", clean, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const data = new TextEncoder().encode(parts[0] + "." + parts[1]);
  return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64urlDecode(parts[2]), data);
}

async function verifyAccess(request, env) {
  const team = normTeam(env.ACCESS_TEAM_DOMAIN);
  const aud = String(env.ACCESS_APPLICATION_AUD || "").trim();
  if (!team || !aud) return false;
  const tokens = accessTokens(request);
  if (!tokens.length) return false;
  for (let i = 0; i < tokens.length; i++) {
    try {
      if (await verifyAccessToken(tokens[i], team, aud)) return true;
    } catch (e) {}
  }
  return false;
}

function adminApi(key, method) {
  if (method === "PUT") return true;
  if (method === "POST") return key === "setup" || key === "login" || key === "logout" || key === "";
  if (method === "GET" || method === "HEAD") return key === "data" || key === "revcode" || key === "auth-state";
  return false;
}

function isAdminPage(url) {
  const bare = url.pathname.replace(/\/+$/, "") || "/";
  if (bare === "/admin" || bare === "/admin.html") return true;
  return url.searchParams.has("admin");
}

function accessDenied(url) {
  const bare = url.pathname.replace(/\/+$/, "") || "/";
  const headers = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" };
  if (bare === "/admin" || bare === "/admin.html") {
    return new Response(JSON.stringify({ error: "forbidden" }), { status: 403, headers: headers });
  }
  headers.Location = "/admin";
  return new Response(null, { status: 302, headers: headers });
}

function cleanStr(s, max) {
  return typeof s === "string" ? s.trim().slice(0, max) : "";
}

function sanitizeReviews(list) {
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const r of list.slice(-200)) {
    if (!r || typeof r !== "object") continue;
    const text = cleanStr(r.text, 2000);
    if (!text) continue;
    out.push({
      id: cleanStr(r.id, 40) || genId().slice(0, 12),
      name: cleanStr(r.name, 100),
      stars: Math.max(1, Math.min(5, Math.round(Number(r.stars) || 5))),
      text: text,
      date: cleanStr(r.date, 40) || new Date().toISOString(),
      approved: r.approved === true,
    });
  }
  return out;
}

async function getData(env) {
  const v = await env.BT_STORE.get("data");
  if (!v) return { reviews: [] };
  try {
    const o = JSON.parse(v);
    return { reviews: sanitizeReviews(o.reviews) };
  } catch (e) {
    return { reviews: [] };
  }
}

async function handleApi(request, env, path) {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

  const key = path.slice("/api".length).replace(/^\/+/, "");
  const ip = request.headers.get("cf-connecting-ip") || "";
  const method = request.method;

  if (method === "GET" || method === "HEAD") {
    if (key === "avail") {
      const v = await env.BT_STORE.get("avail");
      if (v === null) return json({ error: "not found" }, 404);
      if (method === "HEAD") return raw();
      return new Response(v, {
        status: 200,
        headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...CORS },
      });
    }
    if (key === "reviews") {
      const d = await getData(env);
      return json({ reviews: d.reviews.filter((r) => r.approved) });
    }
    if (key === "auth-state") {
      return json({ setup: !!(await getAuth(env)) });
    }
    if (key === "revcode") {
      if (!(await isAuthed(env, request))) return json({ error: "unauthorized" }, 401);
      return json({ code: (await env.BT_STORE.get("revcode")) || null });
    }
    if (key === "data") {
      if (!(await isAuthed(env, request))) return json({ error: "unauthorized" }, 401);
      return json(await getData(env));
    }
    return json({ error: "not found" }, 404);
  }

  if (method === "POST") {
    if (key === "setup") {
      if (!(await rateLimit(env, "setup", ip, 5))) return json({ error: "rate limited" }, 429);
      const rb = await readBody(request);
      if (rb.error) return json({ error: "bad body" }, rb.error);
      const pin = typeof rb.body.pin === "string" ? rb.body.pin : "";
      if (pin.length < 8 || pin.length > 1024) return json({ error: "bad pin" }, 400);
      if (await getAuth(env)) return json({ error: "already set up" }, 409);
      const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
      const hash = await pbkdf2(pin, salt, PBKDF2_IT);
      await env.BT_STORE.put("auth", JSON.stringify({ v: 1, it: PBKDF2_IT, salt: salt, hash: hash }));
      const token = await makeSession(env);
      return json({ token: token });
    }

    if (key === "login") {
      if (!(await rateLimit(env, "login", ip, 10))) return json({ error: "rate limited" }, 429);
      const rb = await readBody(request);
      if (rb.error) return json({ error: "bad body" }, rb.error);
      const pin = typeof rb.body.pin === "string" ? rb.body.pin : "";
      const auth = await getAuth(env);
      if (!auth) return json({ error: "not set up" }, 404);
      const hash = await pbkdf2(pin, auth.salt, auth.it || PBKDF2_IT);
      if (!ctEq(hash, auth.hash)) return json({ error: "invalid pin" }, 401);
      const token = await makeSession(env);
      return json({ token: token });
    }

    if (key === "logout") {
      const t = bearer(request);
      if (t) await env.BT_STORE.delete("sess:" + t);
      return json({ ok: true });
    }

    if (key === "review") {
      if (!(await rateLimit(env, "review", ip, 5))) return json({ error: "rate limited" }, 429);
      const rb = await readBody(request);
      if (rb.error) return json({ error: "bad body" }, rb.error);
      const code = cleanStr(rb.body.code, 100);
      const real = await env.BT_STORE.get("revcode");
      if (!real || !code || !ctEq(real, code)) return json({ error: "bad code" }, 403);
      const name = cleanStr(rb.body.name, 100);
      const text = cleanStr(rb.body.text, 2000);
      const stars = Math.round(Number(rb.body.stars));
      if (!name || !text || !(stars >= 1 && stars <= 5)) return json({ error: "invalid review" }, 400);
      const d = await getData(env);
      d.reviews.push({
        id: genId().slice(0, 12),
        name: name,
        stars: stars,
        text: text,
        date: new Date().toISOString(),
        approved: false,
      });
      await env.BT_STORE.put("data", JSON.stringify({ reviews: sanitizeReviews(d.reviews) }));
      return json({ ok: true }, 201);
    }

    return json({ error: "not found" }, 404);
  }

  if (method === "PUT") {
    if (!(await isAuthed(env, request))) return json({ error: "unauthorized" }, 401);
    const rb = await readBody(request);
    if (rb.error) return json({ error: "bad body" }, rb.error);
    if (key === "avail") {
      if (typeof rb.body.available !== "boolean") return json({ error: "invalid" }, 400);
      await env.BT_STORE.put("avail", JSON.stringify({ available: rb.body.available, updatedAt: new Date().toISOString() }));
      return json({ ok: true });
    }
    if (key === "data") {
      await env.BT_STORE.put("data", JSON.stringify({ reviews: sanitizeReviews(rb.body.reviews) }));
      return json({ ok: true });
    }
    if (key === "revcode") {
      const c = cleanStr(rb.body.code, 100);
      if (c.length < 4) return json({ error: "invalid code" }, 400);
      await env.BT_STORE.put("revcode", c);
      return json({ ok: true });
    }
    return json({ error: "not found" }, 404);
  }

  return json({ error: "method not allowed" }, 405);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      const isApi = url.pathname === "/api" || url.pathname.startsWith("/api/");
      if (isApi) {
        if (request.method !== "OPTIONS") {
          const key = url.pathname.slice("/api".length).replace(/^\/+/, "");
          if (adminApi(key, request.method) && !(await verifyAccess(request, env))) {
            return json({ error: "forbidden" }, 403);
          }
        }
        return await handleApi(request, env, url.pathname);
      }
      if (request.method !== "OPTIONS" && isAdminPage(url) && !(await verifyAccess(request, env))) {
        return accessDenied(url);
      }
      const bare = url.pathname.replace(/\/+$/, "") || "/";
      if (bare === "/admin" || bare === "/admin.html") {
        return env.ASSETS.fetch(new Request(new URL("/", url.origin), { headers: request.headers }));
      }
    } catch (e) {
      return json({ error: "server error", detail: String((e && e.message) || e) }, 500);
    }
    return env.ASSETS.fetch(request);
  },
};
