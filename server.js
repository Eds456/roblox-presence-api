const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "64kb" }));

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: function (origin, cb) {
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.length === 0) return cb(null, true);
      return cb(null, ALLOWED_ORIGINS.includes(origin));
    },
    credentials: false,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "x-roblox-key", "x-radio-token"],
    maxAge: 86400,
  })
);

const presence = {};
const sessions = {};
const sessionsByUser = {};
const radioQueue = {};
const radioState = {};
const tokenRevokedAt = {};

const SESSION_TTL_MS = 2 * 60 * 1000;
const RADIO_TTL_MS = 5 * 60 * 1000;

const STATE_TTL_MS = 25 * 1000;
const STATE_MIN_GAP_MS = 700;

const ROBLOX_SERVER_KEY = process.env.ROBLOX_SERVER_KEY || "";
const WEB_TOKEN_SECRET = process.env.WEB_TOKEN_SECRET || "";
const WEB_TOKEN_TTL_MS = 10 * 60 * 1000;

const LIMITS = {
  verify: { windowMs: 15_000, max: 12 },
  sseOpenIp: { windowMs: 60_000, max: 60 },
  sseOpenUser: { windowMs: 60_000, max: 60 },
  joinIp: { windowMs: 10_000, max: 25 },
  muteIp: { windowMs: 10_000, max: 25 },
  syncIp: { windowMs: 10_000, max: 40 },
  stateIp: { windowMs: 10_000, max: 80 },
  activeIp: { windowMs: 10_000, max: 40 },
  pollIp: { windowMs: 10_000, max: 80 },
  presenceIp: { windowMs: 10_000, max: 200 },
};

const sseClients = new Map();
const sseIpCount = new Map();

const MAX_SSE_PER_USER = Number(process.env.MAX_SSE_PER_USER || 3);
const MAX_SSE_PER_IP = Number(process.env.MAX_SSE_PER_IP || 10);

const hits = new Map();

function nowMs() {
  return Date.now();
}

function getIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf) return String(xf).split(",")[0].trim();
  return req.socket && req.socket.remoteAddress ? String(req.socket.remoteAddress) : "";
}

function rlKey(scope, a, b) {
  return `${scope}:${a}:${b || ""}`;
}

function rateLimit(scope, req, res, keyA, keyB) {
  const cfg = LIMITS[scope];
  if (!cfg) return false;

  const ip = getIp(req);
  const k = rlKey(scope, keyA || ip, keyB || "");
  const t = nowMs();
  let e = hits.get(k);

  if (!e || e.resetAt <= t) {
    e = { count: 0, resetAt: t + cfg.windowMs };
    hits.set(k, e);
  }

  e.count++;
  if (e.count > cfg.max) {
    res.status(429).json({ ok: false, error: "rate_limited" });
    return true;
  }
  return false;
}

function b64urlEncode(bufOrString) {
  const b = Buffer.isBuffer(bufOrString) ? bufOrString : Buffer.from(String(bufOrString));
  return b.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function b64urlDecodeToString(str) {
  const s = String(str).replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  return Buffer.from(s + pad, "base64").toString("utf8");
}

function makeWebToken(usernameLower) {
  if (!WEB_TOKEN_SECRET) return null;
  const t = nowMs();
  const payloadObj = { u: usernameLower, iat: t, exp: t + WEB_TOKEN_TTL_MS };
  const payload = b64urlEncode(JSON.stringify(payloadObj));
  const sig = crypto.createHmac("sha256", WEB_TOKEN_SECRET).update(payload).digest();
  return `${payload}.${b64urlEncode(sig)}`;
}

function verifyWebToken(token) {
  if (!WEB_TOKEN_SECRET) return { ok: false, error: "token_disabled" };
  if (!token || typeof token !== "string") return { ok: false, error: "missing_token" };

  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, error: "bad_token_format" };

  const [payload, sigB64] = parts;
  const expectedSig = crypto.createHmac("sha256", WEB_TOKEN_SECRET).update(payload).digest();

  const b64 = String(sigB64).replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (b64.length % 4)) % 4;
  const gotSig = Buffer.from(b64 + "=".repeat(padLen), "base64");

  if (gotSig.length !== expectedSig.length) return { ok: false, error: "bad_signature" };
  if (!crypto.timingSafeEqual(gotSig, expectedSig)) return { ok: false, error: "bad_signature" };

  let payloadObj;
  try {
    payloadObj = JSON.parse(b64urlDecodeToString(payload));
  } catch {
    return { ok: false, error: "bad_payload" };
  }

  const t = nowMs();
  if (!payloadObj || !payloadObj.u || !payloadObj.exp) return { ok: false, error: "bad_payload" };
  if (payloadObj.exp <= t) return { ok: false, error: "token_expired" };

  const uname = String(payloadObj.u).toLowerCase();
  const revokedAt = tokenRevokedAt[uname] || 0;
  if (payloadObj.iat && payloadObj.iat < revokedAt) return { ok: false, error: "token_revoked" };

  return { ok: true, username: uname, exp: payloadObj.exp };
}

function requireTokenForUser(req, res, usernameLower) {
  if (!WEB_TOKEN_SECRET) return { ok: true, username: usernameLower };

  const headerToken = req.headers["x-radio-token"];
  const qToken = req.query && typeof req.query.token === "string" ? req.query.token : null;
  const bodyToken = req.body && typeof req.body.token === "string" ? req.body.token : null;

  const t =
    typeof headerToken === "string" && headerToken
      ? headerToken
      : qToken
      ? qToken
      : bodyToken
      ? bodyToken
      : null;

  const v = verifyWebToken(t);
  if (!v.ok) {
    res.status(401).json({ ok: false, error: v.error });
    return null;
  }
  if (v.username !== usernameLower) {
    res.status(403).json({ ok: false, error: "token_user_mismatch" });
    return null;
  }
  return v;
}

function genCode(len = 7) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

function sseSendToUser(username, eventName, dataObj) {
  const key = String(username).toLowerCase();
  const set = sseClients.get(key);
  if (!set || set.size === 0) return false;

  const payload = `event: ${eventName}\n` + `data: ${JSON.stringify(dataObj)}\n\n`;
  for (const res of set) {
    try {
      res.write(payload);
    } catch {}
  }
  return true;
}

function sseAddClient(username, res, ip) {
  const key = String(username).toLowerCase();

  const ipCount = sseIpCount.get(ip) || 0;
  if (ipCount >= MAX_SSE_PER_IP) {
    try {
      res.status(429).end();
    } catch {}
    return false;
  }

  const set = sseClients.get(key) || new Set();
  if (set.size >= MAX_SSE_PER_USER) {
    try {
      res.status(429).end();
    } catch {}
    return false;
  }

  set.add(res);
  sseClients.set(key, set);
  sseIpCount.set(ip, ipCount + 1);

  res.on("close", () => {
    const cur = sseClients.get(key);
    if (cur) {
      cur.delete(res);
      if (cur.size === 0) sseClients.delete(key);
    }
    const n = (sseIpCount.get(ip) || 1) - 1;
    if (n <= 0) sseIpCount.delete(ip);
    else sseIpCount.set(ip, n);
  });

  return true;
}

function cleanupSessions() {
  const t = nowMs();
  for (const code of Object.keys(sessions)) {
    const s = sessions[code];
    if (!s || s.exp <= t) {
      const u = s?.username;
      delete sessions[code];
      if (u && sessionsByUser[u] === code) delete sessionsByUser[u];
    }
  }
}

function cleanupRadioQueue() {
  const t = nowMs();
  for (const key of Object.keys(radioQueue)) {
    radioQueue[key] = (radioQueue[key] || []).filter((ev) => t - (ev.ts || t) < RADIO_TTL_MS);
    if (radioQueue[key].length === 0) delete radioQueue[key];
  }
}

function cleanupRadioState() {
  const t = nowMs();
  for (const key of Object.keys(radioState)) {
    if (t - (radioState[key].updatedAt || 0) > STATE_TTL_MS) delete radioState[key];
  }
}

function cleanupTokenRevocations() {
  const t = nowMs();
  const ttl = Math.max(WEB_TOKEN_TTL_MS, 10 * 60 * 1000);
  for (const key of Object.keys(tokenRevokedAt)) {
    if (t - (tokenRevokedAt[key] || 0) > ttl) delete tokenRevokedAt[key];
  }
}

function cleanupRateLimits() {
  const t = nowMs();
  let n = 0;
  for (const [k, v] of hits.entries()) {
    if (v.resetAt <= t) {
      hits.delete(k);
      n++;
      if (n > 5000) break;
    }
  }
}

setInterval(cleanupSessions, 30 * 1000);
setInterval(cleanupRadioQueue, 60 * 1000);
setInterval(cleanupRadioState, 5 * 1000);
setInterval(cleanupTokenRevocations, 60 * 1000);
setInterval(cleanupRateLimits, 60 * 1000);

app.get("/", (req, res) => {
  res.send("Roblox Presence API v6-ultra");
});

app.post("/presence", (req, res) => {
  if (rateLimit("presenceIp", req, res)) return;

  const { username, inGame, havePass } = req.body;

  if (!username || typeof inGame !== "boolean") {
    return res.status(400).json({ ok: false, error: "username(string) e inGame(boolean) obrigatórios" });
  }

  const key = String(username).toLowerCase();
  presence[key] = { inGame, havePass: !!havePass, updatedAt: nowMs() };
  res.json({ ok: true });
});

app.get("/presence/:username", (req, res) => {
  if (rateLimit("presenceIp", req, res)) return;

  const key = (req.params.username || "").toLowerCase();
  const exists = Object.prototype.hasOwnProperty.call(presence, key);

  res.json({
    ok: true,
    exists,
    inGame: exists ? !!presence[key].inGame : false,
    havePass: exists ? !!presence[key].havePass : false,
  });
});

app.post("/session/create", (req, res) => {
  const serverKey = req.headers["x-roblox-key"];
  if (!ROBLOX_SERVER_KEY || serverKey !== ROBLOX_SERVER_KEY) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }

  const { username, havePass } = req.body || {};
  if (!username) return res.status(400).json({ ok: false, error: "username obrigatório" });

  cleanupSessions();

  const uname = String(username).toLowerCase();
  if (!presence[uname] || !presence[uname].inGame) {
    return res.status(403).json({ ok: false, error: "not_in_game" });
  }

  const prev = sessionsByUser[uname];
  if (prev && sessions[prev]) delete sessions[prev];
  delete sessionsByUser[uname];

  tokenRevokedAt[uname] = nowMs();
  delete radioState[uname];
  sseSendToUser(uname, "radio", { type: "KICK", reason: "new_code", ts: nowMs() });

  let code;
  for (let i = 0; i < 12; i++) {
    const c = genCode(7);
    if (!sessions[c]) {
      code = c;
      break;
    }
  }
  if (!code) return res.status(500).json({ ok: false, error: "code_generation_failed" });

  sessions[code] = { username: uname, havePass: !!havePass, exp: nowMs() + SESSION_TTL_MS };
  sessionsByUser[uname] = code;

  res.json({ ok: true, code, exp: sessions[code].exp });
});

app.post("/session/verify", (req, res) => {
  if (rateLimit("verify", req, res)) return;

  const { code } = req.body || {};
  if (!code) return res.status(400).json({ ok: false, error: "code obrigatório" });

  cleanupSessions();

  const key = String(code).trim().toUpperCase();
  const sess = sessions[key];
  if (!sess) return res.json({ ok: false, error: "invalid_or_expired" });

  if (!presence[sess.username] || !presence[sess.username].inGame) {
    delete sessions[key];
    if (sessionsByUser[sess.username] === key) delete sessionsByUser[sess.username];
    return res.json({ ok: false, error: "not_in_game" });
  }

  delete sessions[key];
  if (sessionsByUser[sess.username] === key) delete sessionsByUser[sess.username];

  const token = makeWebToken(sess.username);

  res.json({
    ok: true,
    username: sess.username,
    havePass: !!sess.havePass,
    token: token || null,
    tokenExp: token ? nowMs() + WEB_TOKEN_TTL_MS : null,
  });
});

app.get("/events/:username", (req, res) => {
  const username = (req.params.username || "").toLowerCase();
  if (!username) return res.status(400).end();

  if (rateLimit("sseOpenIp", req, res, getIp(req), "open")) return;
  if (rateLimit("sseOpenUser", req, res, username, "open")) return;

  const v = requireTokenForUser(req, res, username);
  if (!v) return;

  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");

  res.write(`event: hello\ndata: ${JSON.stringify({ ok: true, username })}\n\n`);

  const ip = getIp(req);
  const added = sseAddClient(username, res, ip);
  if (!added) return;

  const hb = setInterval(() => {
    try {
      res.write(`event: ping\ndata: {}\n\n`);
    } catch {}
  }, 20_000);

  res.on("close", () => clearInterval(hb));
});

app.post("/radio/join", (req, res) => {
  if (rateLimit("joinIp", req, res)) return;

  const { username } = req.body || {};
  if (!username) return res.status(400).json({ ok: false, error: "username obrigatório" });

  const key = String(username).toLowerCase();
  const v = requireTokenForUser(req, res, key);
  if (!v) return;

  if (!presence[key] || !presence[key].inGame) {
    return res.status(403).json({ ok: false, error: "not_in_game" });
  }

  if (!radioQueue[key]) radioQueue[key] = [];

  const t = nowMs();
  const last = radioQueue[key].length ? radioQueue[key][radioQueue[key].length - 1] : null;
  if (last && last.type === "RADIO_JOIN" && t - (last.ts || 0) < 10_000) {
    return res.json({ ok: true, ignored: true });
  }

  radioQueue[key].push({ type: "RADIO_JOIN", target: "roblox", ts: t });
  res.json({ ok: true });
});

app.post("/radio/mute", (req, res) => {
  if (rateLimit("muteIp", req, res)) return;

  const { username, muted } = req.body || {};
  if (!username || typeof muted !== "boolean") {
    return res.status(400).json({ ok: false, error: "username e muted(boolean) obrigatórios" });
  }

  const key = String(username).toLowerCase();
  const v = requireTokenForUser(req, res, key);
  if (!v) return;

  if (!presence[key] || !presence[key].inGame) {
    return res.status(403).json({ ok: false, error: "not_in_game" });
  }

  if (!radioQueue[key]) radioQueue[key] = [];
  const last = radioQueue[key][radioQueue[key].length - 1];
  if (last && typeof last.muted === "boolean" && last.muted === muted && nowMs() - last.ts < 1500) {
    return res.json({ ok: true, ignored: true });
  }

  const ev = { type: muted ? "RADIO_MUTE" : "RADIO_UNMUTE", target: "web", muted, ts: nowMs() };
  const pushed = sseSendToUser(key, "radio", ev);
  radioQueue[key].push(ev);

  res.json({ ok: true, pushed });
});

app.post("/radio/mute/server", (req, res) => {
  if (rateLimit("muteIp", req, res)) return;

  const serverKey = req.headers["x-roblox-key"];
  if (!ROBLOX_SERVER_KEY || serverKey !== ROBLOX_SERVER_KEY) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }

  const { username, muted } = req.body || {};
  if (!username || typeof muted !== "boolean") {
    return res.status(400).json({ ok: false, error: "username e muted(boolean) obrigatórios" });
  }

  const key = String(username).toLowerCase();

  if (!presence[key] || !presence[key].inGame) {
    return res.status(403).json({ ok: false, error: "not_in_game" });
  }

  if (!radioQueue[key]) radioQueue[key] = [];
  const last = radioQueue[key][radioQueue[key].length - 1];
  if (last && typeof last.muted === "boolean" && last.muted === muted && nowMs() - last.ts < 1500) {
    return res.json({ ok: true, ignored: true });
  }

  const ev = { type: muted ? "RADIO_MUTE" : "RADIO_UNMUTE", target: "web", muted, ts: nowMs() };
  const pushed = sseSendToUser(key, "radio", ev);
  radioQueue[key].push(ev);

  res.json({ ok: true, pushed });
});

app.get("/radio/sync/:username", (req, res) => {
  if (rateLimit("syncIp", req, res)) return;

  const key = (req.params.username || "").toLowerCase();
  if (!key) return res.status(400).json({ ok: false, error: "username obrigatório" });

  const v = requireTokenForUser(req, res, key);
  if (!v) return;

  const events = radioQueue[key] || [];
  const webEvents = events.filter((e) => e.target === "web");
  radioQueue[key] = events.filter((e) => e.target !== "web");

  res.json({ ok: true, events: webEvents });
});

app.get("/radio/poll/:username", (req, res) => {
  if (rateLimit("pollIp", req, res)) return;

  const serverKey = req.headers["x-roblox-key"];
  if (!ROBLOX_SERVER_KEY || serverKey !== ROBLOX_SERVER_KEY) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }

  const key = (req.params.username || "").toLowerCase();
  const events = radioQueue[key] || [];

  const robloxEvents = events.filter((e) => !e.target || e.target === "roblox");
  radioQueue[key] = events.filter((e) => e.target && e.target !== "roblox");

  res.json({ ok: true, events: robloxEvents });
});

app.post("/radio/state", (req, res) => {
  if (rateLimit("stateIp", req, res)) return;

  const { username, trackIndex, trackName, positionSec, isPlaying, muted } = req.body || {};
  if (!username) return res.status(400).json({ ok: false, error: "username obrigatório" });

  const key = String(username).toLowerCase();
  const v = requireTokenForUser(req, res, key);
  if (!v) return;

  if (!presence[key] || !presence[key].inGame) {
    return res.status(403).json({ ok: false, error: "not_in_game" });
  }

  const t = nowMs();
  const prev = radioState[key];
  if (prev && prev.updatedAt && t - prev.updatedAt < STATE_MIN_GAP_MS) {
    return res.json({ ok: true, ignored: true });
  }

  const pos = Number(positionSec);
  const safePos = Number.isFinite(pos) && pos >= 0 ? pos : 0;

  radioState[key] = {
    trackIndex: Number.isFinite(Number(trackIndex)) ? Number(trackIndex) : prev?.trackIndex ?? 0,
    trackName: typeof trackName === "string" ? trackName : prev?.trackName ?? "",
    positionAt: safePos,
    isPlaying: !!isPlaying,
    muted: !!muted,
    serverTs: t,
    updatedAt: t,
  };

  res.json({ ok: true });
});

app.get("/radio/active", (req, res) => {
  if (rateLimit("activeIp", req, res)) return;

  res.setHeader("Cache-Control", "no-store");

  const t = nowMs();
  const out = [];

  for (const key of Object.keys(radioState)) {
    const st = radioState[key];
    if (!presence[key] || !presence[key].inGame) continue;

    const elapsed = (t - (st.serverTs || t)) / 1000;
    const livePos = st.isPlaying ? st.positionAt + Math.max(0, elapsed) : st.positionAt;

    out.push({
      username: key,
      trackIndex: st.trackIndex,
      trackName: st.trackName,
      positionSec: livePos,
      isPlaying: !!st.isPlaying,
      muted: !!st.muted,
      lastSeenMs: t - st.updatedAt,
    });
  }

  out.sort((a, b) => a.lastSeenMs - b.lastSeenMs);
  res.json({ ok: true, listeners: out });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🚀 Presence API v6-ultra a correr na porta " + PORT);
});
