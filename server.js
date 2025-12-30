const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(cors());

const presence = {};
const sessions = {};
const sessionsByUser = {};
const radioQueue = {};
const radioState = {};

const SESSION_TTL_MS = 2 * 60 * 1000;
const RADIO_TTL_MS = 5 * 60 * 1000;

const STATE_TTL_MS = 25 * 1000;
const STATE_MIN_GAP_MS = 700;

const verifyHits = {};
const VERIFY_WINDOW_MS = 15 * 1000;
const VERIFY_MAX = 12;

const ROBLOX_SERVER_KEY = process.env.ROBLOX_SERVER_KEY || "";
const WEB_TOKEN_SECRET = process.env.WEB_TOKEN_SECRET || "";
const WEB_TOKEN_TTL_MS = 10 * 60 * 1000;

function genCode(len = 7) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

function cleanupSessions() {
  const now = Date.now();
  for (const code of Object.keys(sessions)) {
    const s = sessions[code];
    if (!s || s.exp <= now) {
      const u = s?.username;
      delete sessions[code];
      if (u && sessionsByUser[u] === code) delete sessionsByUser[u];
    }
  }
}

function cleanupRadioQueue() {
  const now = Date.now();
  for (const key of Object.keys(radioQueue)) {
    radioQueue[key] = (radioQueue[key] || []).filter(
      (ev) => (now - (ev.ts || now)) < RADIO_TTL_MS
    );
    if (radioQueue[key].length === 0) delete radioQueue[key];
  }
}

function cleanupRadioState() {
  const now = Date.now();
  for (const key of Object.keys(radioState)) {
    if ((now - (radioState[key].updatedAt || 0)) > STATE_TTL_MS) {
      delete radioState[key];
    }
  }
}

function rateLimitVerify(req, res) {
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "")
    .toString()
    .split(",")[0]
    .trim();

  const now = Date.now();
  let entry = verifyHits[ip];

  if (!entry || entry.resetAt <= now) {
    entry = verifyHits[ip] = { count: 0, resetAt: now + VERIFY_WINDOW_MS };
  }

  entry.count++;
  if (entry.count > VERIFY_MAX) {
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

  const now = Date.now();
  const payloadObj = { u: usernameLower, iat: now, exp: now + WEB_TOKEN_TTL_MS };
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

  const now = Date.now();
  if (!payloadObj || !payloadObj.u || !payloadObj.exp) return { ok: false, error: "bad_payload" };
  if (payloadObj.exp <= now) return { ok: false, error: "token_expired" };

  return { ok: true, username: String(payloadObj.u).toLowerCase(), exp: payloadObj.exp };
}

const sseClients = new Map();

function sseSendToUser(username, eventName, dataObj) {
  const key = String(username).toLowerCase();
  const set = sseClients.get(key);
  if (!set || set.size === 0) return false;

  const payload =
    `event: ${eventName}\n` +
    `data: ${JSON.stringify(dataObj)}\n\n`;

  for (const res of set) {
    try { res.write(payload); } catch (_) {}
  }
  return true;
}

function sseAddClient(username, res) {
  const key = String(username).toLowerCase();
  if (!sseClients.has(key)) sseClients.set(key, new Set());
  sseClients.get(key).add(res);

  res.on("close", () => {
    const set = sseClients.get(key);
    if (set) {
      set.delete(res);
      if (set.size === 0) sseClients.delete(key);
    }
  });
}

setInterval(cleanupSessions, 30 * 1000);
setInterval(cleanupRadioQueue, 60 * 1000);
setInterval(cleanupRadioState, 5 * 1000);

app.get("/", (req, res) => {
  res.send("Roblox Presence API v5");
});

app.post("/presence", (req, res) => {
  const { username, inGame, havePass } = req.body;

  if (!username || typeof inGame !== "boolean") {
    return res.status(400).json({
      ok: false,
      error: "username(string) e inGame(boolean) obrigatórios",
    });
  }

  const key = String(username).toLowerCase();
  presence[key] = { inGame, havePass: !!havePass, updatedAt: Date.now() };
  res.json({ ok: true });
});

app.get("/presence/:username", (req, res) => {
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

  let code;
  for (let i = 0; i < 12; i++) {
    const c = genCode(7);
    if (!sessions[c]) { code = c; break; }
  }
  if (!code) return res.status(500).json({ ok: false, error: "code_generation_failed" });

  sessions[code] = { username: uname, havePass: !!havePass, exp: Date.now() + SESSION_TTL_MS };
  sessionsByUser[uname] = code;

  res.json({ ok: true, code, exp: sessions[code].exp });
});

app.post("/session/verify", (req, res) => {
  if (rateLimitVerify(req, res)) return;

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
    tokenExp: token ? (Date.now() + WEB_TOKEN_TTL_MS) : null
  });
});

app.post("/radio/join", (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ ok: false, error: "username obrigatório" });

  const key = String(username).toLowerCase();
  if (!radioQueue[key]) radioQueue[key] = [];

  const now = Date.now();
  const last = radioQueue[key].length ? radioQueue[key][radioQueue[key].length - 1] : null;
  if (last && last.type === "RADIO_JOIN" && (now - (last.ts || 0)) < 10_000) {
    return res.json({ ok: true, ignored: true });
  }

  radioQueue[key].push({ type: "RADIO_JOIN", target: "roblox", ts: now });
  res.json({ ok: true });
});

app.post("/radio/mute", (req, res) => {
  const { username, muted } = req.body || {};
  if (!username || typeof muted !== "boolean") {
    return res.status(400).json({ ok: false, error: "username e muted(boolean) obrigatórios" });
  }

  const key = String(username).toLowerCase();

  if (!radioQueue[key]) radioQueue[key] = [];
  const last = radioQueue[key][radioQueue[key].length - 1];
  if (last && typeof last.muted === "boolean" && last.muted === muted && Date.now() - last.ts < 1500) {
    return res.json({ ok: true, ignored: true });
  }

  const ev = { type: muted ? "RADIO_MUTE" : "RADIO_UNMUTE", target: "web", muted, ts: Date.now() };
  const pushed = sseSendToUser(key, "radio", ev);
  radioQueue[key].push(ev);

  res.json({ ok: true, pushed });
});

app.get("/events/:username", (req, res) => {
  const username = (req.params.username || "").toLowerCase();
  if (!username) return res.status(400).end();

  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");

  res.write(`event: hello\ndata: ${JSON.stringify({ ok: true, username })}\n\n`);

  sseAddClient(username, res);

  const hb = setInterval(() => {
    try { res.write(`event: ping\ndata: {}\n\n`); } catch (_) {}
  }, 20_000);

  res.on("close", () => clearInterval(hb));
});

app.get("/radio/sync/:username", (req, res) => {
  const key = (req.params.username || "").toLowerCase();
  const events = radioQueue[key] || [];
  const webEvents = events.filter(e => e.target === "web");

  radioQueue[key] = events.filter(e => e.target !== "web");
  res.json({ ok: true, events: webEvents });
});

app.get("/radio/poll/:username", (req, res) => {
  const key = (req.params.username || "").toLowerCase();
  const events = radioQueue[key] || [];

  const robloxEvents = events.filter(e => !e.target || e.target === "roblox");
  radioQueue[key] = events.filter(e => e.target && e.target !== "roblox");

  res.json({ ok: true, events: robloxEvents });
});

app.post("/radio/state", (req, res) => {
  const { username, trackIndex, trackName, positionSec, isPlaying, muted, token } = req.body || {};
  if (!username) return res.status(400).json({ ok: false, error: "username obrigatório" });

  const key = String(username).toLowerCase();

  if (WEB_TOKEN_SECRET) {
    const headerToken = req.headers["x-radio-token"];
    const t = (typeof headerToken === "string" && headerToken) ? headerToken : token;
    const v = verifyWebToken(t);
    if (!v.ok) return res.status(401).json({ ok: false, error: v.error });
    if (v.username !== key) return res.status(403).json({ ok: false, error: "token_user_mismatch" });
  }

  if (!presence[key] || !presence[key].inGame) {
    return res.status(403).json({ ok: false, error: "not_in_game" });
  }

  const now = Date.now();
  const prev = radioState[key];
  if (prev && prev.updatedAt && (now - prev.updatedAt) < STATE_MIN_GAP_MS) {
    return res.json({ ok: true, ignored: true });
  }

  const pos = Number(positionSec);
  const safePos = Number.isFinite(pos) && pos >= 0 ? pos : 0;

  radioState[key] = {
    trackIndex: Number.isFinite(Number(trackIndex)) ? Number(trackIndex) : (prev?.trackIndex ?? 0),
    trackName: typeof trackName === "string" ? trackName : (prev?.trackName ?? ""),
    positionAt: safePos,
    isPlaying: !!isPlaying,
    muted: !!muted,
    serverTs: now,
    updatedAt: now,
  };

  res.json({ ok: true });
});

app.get("/radio/active", (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  const now = Date.now();
  const out = [];

  for (const key of Object.keys(radioState)) {
    const st = radioState[key];
    if (!presence[key] || !presence[key].inGame) continue;

    const elapsed = (now - (st.serverTs || now)) / 1000;
    const livePos = st.isPlaying ? (st.positionAt + Math.max(0, elapsed)) : st.positionAt;

    out.push({
      username: key,
      trackIndex: st.trackIndex,
      trackName: st.trackName,
      positionSec: livePos,
      isPlaying: !!st.isPlaying,
      muted: !!st.muted,
      lastSeenMs: now - st.updatedAt,
    });
  }

  out.sort((a, b) => a.lastSeenMs - b.lastSeenMs);
  res.json({ ok: true, listeners: out });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🚀 Presence API a correr na porta " + PORT);
});
