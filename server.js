const express = require("express");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const presence = {};
const radioQueue = {};

const RADIO_TTL_MS = 5 * 60 * 1000; 

setInterval(() => {
  const now = Date.now();
  for (const key of Object.keys(radioQueue)) {
    radioQueue[key] = (radioQueue[key] || []).filter(
      (ev) => (now - (ev.ts || now)) < RADIO_TTL_MS
    );
    if (radioQueue[key].length === 0) delete radioQueue[key];
  }
}, 60 * 1000);

app.get("/", (req, res) => {
  res.send("Roblox Presence API v2");
});

app.post("/presence", (req, res) => {
  const { username, inGame, havePass } = req.body;

  if (!username || typeof inGame !== "boolean") {
    return res.status(400).json({
      error: "username (string) e inGame (boolean) são obrigatórios",
    });
  }

  const key = username.toLowerCase();
  presence[key] = {
    inGame,
    havePass: !!havePass,
    updatedAt: Date.now(),
  };

  console.log(`Atualizado: ${username} -> ${inGame} (havePass=${!!havePass})`);
  res.json({ ok: true });
});

app.get("/presence/:username", (req, res) => {
  const key = (req.params.username || "").toLowerCase();
  const exists = Object.prototype.hasOwnProperty.call(presence, key);

  res.json({
    exists,
    inGame: exists ? !!presence[key].inGame : false,
    havePass: exists ? !!presence[key].havePass : false,
  });
});

app.post("/radio/join", (req, res) => {
  const { username } = req.body || {};
  if (!username) {
    return res.status(400).json({ ok: false, error: "username obrigatório" });
  }

  const key = username.toLowerCase();
  if (!radioQueue[key]) radioQueue[key] = [];

  const now = Date.now();

  const last = radioQueue[key].length ? radioQueue[key][radioQueue[key].length - 1] : null;
  if (last && last.type === "RADIO_JOIN" && (now - (last.ts || 0)) < 10_000) {
    return res.json({ ok: true, ignored: true });
  }

  radioQueue[key].push({
    type: "RADIO_JOIN",
    ts: now,
  });

  console.log(`Evento RADIO_JOIN registado para ${username}`);
  res.json({ ok: true });
});

app.get("/radio/peek/:username", (req, res) => {
  const key = (req.params.username || "").toLowerCase();
  const events = radioQueue[key] || [];
  res.json({ ok: true, events });
});

app.get("/radio/poll/:username", (req, res) => {
  const key = (req.params.username || "").toLowerCase();
  const events = radioQueue[key] || [];
  radioQueue[key] = [];
  res.json({ ok: true, events });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🚀 Presence API a correr na porta " + PORT);
});


