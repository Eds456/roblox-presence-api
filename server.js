const express = require("express");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const presence = {};

const radioQueue = {};

app.get("/", (req, res) => {
  res.send("Roblox Presence API v1");
});

app.post("/presence", (req, res) => {
  const { username, inGame, havePass } = req.body;

  if (!username || typeof inGame !== "boolean") {
    return res.status(400).json({
      error: "username (string) e inGame (boolean) são obrigatórios"
    });
  }

  const key = username.toLowerCase();
  presence[key] = {
    inGame,
    havePass: !!havePass,
    updatedAt: Date.now()
  };

  console.log(`Atualizado: ${username} -> ${inGame} (havePass=${!!havePass})`);
  res.json({ ok: true });
});

app.get("/presence/:username", (req, res) => {
  const key = (req.params.username || "").toLowerCase();
  const exists = Object.prototype.hasOwnProperty.call(presence, key);

  res.json({
    exists,
    inGame: exists ? presence[key].inGame : false,
    havePass: exists ? presence[key].havePass : false
  });
});

app.post("/radio/join", (req, res) => {
  const { username } = req.body || {};
  if (!username) {
    return res.status(400).json({ ok: false, error: "username obrigatório" });
  }

  const key = username.toLowerCase();
  if (!radioQueue[key]) radioQueue[key] = [];

  radioQueue[key].push({
    type: "RADIO_JOIN",
    msg: "✅ Rádio sincronizada. Bem-vindo à sessão.",
    ts: Date.now()
  });

  console.log(`RADIO_JOIN -> ${username}`);
  res.json({ ok: true });
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
