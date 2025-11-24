const express = require("express");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// "Estado" em memória, só enquanto o servidor está ligado
// Exemplo: { "almina": true, "andre": false }
const presence = {};

app.get("/", (req, res) => {
  res.send("Roblox Presence API 💜");
});

// Roblox chama isto quando o jogador entra/sai do jogo
app.post("/presence", (req, res) => {
  const { username, inGame } = req.body;

  if (!username || typeof inGame !== "boolean") {
    return res.status(400).json({
      error: "username (string) e inGame (boolean) são obrigatórios"
    });
  }

  const key = username.toLowerCase();
  presence[key] = inGame;

  console.log(`Atualizado: ${username} -> ${inGame}`);
  res.json({ ok: true });
});

// O site pergunta aqui se o jogador está no jogo
app.get("/presence/:username", (req, res) => {
  const key = (req.params.username || "").toLowerCase();
  const exists = Object.prototype.hasOwnProperty.call(presence, key);
  const inGame = exists ? presence[key] : false;

  res.json({ exists, inGame });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🚀 Presence API a correr na porta " + PORT);
});
