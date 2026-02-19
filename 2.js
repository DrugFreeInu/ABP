// server.js

const express = require("express");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const Redis = require("ioredis");

const app = express();
app.use(express.json());

/* ================= CONFIG ================= */

const PORT = 3000;
const SECRET = process.env.ANTIBOT_SECRET || crypto.randomBytes(32).toString("hex");
const CHALLENGE_TTL = 60;          // seconds
const TOKEN_TTL = 120;             // seconds
const BASE_DIFFICULTY = 4;
const MAX_DIFFICULTY = 7;

/* ================= REDIS ================= */

const redis = new Redis(); // assumes local redis

/* ================= RATE LIMIT ================= */

app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true
}));

/* ================= UTIL ================= */

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function sign(payload) {
  return crypto
    .createHmac("sha256", SECRET)
    .update(JSON.stringify(payload))
    .digest("hex");
}

function verifySignature(payload, signature) {
  const expected = sign(payload);
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
}

/* ================= DIFFICULTY SCALING ================= */

async function dynamicDifficulty(ip) {
  const requestCount = await redis.get(`rate:${ip}`) || 0;
  const scaled = BASE_DIFFICULTY + Math.floor(requestCount / 50);
  return Math.min(MAX_DIFFICULTY, scaled);
}

/* ================= CHALLENGE ================= */

app.get("/challenge", async (req, res) => {

  const ip = req.ip;
  const difficulty = await dynamicDifficulty(ip);

  const challenge = crypto.randomBytes(16).toString("hex");

  await redis.set(
    `challenge:${challenge}`,
    ip,
    "EX",
    CHALLENGE_TTL
  );

  res.json({ challenge, difficulty });
});

/* ================= VERIFY ================= */

app.post("/verify", async (req, res) => {

  const ip = req.ip;
  const { challenge, nonce, hash, signals } = req.body;

  const storedIp = await redis.get(`challenge:${challenge}`);
  if (!storedIp || storedIp !== ip)
    return res.status(403).json({ error: "Invalid challenge" });

  const difficulty = await dynamicDifficulty(ip);

  const testHash = sha256(challenge + nonce);

  if (testHash !== hash || !hash.startsWith("0".repeat(difficulty)))
    return res.status(403).json({ error: "Invalid PoW" });

  const replayKey = `nonce:${nonce}`;
  if (await redis.exists(replayKey))
    return res.status(403).json({ error: "Replay detected" });

  await redis.set(replayKey, 1, "EX", CHALLENGE_TTL);
  await redis.del(`challenge:${challenge}`);

  const risk = computeRisk(signals, req);
  if (risk > 0.7)
    return res.status(403).json({ error: "High risk" });

  const tokenPayload = {
    ip,
    issued: Date.now()
  };

  const signature = sign(tokenPayload);

  await redis.incr(`rate:${ip}`);
  await redis.expire(`rate:${ip}`, 60);

  res.json({ token: tokenPayload, signature });
});

/* ================= PROTECTED ================= */

app.post("/protected", async (req, res) => {

  const { token, signature } = req.body;

  if (!verifySignature(token, signature))
    return res.status(403).json({ error: "Invalid signature" });

  if (Date.now() - token.issued > TOKEN_TTL * 1000)
    return res.status(403).json({ error: "Token expired" });

  if (token.ip !== req.ip)
    return res.status(403).json({ error: "IP mismatch" });

  res.json({ success: true });
});

/* ================= RISK MODEL ================= */

function computeRisk(signals, req) {

  let score = 0;
  const ua = signals?.ua || "";

  if (/Headless|Phantom/i.test(ua)) score += 0.5;
  if (/curl|wget|python/i.test(ua)) score += 0.5;
  if (!signals?.cpu) score += 0.2;
  if (!signals?.memory) score += 0.2;

  return score;
}

app.listen(PORT, () => {
  console.log(`Enterprise Anti-Bot running on ${PORT}`);
});
