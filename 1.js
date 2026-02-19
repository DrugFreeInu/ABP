// secureAntiBot.js

const express = require("express");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const SECRET = crypto.randomBytes(32).toString("hex");
const CHALLENGE_TTL = 60000; // 60 seconds
const TOKEN_TTL = 120000; // 2 minutes

const activeChallenges = new Map();
const usedNonces = new Set();

/* =====================================================
   RATE LIMITING
===================================================== */
app.use(rateLimit({
    windowMs: 60 * 1000,
    max: 120
}));

/* =====================================================
   UTILITIES
===================================================== */
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

/* =====================================================
   CHALLENGE ENDPOINT
===================================================== */
app.get("/challenge", (req, res) => {

    const challenge = crypto.randomBytes(16).toString("hex");
    const difficulty = 4; // adaptive later if needed

    activeChallenges.set(challenge, Date.now());

    res.json({ challenge, difficulty });
});

/* =====================================================
   VERIFY + TOKEN ISSUANCE
===================================================== */
app.post("/verify", (req, res) => {

    const ip = req.ip;
    const { challenge, nonce, hash, signals } = req.body;

    if (!activeChallenges.has(challenge))
        return res.status(403).json({ error: "Invalid challenge" });

    if (Date.now() - activeChallenges.get(challenge) > CHALLENGE_TTL)
        return res.status(403).json({ error: "Challenge expired" });

    const testHash = sha256(challenge + nonce);

    if (testHash !== hash || !hash.startsWith("0".repeat(4)))
        return res.status(403).json({ error: "Invalid PoW" });

    if (usedNonces.has(nonce))
        return res.status(403).json({ error: "Replay detected" });

    usedNonces.add(nonce);
    activeChallenges.delete(challenge);

    const risk = computeRisk(signals, req);

    if (risk > 0.7)
        return res.status(403).json({ error: "High risk" });

    const tokenPayload = {
        ip,
        timestamp: Date.now()
    };

    const signature = sign(tokenPayload);

    res.json({ token: tokenPayload, signature });
});

/* =====================================================
   PROTECTED API
===================================================== */
app.post("/protected", (req, res) => {

    const { token, signature } = req.body;

    if (!verifySignature(token, signature))
        return res.status(403).json({ error: "Invalid signature" });

    if (Date.now() - token.timestamp > TOKEN_TTL)
        return res.status(403).json({ error: "Token expired" });

    if (token.ip !== req.ip)
        return res.status(403).json({ error: "IP mismatch" });

    res.json({ success: true });
});

/* =====================================================
   RISK MODEL
===================================================== */
function computeRisk(signals, req) {

    let score = 0;

    const ua = signals?.ua || "";

    if (/Headless|Phantom/i.test(ua)) score += 0.5;
    if (/curl|wget|python/i.test(ua)) score += 0.5;
    if (!signals?.cpu) score += 0.2;
    if (!signals?.memory) score += 0.2;

    return score;
}

/* =====================================================
   START
===================================================== */
app.listen(3000, () => {
    console.log("Secure Anti-Bot running on port 3000");
});
