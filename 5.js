// ============================================================================
// NEXUS ADVANCED ANTI-BOT ENGINE (Single File)
// - Adaptive PoW
// - Replay protection
// - Sliding anomaly window
// - Trust memory per fingerprint
// - Suspicion decay
// - Shadow throttling
// - Rolling secret rotation
// - Token versioning
// ============================================================================

const express = require("express");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json());

// ================= CONFIG =================

let SECRET = crypto.randomBytes(32);
let SECRET_VERSION = 1;

const TOKEN_TTL = 60 * 1000;
const NONCE_TTL = 2 * 60 * 1000;
const BASE_DIFFICULTY = 3;

const usedNonces = new Map();
const trustMemory = new Map(); // fingerprint → trust state

// Rotate secret every 10 minutes
setInterval(() => {
    SECRET = crypto.randomBytes(32);
    SECRET_VERSION++;
}, 10 * 60 * 1000);

// ================= RATE LIMIT =================

const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 200
});

app.use(limiter);

// ================= UTILITIES =================

function sha256(data) {
    return crypto.createHash("sha256")
        .update(data)
        .digest("hex");
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

function cleanNonces() {
    const now = Date.now();
    for (const [nonce, time] of usedNonces.entries()) {
        if (now - time > NONCE_TTL) {
            usedNonces.delete(nonce);
        }
    }
}

function getTrustState(fingerprint) {
    if (!trustMemory.has(fingerprint)) {
        trustMemory.set(fingerprint, {
            score: 0,
            lastSeen: Date.now(),
            requestTimes: []
        });
    }
    return trustMemory.get(fingerprint);
}

function decayTrust(state) {
    const now = Date.now();
    const delta = now - state.lastSeen;
    state.score *= Math.max(0.5, 1 - delta / 600000);
    state.lastSeen = now;
}

// ================= RISK ENGINE =================

function computeRisk(req, fingerprint) {

    const state = getTrustState(fingerprint);
    decayTrust(state);

    let score = 0;
    const ua = req.headers["user-agent"] || "";

    if (/Headless/i.test(ua)) score += 0.6;
    if (/curl|wget|python|axios/i.test(ua)) score += 0.6;

    // Sliding window burst detection
    const now = Date.now();
    state.requestTimes.push(now);
    state.requestTimes = state.requestTimes.filter(t => now - t < 10000);

    if (state.requestTimes.length > 30)
        score += 0.5;

    state.score += score;

    return state.score;
}

// ================= CHALLENGE =================

app.post("/challenge", (req, res) => {

    cleanNonces();

    const { fingerprintHash } = req.body;
    if (!fingerprintHash)
        return res.status(400).json({ error: "Missing fingerprint" });

    const state = getTrustState(fingerprintHash);
    decayTrust(state);

    const difficulty =
        BASE_DIFFICULTY + Math.min(3, Math.floor(state.score));

    const nonce = crypto.randomBytes(16).toString("hex");

    res.json({
        nonce,
        difficulty,
        version: SECRET_VERSION
    });
});

// ================= VERIFY =================

app.post("/verify", (req, res) => {

    cleanNonces();

    const {
        fingerprintHash,
        nonce,
        counter,
        hash
    } = req.body;

    if (!fingerprintHash || !nonce || counter === undefined || !hash)
        return res.status(400).json({ error: "Malformed request" });

    if (usedNonces.has(nonce))
        return res.status(403).json({ error: "Replay detected" });

    const expectedHash = sha256(
        fingerprintHash + nonce + counter
    );

    if (expectedHash !== hash)
        return res.status(403).json({ error: "Invalid PoW hash" });

    const state = getTrustState(fingerprintHash);
    const dynamicDifficulty =
        BASE_DIFFICULTY + Math.min(3, Math.floor(state.score));

    if (!hash.startsWith("0".repeat(dynamicDifficulty)))
        return res.status(403).json({ error: "PoW difficulty fail" });

    const risk = computeRisk(req, fingerprintHash);

    usedNonces.set(nonce, Date.now());

    // Soft-ban mode
    if (risk > 3) {
        return res.status(200).json({
            status: "shadow_throttled"
        });
    }

    if (risk > 5)
        return res.status(403).json({ error: "High risk entity" });

    const payload = {
        fingerprintHash,
        ip: req.ip,
        exp: Date.now() + TOKEN_TTL,
        v: SECRET_VERSION
    };

    const signature = sign(payload);

    state.score *= 0.5; // reduce suspicion after valid solve

    res.json({
        payload,
        signature
    });
});

// ================= PROTECTED =================

app.post("/protected", (req, res) => {

    const { payload, signature } = req.body;

    if (!payload || !signature)
        return res.status(400).json({ error: "Missing token" });

    if (!verifySignature(payload, signature))
        return res.status(403).json({ error: "Invalid signature" });

    if (Date.now() > payload.exp)
        return res.status(403).json({ error: "Token expired" });

    if (payload.ip !== req.ip)
        return res.status(403).json({ error: "IP mismatch" });

    res.json({ success: true });
});

// ================= START =================

app.listen(3000, () => {
    console.log("NEXUS ADVANCED Anti-Bot running on port 3000");
});
