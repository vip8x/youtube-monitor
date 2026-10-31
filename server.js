require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_GROUP_ID = process.env.TELEGRAM_GROUP_ID;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!DATABASE_URL || !JWT_SECRET) {
  console.error("Missing DATABASE_URL or JWT_SECRET");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

const asyncRoute = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin', 'employee')),
      telegram_chat_id TEXT UNIQUE,
      telegram_link_code TEXT UNIQUE,
      telegram_link_expires_at TIMESTAMPTZ,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS channels (
      id SERIAL PRIMARY KEY,
      channel_id TEXT UNIQUE NOT NULL,
      title TEXT NOT NULL,
      channel_url TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      initialized BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE channels
    ADD COLUMN IF NOT EXISTS initialized BOOLEAN NOT NULL DEFAULT FALSE;

    CREATE TABLE IF NOT EXISTS subscriptions (
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      channel_id INTEGER REFERENCES channels(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (user_id, channel_id)
    );

    CREATE TABLE IF NOT EXISTS videos (
      video_id TEXT PRIMARY KEY,
      channel_id INTEGER REFERENCES channels(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      video_url TEXT NOT NULL,
      published_at TIMESTAMPTZ,
      notified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  if (ADMIN_USERNAME && ADMIN_PASSWORD) {
    const result = await pool.query(
      "SELECT id FROM users WHERE username = $1",
      [ADMIN_USERNAME]
    );

    if (result.rowCount === 0) {
      const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);

      await pool.query(
        "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'admin')",
        [ADMIN_USERNAME, hash]
      );

      console.log("Admin account created.");
    }
  }
}

function makeToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: "12h" }
  );
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return res.status(401).json({ error: "Vui lòng đăng nhập." });
    }

    req.user = jwt.verify(token, JWT_SECRET);

    const result = await pool.query(
      "SELECT id, username, role, active FROM users WHERE id = $1",
      [req.user.id]
    );

    if (!result.rowCount || !result.rows[0].active) {
      return res.status(401).json({
        error: "Tài khoản không hoạt động."
      });
    }

    req.user = result.rows[0];
    next();
  } catch {
    return res.status(401).json({
      error: "Phiên đăng nhập hết hạn hoặc không hợp lệ."
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "Chỉ quản trị viên được sử dụng chức năng này."
    });
  }

  next();
}async function telegramSend(chatId, text) {
  if (!TELEGRAM_BOT_TOKEN || !chatId) return;

  const response = await fetch(
    `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        disable_web_page_preview: false
      })
    }
  );

  if (!response.ok) {
    throw new Error(await response.text());
  }
}

app.get("/", (req, res) => {
  res.json({
    status: "online",
    message: "YouTube Monitor API is running"
  });
});

app.get("/health", asyncRoute(async (req, res) => {
  await pool.query("SELECT 1");
  res.json({ status: "ok", database: "connected" });
}));

app.post("/api/login", asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      error: "Nhập tên đăng nhập và mật khẩu."
    });
  }

  const result = await pool.query(
    "SELECT * FROM users WHERE username = $1",
    [String(username).trim()]
  );

  const user = result.rows[0];

  if (!user || !user.active ||
      !(await bcrypt.compare(String(password), user.password_hash))) {
    return res.status(401).json({
      error: "Sai tên đăng nhập hoặc mật khẩu."
    });
  }

  res.json({
    token: makeToken(user),
    user: {
      id: user.id,
      username: user.username,
      role: user.role
    }
  });
}));

app.get("/api/me", auth, (req, res) => {
  res.json({ user: req.user });
});

app.get("/api/users", auth, adminOnly, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT u.id, u.username, u.role, u.active,
     u.telegram_chat_id, u.created_at,
     COUNT(s.channel_id)::int AS subscribed_channels
     FROM users u
     LEFT JOIN subscriptions s ON s.user_id = u.id
     GROUP BY u.id ORDER BY u.created_at DESC`
  );

  res.json({ users: result.rows });
}));

app.post("/api/users", auth, adminOnly, asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  const name = String(username || "").trim();

  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(name) ||
      String(password || "").length < 8) {
    return res.status(400).json({
      error: "Tên đăng nhập 3–32 ký tự, mật khẩu tối thiểu 8 ký tự."
    });
  }

  const hash = await bcrypt.hash(String(password), 12);

  try {
    const result = await pool.query(
      `INSERT INTO users (username, password_hash, role)
       VALUES ($1, $2, 'employee')
       RETURNING id, username, role, active`,
      [name, hash]
    );

    res.status(201).json({ user: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "Tên đăng nhập đã tồn tại."
      });
    }
    throw error;
  }
}));app.patch("/api/users/:id", auth, adminOnly, asyncRoute(async (req, res) => {
  const active = Boolean(req.body?.active);

  const result = await pool.query(
    "UPDATE users SET active = $1 WHERE id = $2 AND role = 'employee' RETURNING id, username, role, active",
    [active, req.params.id]
  );

  if (!result.rowCount) {
    return res.status(404).json({ error: "Không tìm thấy nhân viên." });
  }

  res.json({ user: result.rows[0] });
}));

app.get("/api/channels", auth, asyncRoute(async (req, res) => {
  const result = req.user.role === "admin"
    ? await pool.query(
        `SELECT c.*, COUNT(s.user_id)::int AS subscribers
         FROM channels c
         LEFT JOIN subscriptions s ON s.channel_id = c.id
         WHERE c.active = TRUE
         GROUP BY c.id ORDER BY c.created_at DESC`
      )
    : await pool.query(
        `SELECT c.*, EXISTS(
          SELECT 1 FROM subscriptions s
          WHERE s.channel_id = c.id AND s.user_id = $1
        ) AS subscribed
        FROM channels c
        WHERE c.active = TRUE ORDER BY c.title`,
        [req.user.id]
      );

  res.json({ channels: result.rows });
}));

app.post("/api/channels", auth, adminOnly, asyncRoute(async (req, res) => {
  const channelId = String(req.body?.channelId || "").trim();
  const title = String(req.body?.title || "").trim();

  if (!/^UC[a-zA-Z0-9_-]{20,}$/.test(channelId) || !title) {
    return res.status(400).json({
      error: "Cần Channel ID dạng UC... và tên kênh."
    });
  }

  try {
    const result = await pool.query(
      `INSERT INTO channels (channel_id, title, channel_url)
       VALUES ($1, $2, $3) RETURNING *`,
      [
        channelId,
        title,
        `https://www.youtube.com/channel/${channelId}`
      ]
    );

    res.status(201).json({ channel: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "Kênh này đã có trong kho chung."
      });
    }
    throw error;
  }
}));

app.delete("/api/channels/:id", auth, adminOnly, asyncRoute(async (req, res) => {
  const result = await pool.query(
    "UPDATE channels SET active = FALSE WHERE id = $1 RETURNING id",
    [req.params.id]
  );

  if (!result.rowCount) {
    return res.status(404).json({ error: "Không tìm thấy kênh." });
  }

  res.json({ success: true });
}));

app.post("/api/subscriptions/:channelId", auth, asyncRoute(async (req, res) => {
  const channel = await pool.query(
    "SELECT id FROM channels WHERE id = $1 AND active = TRUE",
    [req.params.channelId]
  );

  if (!channel.rowCount) {
    return res.status(404).json({ error: "Kênh không tồn tại." });
  }

  await pool.query(
    `INSERT INTO subscriptions (user_id, channel_id)
     VALUES ($1, $2) ON CONFLICT DO NOTHING`,
    [req.user.id, req.params.channelId]
  );

  res.json({ success: true, subscribed: true });
}));

app.delete("/api/subscriptions/:channelId", auth, asyncRoute(async (req, res) => {
  await pool.query(
    "DELETE FROM subscriptions WHERE user_id = $1 AND channel_id = $2",
    [req.user.id, req.params.channelId]
  );

  res.json({ success: true, subscribed: false });
}));

app.get("/api/my-subscriptions", auth, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT c.* FROM channels c
     JOIN subscriptions s ON s.channel_id = c.id
     WHERE s.user_id = $1 AND c.active = TRUE
     ORDER BY c.title`,
    [req.user.id]
  );

  res.json({ channels: result.rows });
}));

app.post("/api/telegram/link-code", auth, asyncRoute(async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) {
    return res.status(503).json({
      error: "Chưa cấu hình Telegram bot."
    });
  }

  const code = require("crypto").randomBytes(5).toString("hex");

  await pool.query(
    `UPDATE users SET telegram_link_code = $1,
     telegram_link_expires_at = NOW() + INTERVAL '15 minutes'
     WHERE id = $2`,
    [code, req.user.id]
  );

  res.json({
    code,
    instruction: `Mở bot Telegram và gửi: /start ${code}`
  });
}));

app.get("/api/stats", auth, adminOnly, asyncRoute(async (req, res) => {
  const [users, channels, videos] = await Promise.all([
    pool.query("SELECT COUNT(*)::int AS count FROM users WHERE role = 'employee' AND active = TRUE"),
    pool.query("SELECT COUNT(*)::int AS count FROM channels WHERE active = TRUE"),
    pool.query("SELECT COUNT(*)::int AS count FROM videos")
  ]);

  res.json({
    employees: users.rows[0].count,
    channels: channels.rows[0].count,
    videos: videos.rows[0].count
  });
}));

app.listen(PORT, () => {
  console.log(`YouTube Monitor running on port ${PORT}`);
});
