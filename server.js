import fs from "fs";
import http from "http";
import https from "https";
import express from "express";
import { Server as IOServer } from "socket.io";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---- Express static
const app = express();
app.disable("x-powered-by");
// Security headers for all routes
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cache-Control", "no-store");
  if (process.env.ENABLE_HSTS === "1") res.setHeader("Strict-Transport-Security","max-age=31536000; includeSubDomains; preload");
  next();
});
app.use(express.static(path.join(__dirname, "public"), { maxAge: 0, etag: false }));

// Basic routes
app.get("/r/:roomId", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ---- HTTP/HTTPS dev-friendly
const CERT_DIR = path.join(__dirname, "certs");
const CERT = path.join(CERT_DIR, "server.crt");
const KEY  = path.join(CERT_DIR, "server.key");

let server, PORT;
if (fs.existsSync(CERT) && fs.existsSync(KEY)) {
  server = https.createServer({ cert: fs.readFileSync(CERT), key: fs.readFileSync(KEY) }, app);
  PORT = process.env.PORT || 8443;
  console.log("Using HTTPS (certs found).");
} else {
  server = http.createServer(app);
  PORT = process.env.PORT || 3000;
  console.log("Using HTTP (no certs found).");
}

// ---- Socket.IO
// ONLY allow your domain (e.g. ORIGIN=https://chat.example.com)
// === Socket.IO in "local only" mode: no CORS/Origin restrictions ===
const io = new IOServer(server, {
  cors: { origin: true, credentials: true },
  maxHttpBufferSize: 10 * 1024 * 1024
});

// Rooms: { [roomId]: { users:Set<socketId>, timer:Timeout|null } }
const rooms = Object.create(null);
function ensureRoom(id) {
  if (!rooms[id]) rooms[id] = { users: new Set(), timer: null };
  return rooms[id];
}
function schedulePurge(id, ms = 120000) {
  const r = rooms[id];
  if (!r) return;
  if (r.timer) clearTimeout(r.timer);
  r.timer = setTimeout(() => {
    delete rooms[id];
    io.to(id).emit("room-purged");
  }, ms);
}

io.on("connection", (socket) => {
  let joinedRoom = null;

  // mini rate-limit per socket (basic anti-spam)
  const budget = { msg: 20, file: 6 }; // credits / 3s
  const refill = setInterval(()=>{ budget.msg = 20; budget.file = 6; }, 3000);
  socket.on("disconnect", ()=> clearInterval(refill));

  socket.on("join", async ({ roomId /*nick ignoré*/ }) => {
  // ✅ Validate roomId (anti-enumeration/injections)
    if (typeof roomId !== "string" || !/^[A-Za-z0-9_-]{3,64}$/.test(roomId)) {
      return socket.emit("sys:error", { code: "bad-room" });
    }
    const r = ensureRoom(roomId);
    r.users.add(socket.id);
    if (r.timer) { clearTimeout(r.timer); r.timer = null; }
    joinedRoom = roomId;
    socket.join(roomId);

    const all = Array.from(await io.in(roomId).allSockets());
    const peers = all.filter(id => id !== socket.id);
    socket.emit("sys:peers", { ids: peers });
    io.to(roomId).emit("sys:presence", { count: r.users.size });
  // Do NOT relay ANY meta (no clear nick)
    socket.to(roomId).emit("sys:join", { id: socket.id });
  });

  // Opaque relay (server only sees encrypted bytes)
  socket.on("msg",  (payload) => {
    if (!joinedRoom) return;
  if (--budget.msg < 0) return; // basic rate-limit
    socket.to(joinedRoom).emit("msg", payload);
  });
  socket.on("file", (payload) => {
    if (!joinedRoom) return;
  if (--budget.file < 0) return; // basic rate-limit
    socket.to(joinedRoom).emit("file", payload);
  });

  // WebRTC signaling
  socket.on("rtc",  (signal)  => { if (joinedRoom) socket.to(joinedRoom).emit("rtc", signal); });

  // Clear for the whole room
  socket.on("clear", () => { if (joinedRoom) io.to(joinedRoom).emit("sys:clear"); });

  // Explicit quit
  socket.on("leave", () => {
    if (!joinedRoom) return;
    socket.leave(joinedRoom);
    const r = rooms[joinedRoom];
    if (r) {
      r.users.delete(socket.id);
      io.to(joinedRoom).emit("sys:presence", { count: r.users.size });
      socket.to(joinedRoom).emit("sys:leave", { id: socket.id });
      if (r.users.size === 0) schedulePurge(joinedRoom, 120000);
    }
    joinedRoom = null;
  });

  socket.on("disconnect", () => {
    if (!joinedRoom) return;
    const r = rooms[joinedRoom];
    if (r) {
      r.users.delete(socket.id);
      io.to(joinedRoom).emit("sys:presence", { count: r.users.size });
      socket.to(joinedRoom).emit("sys:leave", { id: socket.id });
      if (r.users.size === 0) schedulePurge(joinedRoom, 120000);
    }
  });

});

server.listen(PORT, () => {
  console.log(`Ephemeral Room listening on ${server instanceof https.Server ? "https" : "http"}://localhost:${PORT}`);
});

