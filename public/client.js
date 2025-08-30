// Same rule as the server (prevents silently refused joins)
const ROOM_RE = /^[A-Za-z0-9_-]{3,64}$/;
let lastIntent = null; // "create" | "join" | null

// ===== Viewport helpers (iOS keyboard safe)
(function setupViewportFix(){
  const setVh = () => {
    const vv = window.visualViewport;
    const h = vv ? vv.height : window.innerHeight;
    document.documentElement.style.setProperty('--vh', `${h}px`);
  };
  setVh();
  window.addEventListener('resize', setVh);
  window.visualViewport && window.visualViewport.addEventListener('resize', setVh);
})();
// Choose File button logic
const chooseFileBtn = document.getElementById("chooseFile");
const fileInput = document.getElementById("file");
const fileNameSpan = document.getElementById("fileName");
if (chooseFileBtn && fileInput) {
  chooseFileBtn.onclick = () => fileInput.click();
  fileInput.onchange = () => {
    const f = fileInput.files[0];
    fileNameSpan.textContent = f ? f.name : "";
  };
}
// Custom notification/alert
function customAlert(msg, opts={}){
  let box = document.getElementById("customAlert");
  if (!box) {
    box = document.createElement("div");
    box.id = "customAlert";
    box.style.position = "fixed";
    box.style.top = "32px";
    box.style.right = "32px";
    box.style.zIndex = 9999;
    box.style.background = "#1a0f12";
    box.style.color = "#fff";
    box.style.padding = "18px 28px";
    box.style.borderRadius = "14px";
    box.style.boxShadow = "0 4px 24px #0008";
    box.style.fontSize = "16px";
    box.style.maxWidth = "340px";
    box.style.display = "flex";
    box.style.flexDirection = "column";
    box.style.gap = "12px";
    document.body.appendChild(box);
  }
  // Safe: no HTML interpreted
  box.innerHTML = "";
  const span = document.createElement("span");
  span.textContent = String(msg);
  box.appendChild(span);
  if (opts.confirm) {
    const btns = document.createElement("div");
    btns.style.display = "flex";
    btns.style.gap = "10px";
    const okBtn = document.createElement("button");
    okBtn.textContent = opts.okText || "OK";
    okBtn.className = "danger";
    okBtn.onclick = ()=>{ box.style.display="none"; opts.onConfirm && opts.onConfirm(true); };
    const cancelBtn = document.createElement("button");
    cancelBtn.textContent = opts.cancelText || "Annuler";
    cancelBtn.className = "secondary";
    cancelBtn.onclick = ()=>{ box.style.display="none"; opts.onConfirm && opts.onConfirm(false); };
    btns.appendChild(okBtn);
    btns.appendChild(cancelBtn);
    box.appendChild(btns);
  } else {
    setTimeout(()=>{ box.style.display="none"; }, opts.timeout||2200);
  }
  box.style.display = "flex";
}
/* ===== DOM Helpers (stable names, no duplicates) ===== */
const $id = (id) => document.getElementById(id);
const $qs = (sel) => document.querySelector(sel);
const dot = () => $id("statusDot");
const msgs = () => $id("msgs");
const lock = () => $id("lock");

/* ===== State ===== */
const enc = new TextEncoder(), dec = new TextDecoder();
let socket, key, roomId = null, nick = null, myId = null;
const tempUrls = new Set(); // for revoking blob: URLs
const privacyStrict = true; // does not expose type/size in clear if true

/* ===== UI bits ===== */
function mustFill(el){
  if(!el.value.trim()){ el.classList.add("err"); el.focus(); setTimeout(()=>el.classList.remove("err"), 1000); return false; }
  return true;
}
function nowHHMM(){ const d=new Date(); return d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}); }
function addMsg({side, nick, text, file}) {
  const wrap = document.createElement("div");
  wrap.className = "msg " + (side==="right"?"r":"l");
  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = `${nick} • ${nowHHMM()}`;
  wrap.appendChild(meta);
  if (text){
    const p = document.createElement("div");
    p.textContent = text;
    wrap.appendChild(p);
  }
  if (file){
    const row = document.createElement("div");
    row.className = "file";
    const a = document.createElement("a");
    a.className = "link";
    a.href = file.href;
    a.download = file.name;
    a.textContent = `Télécharger • ${file.name}`;
    row.appendChild(a);
    wrap.appendChild(row);
  // auto-expire after 10 min
    const url = file.href;
    tempUrls.add(url);
    setTimeout(()=>{ URL.revokeObjectURL(url); tempUrls.delete(url); a.textContent = "Lien expiré"; a.removeAttribute("href"); }, 10*60*1000);
  }
  msgs().appendChild(wrap);
  msgs().scrollTop = msgs().scrollHeight;
}
function clearTempUrls(){ for (const u of tempUrls){ URL.revokeObjectURL(u); } tempUrls.clear(); }
function wipeUI(){
  try { clearTempUrls(); } catch{}
  try { msgs().innerHTML = ""; } catch{}
  try { $id("presence").style.display="none"; } catch{}
  try { $id("sas").style.display="none"; } catch{}
  ["text","file","room","pass","nick"].forEach(id => { const el=$id(id); if (el) el.value=""; });
}
function zap(buf){ try{ if (buf && buf.byteLength) new Uint8Array(buf).fill(0); }catch{} }

function setConnected(on){
  dot().classList.toggle("ok", !!on);
  lock().style.display = on ? "none" : "flex";
  ["text","send","file","sendFile","chooseFile"].forEach(id => { $id(id).disabled = !on; });
  $id("clearAll").style.display = on ? "inline-flex" : "none";
  $id("quit").style.display = on ? "inline-flex" : "none";
}

/* ===== E2EE ===== */
async function deriveKey(pass){
  const salt = enc.encode("room:"+roomId);
  const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveBits","deriveKey"]);
  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt, iterations:200000, hash:"SHA-256" },
    base,
    { name:"AES-GCM", length:256 },
  true, // exportable for SAS
    ["encrypt","decrypt"]
  );
}
async function safetyCode(){
  // Prefer HKDF; fallback to direct HMAC if HKDF unavailable (old Safari)
  const material = await crypto.subtle.exportKey("raw", key);
  let mac;
  try {
    const base = await crypto.subtle.importKey("raw", material, "HKDF", false, ["deriveKey"]);
    const sasKey = await crypto.subtle.deriveKey(
      { name:"HKDF", hash:"SHA-256", salt: enc.encode("SAS-salt:"+roomId), info: enc.encode("SAS-info") },
      base, { name:"HMAC", hash:"SHA-256", length:256 }, false, ["sign"]
    );
    mac = await crypto.subtle.sign("HMAC", sasKey, enc.encode("SAS:"+roomId));
  } catch {
  // Fallback: HMAC(key_raw, "SAS:"+roomId)
    const h = await crypto.subtle.importKey("raw", material, {name:"HMAC", hash:"SHA-256"}, false, ["sign"]);
    mac = await crypto.subtle.sign("HMAC", h, enc.encode("SAS:"+roomId));
  }
  const b = new Uint8Array(mac);
  const n = ((b[0]<<16)|(b[1]<<8)|b[2])%1000000;
  return n.toString().padStart(6,"0");
}
function arrayBufferToBase64(buf){
  const bytes = new Uint8Array(buf);
  let binary = ""; for (let i=0;i<bytes.byteLength;i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToArrayBuffer(b64){
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i=0;i<len;i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
async function encText(s){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, enc.encode(s));
  return { iv: Array.from(iv), ct: arrayBufferToBase64(ct) };
}
async function decText(p){
  const iv = new Uint8Array(p.iv);
  const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, base64ToArrayBuffer(p.ct));
  return dec.decode(pt);
}

// Encrypt file name
async function encryptFileName(name) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, enc.encode(name));
  return { iv: Array.from(iv), ct: arrayBufferToBase64(ct) };
}

/* ===== WebRTC (DataChannel + chunking) ===== */
const peers = {}; // id -> { pc, dc }
function openDataChannels() {
  return Object.values(peers || {})
    .map(p => p && p.dc)
    .filter(dc => dc && dc.readyState === "open");
}
const RTC_CONF = (() => {
  // If offline (hotspot without WAN) => no STUN, keep local hosts
  const offline = (typeof navigator !== "undefined" && navigator && "onLine" in navigator)
    ? !navigator.onLine : false;
  return offline
    ? { iceServers: [], iceCandidatePoolSize: 0 }
    : { iceServers: [{ urls: "stun:stun.l.google.com:19302" }] };
})();

function createPeer(peerId, initiator){
  if (peers[peerId]) return peers[peerId];
  const pc = new RTCPeerConnection(RTC_CONF);
  let dc = null;

  pc.onicecandidate = (e)=>{ if(e.candidate) socket.emit("rtc",{type:"candidate",to:peerId,from:myId,candidate:e.candidate}); };
  pc.ondatachannel = ev => { dc = ev.channel; setupDC(peerId, dc); };
  if (initiator){
    dc = pc.createDataChannel("e2e",{ordered:true});
    setupDC(peerId, dc);
    (async ()=>{
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      socket.emit("rtc",{type:"offer",to:peerId,from:myId,sdp:offer});
    })().catch(console.error);
  }

  peers[peerId] = { pc, dc };
  return peers[peerId];
}

const recvFiles = {};
function setupDC(peerId, dc){
  dc.binaryType = "arraybuffer";
  dc.onmessage = async (ev)=>{
    let msg; try { msg = JSON.parse(typeof ev.data==="string"? ev.data : new TextDecoder().decode(ev.data)); } catch { return; }
    if (msg.t === "m") {
      try {
        const body = await decText(msg.payload);   // string
        const parsed = JSON.parse(body);           // {nick,text}
        addMsg({ side:"left", nick: parsed.nick || "?", text: parsed.text || "" });
      } catch(e){ console.error("decrypt/parse msg (dc) failed:", e); }
      return;
    }
  // DC file reception
    if (msg.t === "fstart"){
      recvFiles[msg.id] = { meta: msg.meta, chunks: new Array(msg.total) };
      const namePromise = decryptFileName(msg.meta, key);
      namePromise.then(name => {
        const size = (msg.meta && typeof msg.meta.size==="number") ? ` (${msg.meta.size} bytes)` : "";
        addMsg({side:"left", nick:"file", text:`Receiving: ${name}${size}`});
      });
    } else if (msg.t === "fchunk"){
      recvFiles[msg.id].chunks[msg.seq] = msg.data;
    } else if (msg.t === "fend"){
      const chunks = recvFiles[msg.id].chunks;
      const bufs = [];
      for (const b64 of chunks){
        const pack = base64ToArrayBuffer(b64);
        const u = new Uint8Array(pack);
        const iv = u.slice(0,12);
        const ct = u.slice(12);
        const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, ct);
        bufs.push(new Uint8Array(pt));
      }
      const totalLen = bufs.reduce((s,a)=>s+a.length,0);
      const all = new Uint8Array(totalLen);
      let off=0; for(const a of bufs){ all.set(a, off); off+=a.length; }
      const blob = new Blob([all], { type: recvFiles[msg.id].meta.type || "application/octet-stream" });
      decryptFileName(recvFiles[msg.id].meta, key).then(name => {
        addMsg({side:"left", nick:"file", file:{href:URL.createObjectURL(blob), name}});
      });
      delete recvFiles[msg.id];
    } else if (msg.t==="m"){
  const body = await decText(msg.payload);
  let parsed = {};
  try { parsed = JSON.parse(body); } catch {}
  addMsg({side:"left", nick: parsed.nick || "?", text: parsed.text || ""});
    }
  };
}

// Decrypt file name for DC
function decryptFileName(meta, key) {
  if (meta?.name && meta.name.iv && meta.name.ct) {
    try {
      const nameIv = new Uint8Array(meta.name.iv);
      const nameCt = base64ToArrayBuffer(meta.name.ct);
      return crypto.subtle.decrypt({name:"AES-GCM", iv: nameIv}, key, nameCt).then(buf => dec.decode(buf));
    } catch {}
  }
  return Promise.resolve(typeof meta?.name === "string" ? meta.name : "file.bin");
}

/* ===== Socket.IO (signaling + fallback) ===== */
function setupSocket(){
  socket = io({ transports:["websocket"] });
  socket.on("connect", ()=>{ myId = socket.id; });

  socket.on("sys:presence", ({count})=>{
  $id("presence").style.display="inline-flex";
  $id("presence").textContent = "Present: "+count;
  });
  // Clearly display handshake refusals/issues
  socket.on("connect_error", (err)=>{
    setConnected(false);
    customAlert("Connexion WS refusée (CORS/Origin ?) : "+(err && err.message || "connect_error"));
  });
  socket.on("sys:error", (e)=>{
    setConnected(false);
    customAlert(e && e.code === "bad-room" ? "Join refusé : Room ID invalide." : "Erreur système.");
  });
  socket.on("sys:peers", ({ids})=>{
    ids.forEach(pid=> createPeer(pid, myId < pid));
    setConnected(true);
  // Only write "created/joined" once the connection is confirmed
    if (lastIntent){
      const t = lastIntent === "create" ? "== Room created: " : "== Joined room: ";
      addMsg({side:"right", nick, text: t+roomId+" =="});
      lastIntent = null;
    }
  });
  socket.on("sys:join", ({id})=>{
    createPeer(id, myId < id);
  });
  socket.on("sys:leave", ({id})=>{
    const p = peers[id];
    if (p){ try{ p.dc && p.dc.close(); }catch{} try{ p.pc && p.pc.close(); }catch{} delete peers[id]; }
  });
  socket.on("room-purged", ()=>{
  addMsg({side:"left", nick:"system", text:"Room purged (inactive)."});
  setConnected(false);
  });

  socket.on("rtc", async (signal)=>{
    if (signal.to && signal.to !== myId) return;
    const from = signal.from;
    const p = peers[from] || createPeer(from, false);
    const pc = p.pc;

    if (signal.type === "offer"){
      await pc.setRemoteDescription(signal.sdp);
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      socket.emit("rtc",{type:"answer", to:from, from:myId, sdp:answer});
    } else if (signal.type === "answer"){
      await pc.setRemoteDescription(signal.sdp);
    } else if (signal.type === "candidate" && signal.candidate){
      await pc.addIceCandidate(signal.candidate);
    }
  });

  // Fallback E2EE (messages & files)
  socket.on("msg", async (payload)=>{
  try {
  const body = await decText(payload);      // decrypted string
  const parsed = JSON.parse(body);          // {nick, text}
    addMsg({side:"left", nick: parsed.nick || "?", text: parsed.text || ""});
  } catch(e){
    console.error("decrypt/parse msg (socket) failed:", e);
  }
  });
  socket.on("file", async (payload)=>{
    const iv = new Uint8Array(payload.iv);
    const buf = await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, base64ToArrayBuffer(payload.ct));
  // Decrypt file name
    let fileName = "file.bin";
    if (payload.meta?.name && payload.meta?.name.iv && payload.meta?.name.ct) {
      try {
        const nameIv = new Uint8Array(payload.meta.name.iv);
        const nameCt = base64ToArrayBuffer(payload.meta.name.ct);
        const nameBuf = await crypto.subtle.decrypt({name:"AES-GCM", iv: nameIv}, key, nameCt);
        fileName = dec.decode(nameBuf);
      } catch {}
    }
  const blob = new Blob([buf], { type: privacyStrict ? "application/octet-stream" : (payload.meta?.type || "application/octet-stream") });
  zap(buf);
  const url = URL.createObjectURL(blob);
  addMsg({side:"left", nick:"file", file:{href:url, name:fileName}});
  });

  // Clear received
  socket.on("sys:clear", ()=>{
  clearTempUrls();
  msgs().innerHTML = "";
  addMsg({side:"left", nick:"system", text:"Chat has been cleared for everyone."});
  });

  socket.on("disconnect", () => { setConnected(false); wipeUI(); });
}

/* ===== Actions ===== */
function getInputsOrAbort(){
  const r = $id("room"), p = $id("pass"), n = $id("nick");
  if (!mustFill(r) || !mustFill(p)) return null;
  roomId = r.value.trim();
  if (!ROOM_RE.test(roomId)) {
    r.classList.add("err");
    customAlert("Room ID invalide. Utilise lettres/chiffres/_/- (3–64).");
    setTimeout(()=>r.classList.remove("err"), 1000);
    return null;
  }
  const pass = p.value.trim();
  nick = (n.value.trim() || ("user-"+Math.floor(Math.random()*9000+1000)));
  return { pass, nick, roomId };
}

async function connectJoin(create=false){
  try{
    const got = getInputsOrAbort(); if(!got) return;
    key = await deriveKey(got.pass);
    const sas = await safetyCode();
    $id("sas").style.display="inline-flex";
    $id("sas").textContent = "SAS: "+sas;
    if(!socket) setupSocket();
    lastIntent = create ? "create" : "join";
    socket.emit("join", { roomId });
  }catch(e){
    console.error(e);
    addMsg({side:"left", nick:"erreur", text:String(e)});
  }
}

$id("create").onclick = ()=> { lastIntent="create"; connectJoin(true); };
$id("join").onclick   = ()=> { lastIntent="join";  connectJoin(false); };

$id("send").onclick = async ()=>{
  if(!key) return customAlert("Pas connecté à une room.");
  const textEl = $id("text");
  const text = textEl.value; if(!text) return;

  // Encrypt {nick,text} TOGETHER (no clear meta)
  const payload = await encText(JSON.stringify({ nick, text })); // -> {iv:Array(12), ct:base64}

  // If a DataChannel is open → direct P2P send
  const dcs = openDataChannels();
  if (dcs.length) {
    const pack = JSON.stringify({ t:"m", payload });
    dcs.forEach(dc => dc.send(pack));
  } else {
  // Otherwise fallback via Socket.IO
    if(!socket) return customAlert("Pas connecté à une room.");
    socket.emit("msg", payload);
  }

  // Local echo
  addMsg({side:"right", nick, text});
  textEl.value = "";
};
$id("text").addEventListener("keydown", (ev)=>{
  if (ev.key === "Enter") { ev.preventDefault(); $id("send").click(); }
});

const CHUNK = 16 * 1024;
$id("sendFile").onclick = async ()=>{
  const f = $id("file").files[0]; if(!f) return;
  const openPeers = Object.entries(peers).filter(([,v])=> v.dc && v.dc.readyState==="open");
  // Prevent server-side failure (10 MiB maxHttpBufferSize) in fallback
  const MAX_FALLBACK = 7 * 1024 * 1024; // ~7 MiB (base64+overhead ≈ <10 MiB)
  if (!openPeers.length && f.size > MAX_FALLBACK){
    return customAlert("File too large for fallback relay. Wait for P2P channel (or split the file).");
  }
  const encryptedName = await encryptFileName(f.name);
  if (openPeers.length){
    await Promise.all(openPeers.map(async ([pid])=>{
      const dc = peers[pid].dc;
      const total = Math.ceil(f.size / CHUNK);
      const id = "f"+Date.now()+"_"+Math.floor(Math.random()*1e6);
  const meta = { name: encryptedName };
  if (!privacyStrict) { meta.size = f.size; meta.type = f.type; }
  dc.send(JSON.stringify({ t:"fstart", id, meta, total }));

      let seq=0;
      for (let offset=0; offset < f.size; offset += CHUNK){
        const sliceBuf = await f.slice(offset, Math.min(offset+CHUNK, f.size)).arrayBuffer();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, sliceBuf);
        const pack = new Uint8Array(iv.byteLength + ct.byteLength);
        pack.set(iv,0); pack.set(new Uint8Array(ct), iv.byteLength);
        const b64 = arrayBufferToBase64(pack.buffer);
        dc.send(JSON.stringify({ t:"fchunk", id, seq, data: b64 }));
        zap(sliceBuf);
        seq++;
      }
      dc.send(JSON.stringify({ t:"fend", id }));
    }));
    addMsg({side:"right", nick, text:`↑ file (DC): ${f.name}`});
  } else {
  // Fallback Socket.IO (all encrypted in one block)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plain = await f.arrayBuffer();
    const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, plain);
    socket.emit("file", { iv: Array.from(iv), ct: arrayBufferToBase64(ct),
      meta:{ name: encryptedName, ...(privacyStrict?{}:{ size:f.size, type:f.type }) } });
    zap(plain);
    addMsg({side:"right", nick, text:`↑ file (fallback): ${f.name}`});
  }
  $id("file").value = "";
};

// Clear (visible when connected)
$id("clearAll").onclick = () => {
  if (!socket) return customAlert("Not connected to a room.");
  customAlert("Clear ALL chat history for ALL participants in this room?", {
    confirm: true,
    okText: "Yes, clear",
    cancelText: "Cancel",
    onConfirm: (ok) => { if (ok) socket.emit("clear"); }
  });
};

// Quit
function closePeers(){
  for (const id of Object.keys(peers)){
    try { peers[id].dc && peers[id].dc.close(); }catch{}
    try { peers[id].pc && peers[id].pc.close(); }catch{}
    delete peers[id];
  }
}
$id("quit").onclick = () => {
  try { socket && socket.emit("leave"); } catch {}
  try { socket && socket.disconnect(); } catch {}
  socket = null;
  closePeers();
  wipeUI();
  setConnected(false);
};

// Cleanup on close/reload
window.addEventListener("beforeunload", () => { try{ wipeUI(); }catch{} });

// On load: locked
window.addEventListener("load", ()=>{
  setConnected(false);
  $id("room").focus();
});

// Keep input visible when iOS keyboard appears
(function(){
  const textEl = document.getElementById("text");
  if (!textEl) return;
  textEl.addEventListener('focus', ()=>{
    try{ const box = document.getElementById('msgs'); box.scrollTop = box.scrollHeight; }catch{}
  });
})();
