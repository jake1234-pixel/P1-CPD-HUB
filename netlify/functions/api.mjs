// P1 CPD Hub API for Netlify Functions.
// Records live in Netlify Blobs as one JSON document per collection, written with ETag checks so
// two simultaneous writes never overwrite each other. PDFs live in a separate Blobs store.
// Sign-in uses signed cookies (no session storage needed).
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const LOGIN_MODE = (process.env.LOGIN_MODE || "email").toLowerCase() === "code" ? "code" : "email";
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 30);
const ADMIN_SESSION_HOURS = Number(process.env.ADMIN_SESSION_HOURS || 12);
const MAX_UPLOAD = 5.5 * 1024 * 1024; // Netlify Functions accept request bodies up to about 6 MB
const TYPES = { "application/pdf": ".pdf", "image/png": ".png", "image/jpeg": ".jpg" };
const SESSION_KEYS = ["source", "title", "date", "hours", "cpdType", "kind", "speakers", "outcomes", "signatory", "signatoryRole", "theme", "textColour", "namePos", "showDetails", "templateFileId", "templateType"];

const data = () => getStore({ name: "cpd-data", consistency: "strong" });
const files = () => getStore({ name: "cpd-files", consistency: "strong" });

// ---------- helpers ----------
const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers } });
const fail = (status, error) => json({ error }, status);
const newId = () => crypto.randomBytes(12).toString("hex");
const sha = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
const normEmail = (e) => String(e || "").trim().toLowerCase();
const validEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const same = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const clip = (v, n) => String(v ?? "").slice(0, n);

async function read(name) { return (await data().get("db/" + name, { type: "json" })) || []; }
// read-modify-write with an ETag check; retries if someone else wrote first
async function update(name, fn) {
  const store = data();
  for (let attempt = 0; attempt < 8; attempt++) {
    const cur = await store.getWithMetadata("db/" + name, { type: "json" });
    const list = cur ? cur.data : [];
    const result = await fn(list);
    const opts = cur ? { onlyIfMatch: cur.etag } : { onlyIfNew: true };
    const w = await store.setJSON("db/" + name, list, opts);
    if (w.modified) return result;
    await new Promise(r => setTimeout(r, 40 + Math.random() * 120));
  }
  throw Object.assign(new Error("The hub is busy. Try again in a moment."), { status: 503 });
}

// ---------- signed-cookie sessions ----------
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return body + "." + crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
}
function unsign(token) {
  if (!token || !token.includes(".")) return null;
  const [body, mac] = token.split(".");
  if (!same(mac, crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url"))) return null;
  try { const p = JSON.parse(Buffer.from(body, "base64url").toString()); return p.exp > Date.now() ? p : null; } catch { return null; }
}
const cookieOf = (req) => Object.fromEntries((req.headers.get("cookie") || "").split(";").map(p => p.trim().split("=")).filter(p => p[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join("="))]));
const sessionOf = (req) => unsign(cookieOf(req).cpd_session);
function sessionCookie(payload, maxAgeSec) {
  return `cpd_session=${sign({ ...payload, exp: Date.now() + maxAgeSec * 1000 })}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSec}`;
}

// Best-effort rate limit (per function instance)
const hits = new Map();
function limited(key, max, windowMs) { const now = Date.now(); const h = (hits.get(key) || []).filter(t => now - t < windowMs); h.push(now); hits.set(key, h); return h.length > max; }

// ---------- certificate type fallback ----------
function withCpdType(certs, sessions) {
  const byId = new Map(sessions.map(s => [s.id, s]));
  return certs.map(c => ({ ...c, cpdType: c.cpdType || (c.sessionId && byId.get(c.sessionId)?.cpdType) || "" }));
}

// ---------- email codes (only when LOGIN_MODE=code) ----------
async function sendCode(email, code) {
  if (!process.env.SMTP_HOST) { console.log(`[dev] Login code for ${email}: ${code}`); return; }
  const nodemailer = (await import("nodemailer")).default;
  const t = nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: process.env.SMTP_SECURE === "true",
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined });
  await t.sendMail({ from: process.env.MAIL_FROM, to: email, subject: "Your CPD certificate sign-in code",
    text: `Your sign-in code is ${code}. It expires in 10 minutes.\n\nIf you did not ask for this, you can ignore this email.` });
}

// ---------- routes ----------
export default async (req, context) => {
  if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 10 || SESSION_SECRET.length < 32)
    return fail(500, "The hub isn't configured yet. Set ADMIN_PASSWORD (10+ characters) and SESSION_SECRET (32+ characters) in Netlify, then redeploy.");
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api/, "").replace(/\/$/, "") || "/";
  const m = req.method, ip = context.ip || "unknown";
  const sess = sessionOf(req);
  const isAdmin = !!(sess && sess.adm);
  const body = async () => { try { return await req.json(); } catch { return {}; } };
  const seg = path.split("/").filter(Boolean);
  try {
    // ----- public / adviser -----
    if (path === "/config" && m === "GET") return json({ loginMode: LOGIN_MODE });
    if (path === "/me" && m === "GET") {
      if (!sess) return json({});
      if (sess.adm) return json({ admin: true });
      const a = (await read("advisers")).find(x => x.id === sess.a);
      return json(a ? { adviser: { id: a.id, email: a.email, name: a.name, firm: a.firm || "" } } : {});
    }
    if (path === "/auth/request" && m === "POST") {
      if (limited("req:" + ip, 20, 15 * 60e3)) return fail(429, "Too many attempts. Try again in 15 minutes.");
      const email = normEmail((await body()).email);
      if (!validEmail(email)) return fail(400, "Enter a valid email address.");
      const a = (await read("advisers")).find(x => x.email === email);
      if (LOGIN_MODE === "email") {
        if (!a) return fail(404, "We couldn't find that email. Check it matches the one you registered with for our webinars.");
        return json({ adviser: { id: a.id, email: a.email, name: a.name, firm: a.firm || "" } }, 200, { "Set-Cookie": sessionCookie({ a: a.id }, SESSION_DAYS * 86400) });
      }
      if (a) {
        const code = String(crypto.randomInt(0, 1e6)).padStart(6, "0");
        await data().setJSON("code/" + sha(email), { h: sha(email + ":" + code), exp: Date.now() + 10 * 60e3, tries: 0 });
        try { await sendCode(email, code); } catch (e) { console.error(e); return fail(502, "We couldn't send the email just now. Please try again shortly."); }
      }
      return json({ codeSent: true });
    }
    if (path === "/auth/verify" && m === "POST") {
      if (limited("ver:" + ip, 30, 15 * 60e3)) return fail(429, "Too many attempts. Try again in 15 minutes.");
      const b = await body(), email = normEmail(b.email), code = String(b.code || "").trim();
      const key = "code/" + sha(email), row = await data().get(key, { type: "json" });
      const bad = () => fail(400, "That code is not right or has expired. Request a new one.");
      if (!row || row.exp < Date.now() || row.tries >= 5) return bad();
      if (!same(row.h, sha(email + ":" + code))) { await data().setJSON(key, { ...row, tries: row.tries + 1 }); return bad(); }
      await data().delete(key);
      const a = (await read("advisers")).find(x => x.email === email); if (!a) return bad();
      return json({ adviser: { id: a.id, email: a.email, name: a.name, firm: a.firm || "" } }, 200, { "Set-Cookie": sessionCookie({ a: a.id }, SESSION_DAYS * 86400) });
    }
    if (path === "/auth/logout" && m === "POST") return json({ ok: true }, 200, { "Set-Cookie": "cpd_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0" });
    if (path === "/me/certificates" && m === "GET") {
      if (!sess || sess.adm) return fail(401, "Please sign in.");
      const [certs, sessions] = await Promise.all([read("certificates"), read("sessions")]);
      return json({ certificates: withCpdType(certs.filter(c => c.adviserId === sess.a), sessions) });
    }
    if (seg[0] === "certificates" && seg[2] === "file" && m === "GET") {
      if (!sess) return fail(401, "Please sign in.");
      const c = (await read("certificates")).find(x => x.id === seg[1]);
      if (!c || (!isAdmin && c.adviserId !== sess.a)) return fail(404, "Certificate not found.");
      const f = await files().get("cert/" + c.id, { type: "arrayBuffer" });
      if (!f) return fail(404, "Certificate file not found.");
      return new Response(f, { headers: { "Content-Type": c.contentType, "Content-Disposition": `inline; filename="${c.fileName.replace(/[^\w.\- ]+/g, "_")}"`, "Cache-Control": "private, max-age=300", "X-Content-Type-Options": "nosniff" } });
    }

    // ----- admin -----
    if (path === "/admin/login" && m === "POST") {
      if (limited("adm:" + ip, 10, 15 * 60e3)) return fail(429, "Too many attempts. Try again in 15 minutes.");
      if (!same(sha((await body()).password || ""), sha(ADMIN_PASSWORD))) return fail(401, "That password is not right.");
      return json({ ok: true }, 200, { "Set-Cookie": sessionCookie({ adm: true }, ADMIN_SESSION_HOURS * 3600) });
    }
    if (seg[0] === "admin" && !isAdmin) return fail(401, "Admin sign-in required.");

    if (path === "/admin/advisers" && m === "GET") return json({ advisers: (await read("advisers")).sort((a, b) => a.name.localeCompare(b.name)) });
    if (path === "/admin/advisers/import" && m === "POST") {
      const list = (await body()).advisers || [];
      const res = await update("advisers", (advisers) => {
        let added = 0, updated = 0, skipped = 0; const ids = {}; const byEmail = new Map(advisers.map(a => [a.email, a]));
        for (const p of list) {
          const email = normEmail(p.email), name = clip(p.name, 200).trim(), firm = clip(p.firm, 200).trim();
          if (!validEmail(email) || !name) { skipped++; continue; }
          const ex = byEmail.get(email);
          if (ex) { ids[email] = ex.id; if (ex.name !== name || (firm && ex.firm !== firm)) { ex.name = name; ex.firm = firm || ex.firm; updated++; } }
          else { const a = { id: newId(), email, name, firm, createdAt: new Date().toISOString() }; advisers.push(a); byEmail.set(email, a); ids[email] = a.id; added++; }
        }
        return { added, updated, skipped, ids };
      });
      return json(res);
    }
    if (seg[0] === "admin" && seg[1] === "advisers" && seg[2] && m === "DELETE") {
      await update("certificates", certs => { certs.forEach(c => { if (c.adviserId === seg[2]) { c.adviserId = ""; c.matchMethod = ""; } }); });
      await update("advisers", advisers => { const i = advisers.findIndex(a => a.id === seg[2]); if (i >= 0) advisers.splice(i, 1); });
      return json({ ok: true });
    }

    if (path === "/admin/certificates" && m === "GET") {
      const [certs, sessions] = await Promise.all([read("certificates"), read("sessions")]);
      return json({ certificates: withCpdType(certs, sessions).sort((a, b) => String(b.eventDate).localeCompare(String(a.eventDate))) });
    }
    if (path === "/admin/certificates" && m === "POST") {
      const type = (req.headers.get("content-type") || "").split(";")[0].trim();
      if (!TYPES[type]) return fail(400, "Upload a PDF, PNG or JPG file.");
      const buf = Buffer.from(await req.arrayBuffer());
      if (!buf.length) return fail(400, "The file is empty.");
      if (buf.length > MAX_UPLOAD) return fail(413, "That file is too large (5.5 MB max).");
      if (type === "application/pdf" && buf.subarray(0, 5).toString() !== "%PDF-") return fail(400, "That file is not a valid PDF.");
      let meta; try { meta = JSON.parse(url.searchParams.get("meta") || "{}"); } catch { return fail(400, "Bad metadata."); }
      const title = clip(meta.eventTitle, 200).trim(); if (!title) return fail(400, "Session title is required.");
      const [advisers, sessions] = await Promise.all([read("advisers"), read("sessions")]);
      const adviserId = meta.adviserId && advisers.some(a => a.id === meta.adviserId) ? meta.adviserId : "";
      const sessionId = meta.sessionId && sessions.some(s => s.id === meta.sessionId) ? meta.sessionId : "";
      const cert = { id: newId(), sessionId, adviserId, eventTitle: title, eventDate: clip(meta.eventDate, 10), eventKind: clip(meta.eventKind, 40), cpdType: clip(meta.cpdType, 20),
        cpdHours: Number(meta.cpdHours) || 0, fileName: clip(meta.fileName || "certificate", 200), contentType: type, sizeBytes: buf.length,
        matchMethod: adviserId ? clip(meta.matchMethod || "manual", 20) : "", uploadedAt: new Date().toISOString() };
      // store the file first, so a record never points at a missing file
      if (/^[a-z0-9]{8,40}$/i.test(meta.id || "") && !(await read("certificates")).some(c => c.id === meta.id)) cert.id = meta.id;
      await files().set("cert/" + cert.id, buf, { metadata: { type } });
      await update("certificates", certs => { certs.push(cert); });
      return json({ certificate: cert });
    }
    if (seg[0] === "admin" && seg[1] === "certificates" && seg[2] && m === "PATCH") {
      const b = await body();
      const adviserId = b.adviserId && (await read("advisers")).some(a => a.id === b.adviserId) ? b.adviserId : "";
      await update("certificates", certs => { const c = certs.find(x => x.id === seg[2]); if (c) { c.adviserId = adviserId; c.matchMethod = adviserId ? "manual" : ""; } });
      return json({ ok: true });
    }
    if (seg[0] === "admin" && seg[1] === "certificates" && seg[2] && m === "DELETE") {
      await update("certificates", certs => { const i = certs.findIndex(c => c.id === seg[2]); if (i >= 0) certs.splice(i, 1); });
      await files().delete("cert/" + seg[2]);
      return json({ ok: true });
    }

    if (path === "/admin/sessions" && m === "GET") return json({ sessions: (await read("sessions")).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))) });
    if (path === "/admin/sessions" && m === "POST") {
      const b = await body(), d = {};
      for (const k of SESSION_KEYS) if (b[k] !== undefined) d[k] = typeof b[k] === "string" ? b[k].slice(0, 2000) : b[k];
      if (!String(d.title || "").trim()) return fail(400, "Session title is required.");
      const id = await update("sessions", sessions => {
        const ex = b.id && sessions.find(s => s.id === b.id);
        if (ex) { Object.assign(ex, d, { updatedAt: new Date().toISOString() }); return ex.id; }
        const s = { id: newId(), ...d, createdAt: new Date().toISOString() }; sessions.push(s); return s.id;
      });
      return json({ id });
    }
    if (seg[0] === "admin" && seg[1] === "sessions" && seg[2] && m === "DELETE") {
      let removed = [];
      await update("certificates", certs => { removed = certs.filter(c => c.sessionId === seg[2]).map(c => c.id); for (let i = certs.length - 1; i >= 0; i--) if (certs[i].sessionId === seg[2]) certs.splice(i, 1); });
      let tpl = "";
      await update("sessions", sessions => { const i = sessions.findIndex(s => s.id === seg[2]); if (i >= 0) { tpl = sessions[i].templateFileId || ""; sessions.splice(i, 1); } });
      await Promise.all(removed.map(id => files().delete("cert/" + id)));
      if (tpl) await files().delete("tpl/" + tpl);
      return json({ ok: true, deletedCertificates: removed.length });
    }

    if (path === "/admin/templates" && m === "POST") {
      const type = (req.headers.get("content-type") || "").split(";")[0].trim();
      if (!TYPES[type]) return fail(400, "Upload a PDF, PNG or JPG file.");
      const buf = Buffer.from(await req.arrayBuffer());
      if (!buf.length || buf.length > MAX_UPLOAD) return fail(413, "The background must be under 5.5 MB.");
      const id = newId(); await files().set("tpl/" + id, buf, { metadata: { type } });
      return json({ templateFileId: id, templateType: type });
    }
    if (seg[0] === "admin" && seg[1] === "templates" && seg[2] && m === "GET") {
      const r = await files().getWithMetadata("tpl/" + seg[2], { type: "arrayBuffer" });
      if (!r) return fail(404, "Template not found.");
      return new Response(r.data, { headers: { "Content-Type": r.metadata.type || "application/octet-stream", "Cache-Control": "private, max-age=300" } });
    }
    return fail(404, "Not found.");
  } catch (e) {
    console.error(e);
    return fail(e.status || 500, e.status ? e.message : "Something went wrong on the server.");
  }
};

export const config = { path: "/api/*" };
