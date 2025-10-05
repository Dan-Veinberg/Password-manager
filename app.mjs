import Database from "better-sqlite3";
import crypto from "crypto";
import fs from "fs";
import readline from "readline";
import { stdin as input, stdout as output } from "process";

/* ===================== Helpers ===================== */
const rl = readline.createInterface({ input, output });

function ask(q) {
  return new Promise(res => rl.question(q, a => res(a.trim())));
}

function askHidden(q) {
  return new Promise(res => {
    const orig = rl._writeToOutput;
    rl._writeToOutput = function () {}; // mute echo
    rl.question(`${q}: `, (ans) => {
      rl._writeToOutput = orig; // unmute
      output.write("\n");
      res(ans.trim());
    });
  });
}
const nowISO = () => new Date().toISOString();

/* ===================== Crypto ===================== */
/* AES-256-GCM; key from scrypt */
const KDF = { N: 16384, r: 8, p: 1 };
function newSaltB64() { return crypto.randomBytes(16).toString("base64"); }
function deriveKey(password, saltB64) {
  return crypto.scryptSync(password, Buffer.from(saltB64, "base64"), 32, KDF);
}
function encrypt(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString("base64"), ct: Buffer.concat([enc, tag]).toString("base64") };
}
function decrypt(key, ivB64, ctB64) {
  const iv = Buffer.from(ivB64, "base64");
  const buf = Buffer.from(ctB64, "base64");
  const enc = buf.subarray(0, buf.length - 16);
  const tag = buf.subarray(buf.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec.toString("utf8");
}

/* ===================== DB Setup ===================== */
const db = new Database("vault.db");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  title      TEXT NOT NULL,
  url        TEXT,
  username   TEXT,
  tags       TEXT,
  notes      TEXT,
  pwd_iv     TEXT NOT NULL,
  pwd_ct     TEXT NOT NULL,
  favorite   INTEGER DEFAULT 0,
  archived   INTEGER DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
`);
const getMeta = (k) => db.prepare(`SELECT value FROM meta WHERE key=?`).get(k)?.value ?? null;
const setMeta = (k, v) => db.prepare(
  `INSERT INTO meta(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`
).run(k, v);

/* ===================== Master Password ===================== */
async function ensureMasterKey() {
  let saltB64 = getMeta("kdf_salt_b64");
  const verifierIv = getMeta("verifier_iv");
  const verifierCt = getMeta("verifier_ct");

  // First run
  if (!saltB64) {
    const p1 = await askHidden("Create master password");
    const p2 = await askHidden("Confirm master password");
    if (p1 !== p2) { console.error("Passwords do not match."); return null; }
    saltB64 = newSaltB64();
    const key = deriveKey(p1, saltB64);
    const { iv, ct } = encrypt(key, "VERIFIED");
    setMeta("kdf_salt_b64", saltB64);
    setMeta("verifier_iv", iv);
    setMeta("verifier_ct", ct);
    setMeta("created_at", nowISO());
    console.log("Master password initialized.");
    return key;
  }

  // Existing vault: allow 3 tries, and recreate missing verifier if needed
  for (let tries = 1; tries <= 3; tries++) {
    const pw = await askHidden("Enter master password");
    const key = deriveKey(pw, saltB64);
    try {
      if (verifierIv && verifierCt) {
        const phrase = decrypt(key, verifierIv, verifierCt);
        if (phrase === "VERIFIED") return key;
      } else {
        const { iv, ct } = encrypt(key, "VERIFIED");
        setMeta("verifier_iv", iv);
        setMeta("verifier_ct", ct);
        console.warn("Verifier was missing; recreated.");
        return key;
      }
    } catch {}
    console.error(`Incorrect password. Attempts left: ${3 - tries}`);
  }
  return null;
}

/* ===================== CRUD ===================== */
function addEntry({ title, url, username, tags, notes, password }, key) {
  const { iv, ct } = encrypt(key, password);
  const info = db.prepare(`
    INSERT INTO entries (title, url, username, tags, notes, pwd_iv, pwd_ct, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(title, url, username, tags, notes, iv, ct, nowISO(), nowISO());
  return info.lastInsertRowid;
}
function listEntries({ includeArchived = false } = {}) {
  const where = includeArchived ? "" : "WHERE archived=0";
  return db.prepare(`SELECT id, title, url, username, tags, favorite, archived, updated_at
                     FROM entries ${where} ORDER BY updated_at DESC`).all();
}
function searchEntries(q) {
  const like = `%${q.toLowerCase()}%`;
  return db.prepare(`
    SELECT id, title, url, username, tags, favorite, archived, updated_at
    FROM entries
    WHERE archived=0 AND (
      lower(title) LIKE ? OR lower(url) LIKE ? OR lower(username) LIKE ? OR lower(tags) LIKE ?
    )
    ORDER BY updated_at DESC
  `).all(like, like, like, like);
}
const getEntry = (id) => db.prepare(`SELECT * FROM entries WHERE id=?`).get(id);
function updateEntry(id, { title, url, username, tags, notes }) {
  const e = getEntry(id); if (!e) return false;
  db.prepare(`
    UPDATE entries SET title=?, url=?, username=?, tags=?, notes=?, updated_at=? WHERE id=?
  `).run(title ?? e.title, url ?? e.url, username ?? e.username, tags ?? e.tags,
         notes ?? e.notes, nowISO(), id);
  return true;
}
function updatePassword(id, newPwd, key) {
  const e = getEntry(id); if (!e) return false;
  const { iv, ct } = encrypt(key, newPwd);
  db.prepare(`UPDATE entries SET pwd_iv=?, pwd_ct=?, updated_at=? WHERE id=?`)
    .run(iv, ct, nowISO(), id);
  return true;
}
function setArchived(id, val) {
  db.prepare(`UPDATE entries SET archived=?, updated_at=? WHERE id=?`)
    .run(val ? 1 : 0, nowISO(), id);
}
function deleteEntry(id) { db.prepare(`DELETE FROM entries WHERE id=?`).run(id); }
function revealPassword(id, key) {
  const e = getEntry(id); if (!e) return null;
  return decrypt(key, e.pwd_iv, e.pwd_ct);
}
function exportJSON(path = "export.json") {
  const data = {
    meta: {
      kdf: { algo: "scrypt", ...KDF, salt_b64: getMeta("kdf_salt_b64") },
      created_at: getMeta("created_at")
    },
    entries: db.prepare(`SELECT * FROM entries ORDER BY id ASC`).all()
  };
  fs.writeFileSync(path, JSON.stringify(data, null, 2));
  return path;
}

/* ===================== CLI ===================== */
function printRows(rows) {
  if (!rows.length) return console.log("(no entries)");
  for (const r of rows) {
    console.log(`#${r.id} | ${r.title} | ${r.username ?? ""} | ${r.url ?? ""} | ${r.tags ?? ""} | fav:${r.favorite} arch:${r.archived} | ${r.updated_at}`);
  }
}

async function main() {
  const key = await ensureMasterKey();
  if (!key) { console.error("Could not unlock vault."); rl.close(); return; }

  console.log("\nCommands:");
  console.log("  add                - add a new entry");
  console.log("  list               - list entries");
  console.log("  list all           - include archived");
  console.log("  view <id>          - show entry details (no password)");
  console.log("  show <id>          - reveal password");
  console.log("  search <text>      - search title/url/username/tags");
  console.log("  update <id>        - update fields");
  console.log("  passwd <id>        - change password");
  console.log("  archive <id>       - archive entry");
  console.log("  unarchive <id>     - unarchive entry");
  console.log("  del <id>           - delete entry");
  console.log("  export             - export to export.json");
  console.log("  quit               - exit\n");

  while (true) {
    const line = await ask("> ");
    const [cmd, ...rest] = line.split(/\s+/);
    try {
      if (!cmd) continue;
      if (cmd === "quit" || cmd === "exit") break;

      if (cmd === "add") {
        const title = await ask("title: ");
        const url = await ask("url: ");
        const username = await ask("username: ");
        const tags = await ask("tags (comma-separated): ");
        const notes = await ask("notes (non-sensitive; ENTER for none): ");
        const password = await askHidden("password");
        const id = addEntry({ title, url, username, tags, notes, password }, key);
        console.log(`Added entry #${id}`);
      } else if (cmd === "list") {
        printRows(listEntries({ includeArchived: rest[0] === "all" }));
      } else if (cmd === "view") {
        const id = Number(rest[0]); const e = getEntry(id);
        console.log(e ? JSON.stringify({
          id: e.id, title: e.title, url: e.url, username: e.username,
          tags: e.tags, notes: e.notes, favorite: e.favorite,
          archived: e.archived, created_at: e.created_at, updated_at: e.updated_at
        }, null, 2) : "Not found.");
      } else if (cmd === "show") {
        const pwd = revealPassword(Number(rest[0]), key);
        console.log(pwd == null ? "Not found." : `PASSWORD: ${pwd}`);
      } else if (cmd === "search") {
        printRows(searchEntries(rest.join(" ")));
      } else if (cmd === "update") {
        const id = Number(rest[0]); const e = getEntry(id);
        if (!e) { console.log("Not found."); continue; }
        const title = await ask(`title [${e.title}]: `) || e.title;
        const url = await ask(`url [${e.url ?? ""}]: `) || e.url;
        const username = await ask(`username [${e.username ?? ""}]: `) || e.username;
        const tags = await ask(`tags [${e.tags ?? ""}]: `) || e.tags;
        const notes = await ask(`notes [${e.notes ?? ""}]: `) || e.notes;
        updateEntry(id, { title, url, username, tags, notes });
        console.log("Updated.");
      } else if (cmd === "passwd") {
        const id = Number(rest[0]);
        const pwd = await askHidden("new password");
        console.log(updatePassword(id, pwd, key) ? "Password updated." : "Not found.");
      } else if (cmd === "archive") {
        setArchived(Number(rest[0]), true); console.log("Archived.");
      } else if (cmd === "unarchive") {
        setArchived(Number(rest[0]), false); console.log("Unarchived.");
      } else if (cmd === "del") {
        deleteEntry(Number(rest[0])); console.log("Deleted.");
      } else if (cmd === "export") {
        console.log(`Exported to ${exportJSON()}`);
      } else {
        console.log("Unknown command.");
      }
    } catch (e) {
      console.error("Error:", e.message);
    }
  }

  rl.close();
  console.log("Goodbye.");
}

await main();
