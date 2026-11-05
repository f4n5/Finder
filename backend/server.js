/**
 * Shiv Cleaner API
 * ----------------
 * POST /api/clean  — strip malware payloads OR key-system checks from executor binaries
 * GET  /health     — uptime check
 * GET  /api/report/:id — last job report
 *
 * Modes:
 *   malware — remove stealers, webhooks, clipboard hooks, persistence, C2
 *             KEEP injection, DLL map, script engine, UI
 *   key     — nop / force-success key checks, license HTTP, HWID lock
 *             KEEP inject path
 *
 * AI layer:
 *   - Pattern engine (always on, free, local)
 *   - Optional OpenAI / compatible LLM for harder packed sections
 *     set OPENAI_API_KEY + OPENAI_BASE (default https://api.openai.com/v1)
 *
 * Run:
 *   node server.js
 *   PORT=8790 OPENAI_API_KEY=sk-... node server.js
 *
 * Point Shiv Finder CLEAN_API to:
 *   http://localhost:8790/api/clean
 */

const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");

const PORT = Number(process.env.PORT || 8790);
const HOST = process.env.HOST || "0.0.0.0";
const MAX_BYTES = Number(process.env.MAX_BYTES || 80 * 1024 * 1024); // 80 MB
const OUT_DIR = path.join(__dirname, "out");
// Accept OPENAI_* or GROQ_* (Groq is OpenAI-compatible at https://api.groq.com/openai/v1)
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || process.env.GROQ_API_KEY || "";
const OPENAI_BASE = (
  process.env.OPENAI_BASE ||
  process.env.GROQ_BASE ||
  (process.env.GROQ_API_KEY ? "https://api.groq.com/openai/v1" : "https://api.openai.com/v1")
).replace(/\/$/, "");
const OPENAI_MODEL =
  process.env.OPENAI_MODEL ||
  process.env.GROQ_MODEL ||
  (
    process.env.GROQ_API_KEY ||
    (process.env.OPENAI_BASE || "").includes("groq.com")
      ? "openai/gpt-oss-20b"
      : "gpt-4o-mini"
  );
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
// Public base URL for download links (Render sets RENDER_EXTERNAL_URL)
const PUBLIC_BASE = (process.env.PUBLIC_BASE || process.env.RENDER_EXTERNAL_URL || `http://127.0.0.1:${PORT}`).replace(/\/$/, "");

if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

/** @type {Map<string, object>} */
const jobs = new Map();

/* =========================================================
   PATTERN DATABASE
   Each rule: label, mode ("malware"|"key"|"both"), find (Buffer|string|regex-as-string),
   replace strategy, keepNote
   ========================================================= */

/** Convert ascii/utf8 string to Buffer for binary search */
function b(s) {
  return Buffer.from(s, "utf8");
}

/**
 * Known bad / key patterns.
 * replace: "nop" = 0x90 fill, "zero" = 0x00 fill, "ret" = C3, "force1" = patch near JE/JNE if found
 */
const RULES = [
  /* ---------- MALWARE ---------- */
  {
    label: "discord_webhook",
    mode: "malware",
    finds: [
      b("discord.com/api/webhooks"),
      b("discordapp.com/api/webhooks"),
      b("discord.com/api/v9/webhooks"),
      b("discord.com/api/v10/webhooks"),
    ],
    replace: "zero",
    note: "Discord webhook C2 / stealer sink",
  },
  {
    label: "telegram_bot_token",
    mode: "malware",
    finds: [b("api.telegram.org/bot"), b("api.telegram.org/file/bot")],
    replace: "zero",
    note: "Telegram bot C2",
  },
  {
    label: "clipboard_hook",
    mode: "malware",
    finds: [
      b("OpenClipboard"),
      b("SetClipboardData"),
      b("GetClipboardData"),
      b("clipboard_hook"),
      b("ClipboardWatcher"),
    ],
    replace: "nop_api", // special: soft-kill by zeroing string only (don't break legitimate UI)
    note: "Clipboard hijack markers",
  },
  {
    label: "startup_persistence",
    mode: "malware",
    finds: [
      b("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
      b("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
      b("schtasks /create"),
      b("schtasks.exe"),
      b("\\Startup\\"),
    ],
    replace: "zero",
    note: "Run-key / scheduled task persistence",
  },
  {
    label: "marsalek_stealer",
    mode: "malware",
    finds: [b("marsalek"), b("Marsalek"), b("MARSSALEK")],
    replace: "zero",
    note: "Marsalek stealer family marker",
  },
  {
    label: "browser_token_steal",
    mode: "malware",
    finds: [
      b("Login Data"),
      b("Local State"),
      b("Cookies"),
      b("Web Data"),
      b("\\Google\\Chrome\\User Data"),
      b("\\Microsoft\\Edge\\User Data"),
      b("\\BraveSoftware\\Brave-Browser"),
      b("DPAPI"),
      b("CryptUnprotectData"),
    ],
    replace: "zero_soft",
    note: "Browser credential / cookie harvest paths",
  },
  {
    label: "crypto_wallet_paths",
    mode: "malware",
    finds: [
      b("\\Exodus\\"),
      b("\\Electrum\\"),
      b("\\Atomic\\"),
      b("\\MetaMask\\"),
      b("wallet.dat"),
      b("seed phrase"),
      b("mnemonic"),
    ],
    replace: "zero_soft",
    note: "Crypto wallet steal paths",
  },
  {
    label: "generic_stealer_exfil",
    mode: "malware",
    finds: [
      b("/api/steal"),
      b("/gate.php"),
      b("/panel/send"),
      b("exfil"),
      b("StealToken"),
      b("Grabber"),
      b("token_grab"),
    ],
    replace: "zero",
    note: "Generic stealer / grabber endpoints",
  },
  {
    label: "anti_vm_heavy",
    mode: "malware",
    finds: [
      b("VBoxGuest"),
      b("VBoxMouse"),
      b("VMware"),
      b("vmcheck"),
      b("SbieDll"),
    ],
    replace: "zero_soft",
    note: "Heavy anti-VM (often bundled with malware, not inject)",
  },

  /* ---------- KEY SYSTEM ---------- */
  {
    label: "key_http_check",
    mode: "key",
    finds: [
      b("/api/key"),
      b("/api/verify"),
      b("/v1/verify"),
      b("/v1/key"),
      b("/auth/key"),
      b("/license/check"),
      b("/license/verify"),
      b("checkkey"),
      b("CheckKey"),
      b("ValidateKey"),
      b("verify_key"),
      b("key_valid"),
      b("KeySystem"),
      b("keysystem"),
    ],
    replace: "zero",
    note: "Key / license HTTP endpoint strings",
  },
  {
    label: "hwid_lock",
    mode: "key",
    finds: [
      b("GetVolumeInformation"),
      b("GetComputerName"),
      b("GetUserName"),
      b("hwid"),
      b("HWID"),
      b("HardwareId"),
      b("machine_id"),
      b("MachineGuid"),
      b("MachineGuid"),
    ],
    replace: "zero_soft",
    note: "HWID / machine lock markers",
  },
  {
    label: "keyauth_style",
    mode: "key",
    finds: [
      b("keyauth"),
      b("KeyAuth"),
      b("keyauth.win"),
      b("keyauth.cc"),
      b("sellerkey"),
      b("init_keyauth"),
    ],
    replace: "zero",
    note: "KeyAuth-style licensing",
  },
  {
    label: "auth_fail_strings",
    mode: "key",
    finds: [
      b("Invalid key"),
      b("invalid key"),
      b("Key expired"),
      b("key expired"),
      b("License expired"),
      b("HWID mismatch"),
      b("hwid mismatch"),
      b("Please enter a key"),
      b("Enter your key"),
      b("Get Key"),
      b("getkey"),
      b("Linkvertise"),
      b("linkvertise"),
      b("workink"),
      b("lootlabs"),
    ],
    replace: "zero",
    note: "User-facing key failure / ad-key pages",
  },
  {
    label: "paid_gate_urls",
    mode: "key",
    finds: [
      b("sell.app"),
      b("sellhub"),
      b("sellix.io"),
      b("btcpay"),
      b("/checkout"),
      b("/redeem"),
    ],
    replace: "zero_soft",
    note: "Payment / redeem gate URLs often tied to key flow",
  },
];

/* Strings we NEVER touch (protect inject / engine) */
const PROTECTED = [
  "VirtualAlloc",
  "VirtualProtect",
  "WriteProcessMemory",
  "ReadProcessMemory",
  "CreateRemoteThread",
  "NtCreateThreadEx",
  "LdrLoadDll",
  "LoadLibrary",
  "GetProcAddress",
  "ManualMap",
  "Reflective",
  "LuaState",
  "lua_pcall",
  "luaL_",
  "Luau",
  "ScriptContext",
  "DataModel",
  "RobloxPlayerBeta",
  "Hyperion",
  "Byfron",
];

/* =========================================================
   BINARY HELPERS
   ========================================================= */

function findAll(haystack, needle) {
  const hits = [];
  if (!needle || !needle.length || needle.length > haystack.length) return hits;
  let start = 0;
  while (start <= haystack.length - needle.length) {
    const idx = haystack.indexOf(needle, start);
    if (idx === -1) break;
    hits.push(idx);
    start = idx + 1;
  }
  return hits;
}

function isNearProtected(buf, offset, radius = 24) {
  // Only block if a protected API name overlaps the same local window.
  // Small radius so malware/key strings in the same file still get wiped.
  const from = Math.max(0, offset - radius);
  const to = Math.min(buf.length, offset + radius + 32);
  const window = buf.slice(from, to).toString("latin1");
  for (const p of PROTECTED) {
    const idx = window.indexOf(p);
    if (idx === -1) continue;
    // protected string start relative to buf
    const protStart = from + idx;
    const protEnd = protStart + p.length;
    const hitEnd = offset + 8;
    // overlap?
    if (protStart < hitEnd && protEnd > offset) return true;
  }
  return false;
}

/**
 * Apply a replace strategy at offset for `len` bytes.
 * Returns true if we wrote something.
 */
function applyReplace(buf, offset, len, strategy) {
  if (offset < 0 || offset + len > buf.length) return false;

  if (strategy === "nop") {
    buf.fill(0x90, offset, offset + len);
    return true;
  }
  if (strategy === "zero" || strategy === "zero_soft") {
    buf.fill(0x00, offset, offset + len);
    return true;
  }
  if (strategy === "ret") {
    buf[offset] = 0xc3;
    if (len > 1) buf.fill(0x90, offset + 1, offset + len);
    return true;
  }
  if (strategy === "nop_api") {
    // only zero the string itself — safer for dual-use APIs
    buf.fill(0x00, offset, offset + len);
    return true;
  }
  // default zero
  buf.fill(0x00, offset, offset + len);
  return true;
}

/**
 * Run pattern rules against a mutable Buffer.
 * Returns list of applied patches.
 */
function runPatterns(buf, mode) {
  const applied = [];
  const skippedProtected = [];

  for (const rule of RULES) {
    if (rule.mode !== mode && rule.mode !== "both") continue;
    for (const needle of rule.finds) {
      const hits = findAll(buf, needle);
      for (const off of hits) {
        if (isNearProtected(buf, off)) {
          skippedProtected.push({ label: rule.label, offset: off, reason: "near_protected" });
          continue;
        }
        const strategy = rule.replace || "zero";
        // zero_soft: only wipe the matched string, never expand
        const ok = applyReplace(buf, off, needle.length, strategy);
        if (ok) {
          applied.push({
            label: rule.label,
            offset: off,
            length: needle.length,
            strategy,
            note: rule.note,
            sample: needle.toString("utf8").slice(0, 48),
          });
        }
      }
    }
  }

  return { applied, skippedProtected };
}

/* =========================================================
   OPTIONAL LLM ASSIST (for packed / unknown sections)
   ========================================================= */

function httpsJson(method, urlStr, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const data = body ? JSON.stringify(body) : null;
    const opts = {
      method,
      hostname: u.hostname,
      path: u.pathname + u.search,
      port: u.port || 443,
      headers: {
        "Content-Type": "application/json",
        ...(data ? { "Content-Length": Buffer.byteLength(data) } : {}),
        ...headers,
      },
    };
    const req = https.request(opts, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        try {
          resolve({ status: res.statusCode, json: JSON.parse(raw), raw });
        } catch {
          resolve({ status: res.statusCode, json: null, raw });
        }
      });
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

/**
 * Ask the model for extra patch suggestions.
 * We only send printable ASCII islands (not full binary) to keep tokens down.
 */
async function askModelForPatches(mode, asciiIslands) {
  if (!OPENAI_API_KEY) return [];

  const system = `You are a binary triage assistant for Roblox executor cleaners.
You receive printable string islands extracted from a PE/DLL.
Mode: ${mode}.

If mode=malware: list strings that look like stealers, C2, webhooks, persistence, clipboard hijack, browser/crypto steal. Do NOT flag injection, VirtualAlloc, WriteProcessMemory, Luau, ScriptContext, LoadLibrary used for inject.
If mode=key: list strings that look like key checks, license verify, HWID lock, KeyAuth, "invalid key", linkvertise, getkey pages.

Return ONLY a JSON array of objects: [{"label":"short_name","string":"exact substring to zero","reason":"why"}]
Max 20 items. No markdown.`;

  const user = asciiIslands.slice(0, 12000);

  try {
    const res = await httpsJson(
      "POST",
      `${OPENAI_BASE}/chat/completions`,
      {
        model: OPENAI_MODEL,
        temperature: 0.1,
        messages: [
          { role: "system", content: system },
          { role: "user", content: user },
        ],
      },
      { Authorization: `Bearer ${OPENAI_API_KEY}` }
    );

    if (!res.json || !res.json.choices || !res.json.choices[0]) return [];
    let text = res.json.choices[0].message?.content || "";
    text = text.trim();
    // strip markdown fences if any
    if (text.startsWith("```")) {
      text = text.replace(/^```(?:json)?\n?/, "").replace(/\n?```$/, "");
    }
    const arr = JSON.parse(text);
    if (!Array.isArray(arr)) return [];
    return arr
      .filter((x) => x && typeof x.string === "string" && x.string.length >= 4)
      .slice(0, 20);
  } catch (err) {
    console.error("[llm]", err.message || err);
    return [];
  }
}

/** Pull readable ASCII islands for the model */
function extractAsciiIslands(buf, minLen = 6) {
  const out = [];
  let cur = "";
  for (let i = 0; i < Math.min(buf.length, 4 * 1024 * 1024); i++) {
    const c = buf[i];
    if (c >= 32 && c < 127) {
      cur += String.fromCharCode(c);
    } else {
      if (cur.length >= minLen) out.push(cur);
      cur = "";
    }
  }
  if (cur.length >= minLen) out.push(cur);
  // unique-ish, longest first
  const uniq = [...new Set(out)].sort((a, b) => b.length - a.length);
  return uniq.slice(0, 400).join("\n");
}

function applyModelSuggestions(buf, suggestions) {
  const applied = [];
  for (const s of suggestions) {
    const needle = Buffer.from(String(s.string), "utf8");
    if (needle.length < 4 || needle.length > 256) continue;
    const hits = findAll(buf, needle);
    for (const off of hits) {
      if (isNearProtected(buf, off)) continue;
      applyReplace(buf, off, needle.length, "zero");
      applied.push({
        label: s.label || "llm_suggestion",
        offset: off,
        length: needle.length,
        strategy: "zero",
        note: s.reason || "model",
        sample: String(s.string).slice(0, 48),
        source: "llm",
      });
    }
  }
  return applied;
}

/* =========================================================
   MULTIPART PARSE (no deps)
   ========================================================= */

function parseMultipart(buf, contentType) {
  const m = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType || "");
  if (!m) return null;
  const boundary = m[1] || m[2];
  const sep = Buffer.from("--" + boundary);
  const parts = [];
  let start = buf.indexOf(sep) + sep.length;
  while (start < buf.length) {
    if (buf[start] === 0x2d && buf[start + 1] === 0x2d) break; // --
    if (buf[start] === 0x0d && buf[start + 1] === 0x0a) start += 2;
    const next = buf.indexOf(sep, start);
    if (next === -1) break;
    let part = buf.slice(start, next - 2); // trim \r\n
    const headerEnd = part.indexOf("\r\n\r\n");
    if (headerEnd === -1) {
      start = next + sep.length;
      continue;
    }
    const header = part.slice(0, headerEnd).toString("utf8");
    const body = part.slice(headerEnd + 4);
    const nameMatch = /name="([^"]+)"/i.exec(header);
    const fileMatch = /filename="([^"]*)"/i.exec(header);
    parts.push({
      name: nameMatch ? nameMatch[1] : "",
      filename: fileMatch ? fileMatch[1] : null,
      body,
    });
    start = next + sep.length;
  }
  return parts;
}

/* =========================================================
   HTTP
   ========================================================= */

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Access-Control-Allow-Origin": CORS_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  });
  res.end(body);
}

function sendFile(res, filePath, downloadName) {
  const data = fs.readFileSync(filePath);
  res.writeHead(200, {
    "Content-Type": "application/octet-stream",
    "Content-Length": data.length,
    "Content-Disposition": `attachment; filename="${downloadName || path.basename(filePath)}"`,
    "Access-Control-Allow-Origin": CORS_ORIGIN,
  });
  res.end(data);
}

async function handleClean(req, res, rawBody) {
  const parts = parseMultipart(rawBody, req.headers["content-type"] || "");
  if (!parts || !parts.length) {
    return sendJson(res, 400, { ok: false, error: "expected multipart/form-data with file + mode" });
  }

  let filePart = parts.find((p) => p.name === "file" && p.body && p.body.length);
  if (!filePart) filePart = parts.find((p) => p.filename && p.body && p.body.length);
  const modePart = parts.find((p) => p.name === "mode");
  const namePart = parts.find((p) => p.name === "name");

  if (!filePart) {
    return sendJson(res, 400, { ok: false, error: "missing file field" });
  }

  const mode = ((modePart && modePart.body.toString("utf8")) || "malware").trim().toLowerCase();
  if (mode !== "malware" && mode !== "key") {
    return sendJson(res, 400, { ok: false, error: 'mode must be "malware" or "key"' });
  }

  const originalName =
    (namePart && namePart.body.toString("utf8")) ||
    filePart.filename ||
    "payload.bin";

  if (filePart.body.length > MAX_BYTES) {
    return sendJson(res, 413, { ok: false, error: `file too large (max ${MAX_BYTES} bytes)` });
  }

  const jobId = crypto.randomBytes(8).toString("hex");
  const buf = Buffer.from(filePart.body); // mutable copy

  // 1) deterministic pattern pass
  const { applied, skippedProtected } = runPatterns(buf, mode);

  // 2) optional LLM pass
  let llmApplied = [];
  let llmUsed = false;
  if (OPENAI_API_KEY) {
    llmUsed = true;
    const islands = extractAsciiIslands(buf);
    const suggestions = await askModelForPatches(mode, islands);
    llmApplied = applyModelSuggestions(buf, suggestions);
  }

  const allPatches = [...applied, ...llmApplied];
  const removed = [...new Set(allPatches.map((p) => p.label))];
  const kept = [
    "injection_stub",
    "script_engine",
    "ui_module",
    "dll_mapping",
    "process_attach",
  ];

  // 3) write output
  const safeBase = path
    .basename(originalName)
    .replace(/[^\w.\-]+/g, "_")
    .slice(0, 80);
  const outName = `${mode}_${jobId}_${safeBase}`;
  const outPath = path.join(OUT_DIR, outName);
  fs.writeFileSync(outPath, buf);

  const report = {
    ok: true,
    job_id: jobId,
    mode,
    original_name: originalName,
    size_in: filePart.body.length,
    size_out: buf.length,
    patches: allPatches.length,
    removed,
    kept,
    skipped_protected: skippedProtected.slice(0, 20),
    llm_used: llmUsed,
    download_url: `${PUBLIC_BASE}/api/download/${jobId}`,
    download_name: outName,
    report:
      mode === "malware"
        ? `Stripped ${removed.length} malware-related marker group(s), ${allPatches.length} patch(es). Injection / engine paths left alone.`
        : `Key-system markers patched (${removed.length} group(s), ${allPatches.length} hit(s)). Inject path untouched.`,
    details: allPatches.slice(0, 50),
  };

  jobs.set(jobId, { ...report, outPath, created: Date.now() });
  // keep only last 40 jobs in memory
  if (jobs.size > 40) {
    const oldest = [...jobs.entries()].sort((a, b) => a[1].created - b[1].created)[0];
    if (oldest) {
      try {
        fs.unlinkSync(oldest[1].outPath);
      } catch {}
      jobs.delete(oldest[0]);
    }
  }

  return sendJson(res, 200, report);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (c) => {
      total += c.length;
      if (total > MAX_BYTES + 1024 * 1024) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": CORS_ORIGIN,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
    });
    return res.end();
  }

  try {
    if (req.method === "GET" && url.pathname === "/health") {
      return sendJson(res, 200, {
        ok: true,
        service: "shiv-cleaner-api",
        llm: !!OPENAI_API_KEY,
        model: OPENAI_API_KEY ? OPENAI_MODEL : null,
        max_bytes: MAX_BYTES,
      });
    }

    if (req.method === "GET" && url.pathname.startsWith("/api/download/")) {
      const id = url.pathname.split("/").pop();
      const job = jobs.get(id);
      if (!job || !fs.existsSync(job.outPath)) {
        return sendJson(res, 404, { ok: false, error: "job not found or expired" });
      }
      return sendFile(res, job.outPath, job.download_name);
    }

    if (req.method === "GET" && url.pathname.startsWith("/api/report/")) {
      const id = url.pathname.split("/").pop();
      const job = jobs.get(id);
      if (!job) return sendJson(res, 404, { ok: false, error: "job not found" });
      const { outPath, ...rest } = job;
      return sendJson(res, 200, rest);
    }

    if (req.method === "POST" && (url.pathname === "/api/clean" || url.pathname === "/clean")) {
      const body = await readBody(req);
      return await handleClean(req, res, body);
    }

    // tiny index
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/api")) {
      return sendJson(res, 200, {
        service: "shiv-cleaner-api",
        endpoints: {
          "POST /api/clean": "multipart file + mode (malware|key)",
          "GET /api/download/:jobId": "cleaned binary",
          "GET /api/report/:jobId": "job report",
          "GET /health": "status",
        },
        env: {
          PORT,
          OPENAI_API_KEY: OPENAI_API_KEY ? "set" : "not set (pattern-only)",
          OPENAI_MODEL,
          MAX_BYTES,
        },
      });
    }

    sendJson(res, 404, { ok: false, error: "not found" });
  } catch (err) {
    console.error(err);
    sendJson(res, 500, { ok: false, error: String(err.message || err) });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`[shiv-cleaner] http://${HOST}:${PORT}`);
  console.log(`[shiv-cleaner] POST /api/clean  mode=malware|key`);
  console.log(`[shiv-cleaner] LLM: ${OPENAI_API_KEY ? "ON (" + OPENAI_MODEL + ")" : "OFF (patterns only)"}`);
  console.log(`[shiv-cleaner] out: ${OUT_DIR}`);
});
