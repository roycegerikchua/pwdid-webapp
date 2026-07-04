require('dotenv').config();
const express = require('express');
const path = require('path');
const sql = require('mssql');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');


const app = express();
const PORT = Number(process.env.PORT || 3015);
const JWT_KEY = process.env.JWT_SECRET || 'pwdid-change-this-jwt-secret';

app.set('trust proxy', 1);
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));
app.use(session({
  name: 'pwdid.sid',
  secret: process.env.SESSION_SECRET || 'pwdid-change-this-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: true, maxAge: 12 * 60 * 60 * 1000 }
}));
app.use(cookieParser());
// No unauthenticated static index. The app shell is served by authenticated routes below.

const dbConfig = {
  server: process.env.MSSQL_SERVER,
  port: Number(process.env.MSSQL_PORT || 1433),
  database: process.env.MSSQL_DATABASE,
  user: process.env.MSSQL_USER,
  password: process.env.MSSQL_PASSWORD,
  options: {
    encrypt: String(process.env.MSSQL_ENCRYPT || 'false').toLowerCase() === 'true',
    trustServerCertificate: String(process.env.MSSQL_TRUST_CERT || 'true').toLowerCase() !== 'false',
    enableArithAbort: true,
    useUTC: false
  },
  pool: { max: Number(process.env.MSSQL_POOL_MAX || 5), min: 0, idleTimeoutMillis: 30000 },
  connectionTimeout: Number(process.env.MSSQL_CONNECT_TIMEOUT || 15000),
  requestTimeout: Number(process.env.MSSQL_REQUEST_TIMEOUT || 15000)
};

let poolPromise;
let schemaReadyPromise;
async function getPool() {
  if (!poolPromise) {
    poolPromise = sql.connect(dbConfig).catch(err => {
      poolPromise = null;
      schemaReadyPromise = null;
      throw err;
    });
  }
  const pool = await poolPromise;
  if (!schemaReadyPromise) schemaReadyPromise = ensureSchema(pool);
  await schemaReadyPromise;
  return pool;
}

async function ensureSchema(pool) {
  await pool.request().query(`
    IF OBJECT_ID('dbo.Branches','U') IS NULL
    CREATE TABLE dbo.Branches (
      id INT IDENTITY(1,1) PRIMARY KEY,
      branch_code NVARCHAR(50) NOT NULL UNIQUE,
      branch_name NVARCHAR(255) NOT NULL,
      address NVARCHAR(500) NULL,
      city NVARCHAR(100) NULL,
      gps_radius_meters INT NOT NULL CONSTRAINT DF_PWD_Branches_gps DEFAULT 100,
      is_active BIT NOT NULL CONSTRAINT DF_PWD_Branches_active DEFAULT 1,
      created_at DATETIME NOT NULL CONSTRAINT DF_PWD_Branches_created DEFAULT GETDATE(),
      updated_at DATETIME NOT NULL CONSTRAINT DF_PWD_Branches_updated DEFAULT GETDATE()
    );

    IF OBJECT_ID('dbo.Staff','U') IS NULL
    CREATE TABLE dbo.Staff (
      id INT IDENTITY(1,1) PRIMARY KEY,
      employee_id NVARCHAR(50) NULL,
      username NVARCHAR(100) NOT NULL UNIQUE,
      password_hash NVARCHAR(255) NOT NULL CONSTRAINT DF_PWD_Staff_password DEFAULT '',
      full_name NVARCHAR(255) NOT NULL,
      email NVARCHAR(255) NULL,
      role NVARCHAR(50) NOT NULL CONSTRAINT DF_PWD_Staff_role DEFAULT 'staff',
      branch_id INT NULL,
      is_active BIT NOT NULL CONSTRAINT DF_PWD_Staff_active DEFAULT 1,
      last_login DATETIME NULL,
      created_at DATETIME NOT NULL CONSTRAINT DF_PWD_Staff_created DEFAULT GETDATE(),
      updated_at DATETIME NOT NULL CONSTRAINT DF_PWD_Staff_updated DEFAULT GETDATE()
    );

    IF OBJECT_ID('dbo.PWDID_Audit','U') IS NULL
    CREATE TABLE dbo.PWDID_Audit (
      id INT IDENTITY(1,1) PRIMARY KEY,
      pwd_id_number VARCHAR(50) NOT NULL,
      action NVARCHAR(50) NOT NULL,
      staff_id INT NULL,
      username NVARCHAR(100) NULL,
      full_name NVARCHAR(255) NULL,
      branch_id INT NULL,
      branch_code NVARCHAR(50) NULL,
      branch_name NVARCHAR(255) NULL,
      ip_address NVARCHAR(80) NULL,
      created_at DATETIME NOT NULL CONSTRAINT DF_PWDID_Audit_created DEFAULT GETDATE()
    );

    IF COL_LENGTH('dbo.PWDID','encoded_by_user_id') IS NULL ALTER TABLE dbo.PWDID ADD encoded_by_user_id INT NULL;
    IF COL_LENGTH('dbo.PWDID','encoded_by_username') IS NULL ALTER TABLE dbo.PWDID ADD encoded_by_username NVARCHAR(100) NULL;
    IF COL_LENGTH('dbo.PWDID','encoded_by_full_name') IS NULL ALTER TABLE dbo.PWDID ADD encoded_by_full_name NVARCHAR(255) NULL;
    IF COL_LENGTH('dbo.PWDID','branch_id') IS NULL ALTER TABLE dbo.PWDID ADD branch_id INT NULL;
    IF COL_LENGTH('dbo.PWDID','branch_code') IS NULL ALTER TABLE dbo.PWDID ADD branch_code NVARCHAR(50) NULL;
    IF COL_LENGTH('dbo.PWDID','branch_name') IS NULL ALTER TABLE dbo.PWDID ADD branch_name NVARCHAR(255) NULL;
    IF COL_LENGTH('dbo.PWDID','saved_from_app') IS NULL ALTER TABLE dbo.PWDID ADD saved_from_app NVARCHAR(50) NULL;
  `);
}

function ctaDecrypt(sInput) {
  if (!sInput) return '';
  let out = '';
  for (let i = 0; i < sInput.length; i++) {
    const code = sInput.charCodeAt(i);
    if (code >= 192 && code <= 217) out += String.fromCharCode(code - 127);
    else if (code >= 218 && code <= 243) out += String.fromCharCode(code - 121);
    else if (code >= 244 && code <= 253) out += String.fromCharCode(code - 196);
    else out += String.fromCharCode(code);
  }
  return out;
}

function h(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c])); }

function ssoMiddleware(req, res, next) {
  if (req.session.user) return next();

  const token = req.cookies.sso_token;
  if (!token) return next(); // No SSO token → let app's own auth handle it

  try {
    const decoded = jwt.verify(token, JWT_KEY);
    // SSO users need branch selection first
    req.session.pendingAuth = {
      staffId: decoded.staff_id,
      fullName: decoded.fullName,
      role: decoded.role,
      username: decoded.sub,
      sso_login: true
    };
    // Redirect to branch selection if landing on any protected page
    const skip = ['/auth/login', '/auth/select-branch', '/auth/logout', '/health', '/sso-login'];
    if (!skip.includes(req.path)) {
      return req.session.save(() => res.redirect('/auth/select-branch'));
    }
    return next();
  } catch {
    res.clearCookie('sso_token', { domain: '.ubesvr.com', path: '/' });
    return next();
  }
}

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  if (req.path.startsWith('/pwdid') || req.path.startsWith('/pwd-') || req.path.startsWith('/test-pwd') || req.path.startsWith('/api/')) {
    return res.status(401).json({ success: false, error: 'Login required' });
  }
  return res.redirect('/auth/login');
}

function renderLogin(error) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PWD ID Login</title><style>body{margin:0;background:#f7f3ff;font-family:Arial,sans-serif;color:#1d1730}.box{max-width:390px;margin:8vh auto;background:white;border:1px solid #ded3f4;border-radius:18px;padding:28px;box-shadow:0 12px 30px rgba(75,0,130,.08)}h1{margin:0 0 6px;color:#4b0082}.muted{color:#6f6687;margin:0 0 22px}label{display:block;font-weight:700;font-size:12px;margin:14px 0 6px;text-transform:uppercase;color:#6f6687}input{width:100%;box-sizing:border-box;padding:12px;border:1.5px solid #ded3f4;border-radius:10px;font-size:16px}button{width:100%;margin-top:18px;padding:13px;border:0;border-radius:10px;background:#4b0082;color:#fff;font-weight:800;font-size:15px}.err{background:#ffecec;color:#b4232d;border:1px solid #ffc7cc;border-radius:10px;padding:10px;margin-bottom:12px}.sso-btn{display:block;width:100%;margin-top:12px;padding:13px;border:2px solid #e94560;border-radius:10px;background:transparent;color:#e94560;font-weight:800;font-size:15px;text-align:center;text-decoration:none;box-sizing:border-box}.sso-btn:hover{background:#e94560;color:#fff}.hr-or{display:flex;align-items:center;margin:18px 0 4px;color:#968bab;font-size:12px;font-weight:700}.hr-or::before,.hr-or::after{content:"";flex:1;height:1px;background:#ded3f4}.hr-or:not(:empty)::before{margin-right:12px}.hr-or:not(:empty)::after{margin-left:12px}</style></head><body><div class="box"><h1>PWD ID Checker</h1><p class="muted">Login using your UBEPOS/VIP_HO barcode and password.</p>${error ? `<div class="err">${h(error)}</div>` : ''}<form method="post" action="/auth/login"><label>Barcode / Username</label><input name="username" autocomplete="username" autofocus required><label>Password</label><input name="password" type="password" autocomplete="current-password" required><button type="submit">Login</button><div class="hr-or">or</div><a href="/sso-login" class="sso-btn">Sign in with UBEPOS SSO</a></form></div></body></html>`;
}

function renderBranchSelect(pending, branches, error) {
  const rows = branches.map(b => `<label class="branch" data-code="${h(String(b.branch_code||'').toLowerCase())}" data-name="${h(String(b.branch_name||'').toLowerCase())}"><input type="radio" name="branch_id" value="${h(b.id)}" onchange="submitBranch.disabled=false"><span><b>${h(b.branch_name)}</b><small>${h(b.branch_code)}${b.address ? ' · '+h(b.address) : ''}</small></span></label>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Select Branch</title><style>body{margin:0;background:#f7f3ff;font-family:Arial,sans-serif;color:#1d1730}.box{max-width:620px;margin:4vh auto;background:white;border:1px solid #ded3f4;border-radius:18px;padding:24px;box-shadow:0 12px 30px rgba(75,0,130,.08)}h1{margin:0;color:#4b0082}.muted{color:#6f6687}.err{background:#ffecec;color:#b4232d;border:1px solid #ffc7cc;border-radius:10px;padding:10px}.search{width:100%;box-sizing:border-box;padding:12px;border:1.5px solid #ded3f4;border-radius:10px;font-size:15px;margin:12px 0}.list{max-height:58vh;overflow:auto;border:1px solid #eee;border-radius:12px}.branch{display:flex;gap:12px;align-items:center;padding:12px;border-bottom:1px solid #eee;cursor:pointer}.branch:hover{background:#f7f3ff}.branch small{display:block;color:#6f6687;margin-top:3px}.hide{display:none}button{width:100%;margin-top:14px;padding:13px;border:0;border-radius:10px;background:#4b0082;color:#fff;font-weight:800;font-size:15px}button:disabled{background:#b9a7cf}</style></head><body><div class="box"><h1>Select Your Branch</h1><p class="muted">Welcome, <b>${h(pending.fullName)}</b>. Select your assigned branch for this login.</p>${error ? `<div class="err">${h(error)}</div>` : ''}<input id="filter" class="search" placeholder="Search branch name or code" autofocus><form method="post" action="/auth/select-branch"><div id="list" class="list">${rows || '<p class="muted" style="padding:18px">No active branches found.</p>'}</div><button id="submitBranch" disabled>Continue</button></form></div><script>filter.oninput=function(){var q=filter.value.toLowerCase().trim();document.querySelectorAll('.branch').forEach(function(x){x.classList.toggle('hide',q && x.dataset.code.indexOf(q)<0 && x.dataset.name.indexOf(q)<0)})}</script></body></html>`;
}

async function syncBranches(pool) {
  await pool.request().query(`MERGE INTO dbo.Branches t
    USING (SELECT br_code, store_name FROM [posConfig].[dbo].[posConfig] WHERE status = 1 AND (xtra3 IS NOT NULL AND xtra3 <> 0)) s
    ON t.branch_code = s.br_code
    WHEN MATCHED THEN UPDATE SET branch_name = s.store_name, is_active = 1, updated_at = GETDATE()
    WHEN NOT MATCHED THEN INSERT (branch_code, branch_name, address, gps_radius_meters, is_active) VALUES (s.br_code, s.store_name, '', 100, 1);`);
}

function normalizePwdId(value) {
  const raw = String(value || '').trim();
  const digits = raw.replace(/\D/g, '');
  if (digits.length !== 16) {
    const err = new Error('PWD ID must contain exactly 16 digits');
    err.statusCode = 400;
    err.details = { received: raw, digits };
    throw err;
  }
  return `${digits.slice(0, 2)}-${digits.slice(2, 6)}-${digits.slice(6, 9)}-${digits.slice(9, 16)}`;
}

function parseGoogleVisionResult(response) {
  if (!response || !response.responses || !response.responses[0]) {
    return { success: false, error: 'Invalid Google Vision response', raw: response };
  }
  const result = response.responses[0];
  if (result.error) return { success: false, error: result.error.message || 'Google Vision error', googleError: result.error };

  const rawText = result.fullTextAnnotation?.text || result.textAnnotations?.[0]?.description || '';
  const lines = rawText.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
  const pageHeight = result.fullTextAnnotation?.pages?.[0]?.height || 599;
  const pageWidth = result.fullTextAnnotation?.pages?.[0]?.width || 950;

  const wordAnns = (result.textAnnotations || []).slice(1).map(ann => {
    const v = ann.boundingPoly?.vertices || [];
    if (v.length < 4) return null;
    const xs = v.map(p => p.x || 0);
    const ys = v.map(p => p.y || 0);
    return {
      text: ann.description,
      x: xs.reduce((s, n) => s + n, 0) / 4,
      y: ys.reduce((s, n) => s + n, 0) / 4,
      top: Math.min(...ys), bottom: Math.max(...ys),
      left: Math.min(...xs), right: Math.max(...xs)
    };
  }).filter(Boolean);

  const textLines = [];
  const used = new Set();
  for (let i = 0; i < wordAnns.length; i++) {
    if (used.has(i)) continue;
    const group = [wordAnns[i]];
    used.add(i);
    for (let j = i + 1; j < wordAnns.length; j++) {
      if (!used.has(j) && Math.abs(wordAnns[j].y - wordAnns[i].y) < 15) {
        group.push(wordAnns[j]);
        used.add(j);
      }
    }
    group.sort((a, b) => a.x - b.x);
    textLines.push({
      text: group.map(w => w.text).join(' '),
      y: group.reduce((s, w) => s + w.y, 0) / group.length,
      top: Math.min(...group.map(w => w.top)), bottom: Math.max(...group.map(w => w.bottom)),
      left: Math.min(...group.map(w => w.left)), right: Math.max(...group.map(w => w.right)),
      words: group
    });
  }
  textLines.sort((a, b) => a.y - b.y);

  const BOILERPLATE = /republic|philippines|persons with disability|person with disability|city government|city of|lungsod ng|municipality|province of|barangay|lgu|affairs office|non-transferable|valid anywhere|valid for|type of disability|id no|i\.d\. no|id number|mayor|vice mayor|governor|congressman|hon\b|department|dswd|phic|philhealth|social welfare|sangguniang|punong|kagawad|office of|national|regional|chairperson|signed|signature|thumbmark|thumb mark|pwd id|this card|holder of this|entitled|accordance|republic act|non.transferable|kagawaran|maynila|pilipinas|makabagong|aksyon|malasakit|bagong pilipinas|valid until|date issued|date of birth|blood type|civil status|address|classification|sex|female|male|atsyn|disability affairs/i;
  const STOPWORDS = new Set(['OF','THE','AND','OR','BY','AT','IN','TO','FOR','WITH','IS','AS','AN','A','DE','DEL','LAS','LOS','SI','NG','SA','ANG','NA','MGA','NI','NY','NO','DI','ITY','ILITY','GAN']);
  const disabilityTypes = ['PSYCHOSOCIAL','VISUAL','HEARING','ORTHOPEDIC','PHYSICAL','MENTAL','INTELLECTUAL','LEARNING','SPEECH','MULTIPLE','RARE DISEASE','CANCER'];

  function looksLikeName(text) {
    if (!text || text.length < 3) return false;
    if (BOILERPLATE.test(text)) return false;
    if (!/^[A-Za-zÑñÃã.\s\-']+$/.test(text)) return false;
    const words = text.trim().split(/\s+/);
    if (words.length < 2 || words.length > 7) return false;
    if (words.some(w => w.length === 1 && !/[A-Z]/.test(w))) return false;
    if (!words.some(w => w.replace(/[^A-Za-zÑñ]/g, '').length >= 3)) return false;
    const nonStop = words.filter(w => !STOPWORDS.has(w.toUpperCase().replace(/[^A-Z]/g, '')));
    if (nonStop.length === 0) return false;
    if (/\bof\s+the\b|\bof\s+\w+\s+(city|province|municipality)\b/i.test(text)) return false;
    return true;
  }

  let id_number = null, idLineY = null;
  for (const line of lines) {
    const match = line.match(/\b\d{2}-\d{4}-\d{3}-\d{7}\b/);
    if (match) { id_number = match[0]; break; }
  }
  if (!id_number) {
    for (const line of lines) {
      const cleaned = line.replace(/[^\d]/g, '');
      if (cleaned.length === 16) {
        id_number = `${cleaned.slice(0,2)}-${cleaned.slice(2,6)}-${cleaned.slice(6,9)}-${cleaned.slice(9)}`;
        break;
      }
    }
  }
  if (id_number) {
    const idDigits = id_number.replace(/\D/g, '');
    const tl = textLines.find(line => line.text.replace(/[^\d]/g, '').includes(idDigits.slice(0, 10)));
    if (tl) idLineY = tl.y;
  }

  let disability_type = null, disabilityLineY = null;
  for (const tl of textLines) {
    const upper = tl.text.toUpperCase();
    const found = disabilityTypes.find(t => upper.includes(t));
    if (found) { disability_type = found; disabilityLineY = tl.y; break; }
  }

  let full_name = null;
  let nameLabelY = null;
  for (const tl of textLines) {
    const t = tl.text.trim().toUpperCase();
    if (t === 'NAME' || t === 'NAME:' || t === "HOLDER'S NAME:" || t === 'NAME OF PWD') { nameLabelY = tl.y; break; }
  }
  if (nameLabelY !== null) {
    let best = null, bestDist = Infinity;
    for (const tl of textLines) {
      if (tl.y >= nameLabelY) continue;
      const dist = nameLabelY - tl.y;
      if (dist < bestDist && dist < pageHeight * 0.18 && looksLikeName(tl.text)) { bestDist = dist; best = tl.text; }
    }
    if (best) full_name = best;
  }
  if (!full_name && nameLabelY !== null) {
    let best = null, bestDist = Infinity;
    for (const tl of textLines) {
      if (tl.y <= nameLabelY) continue;
      const dist = tl.y - nameLabelY;
      if (dist < bestDist && dist < pageHeight * 0.15 && looksLikeName(tl.text)) { bestDist = dist; best = tl.text; }
    }
    if (best) full_name = best;
  }
  if (!full_name && idLineY !== null) {
    let best = null, bestDist = Infinity;
    for (const tl of textLines) {
      if (tl.y <= idLineY) continue;
      const dist = tl.y - idLineY;
      if (dist < bestDist && dist < pageHeight * 0.20 && looksLikeName(tl.text)) { bestDist = dist; best = tl.text; }
    }
    if (best) full_name = best;
  }
  if (!full_name && disabilityLineY !== null) {
    let best = null, bestDist = Infinity;
    for (const tl of textLines) {
      if (tl.y >= disabilityLineY) continue;
      const dist = disabilityLineY - tl.y;
      if (dist < bestDist && dist < pageHeight * 0.20 && looksLikeName(tl.text)) { bestDist = dist; best = tl.text; }
    }
    if (best) full_name = best;
  }
  if (!full_name) {
    const yMin = pageHeight * 0.20, yMax = pageHeight * 0.70;
    const tl = textLines.find(line => line.y >= yMin && line.y <= yMax && looksLikeName(line.text));
    if (tl) full_name = tl.text;
  }

  let birthday = null;
  const datePatterns = [/\b(\d{2}[-\/]\d{2}[-\/]\d{4})\b/, /\b(\d{2}[-\/]\d{2}[-\/]\d{2})\b/, /\b(\d{1,2}[-\/]\d{1,2}[-\/]\d{2,4})\b/];
  for (const line of lines) {
    if (/\d{2}-\d{4}-\d{3}-\d{7}/.test(line)) continue;
    for (const pat of datePatterns) {
      const m = line.match(pat);
      if (m) { birthday = m[1]; break; }
    }
    if (birthday) break;
  }

  if (!id_number) return { success: false, error: 'PWD ID number not found', rawText };
  return { success: true, id_number, full_name, disability_type, birthday, rawText, pageWidth, pageHeight };
}

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

app.use(ssoMiddleware);

app.get('/sso-login', (req, res) => {
  const ssoUrl = process.env.SSO_URL || 'https://sso.server.ubesvr.com';
  const appUrl = process.env.APP_URL || 'https://pwdid.ubesvr.com';
  res.redirect(ssoUrl + '/auth/login?redirect=' + encodeURIComponent(appUrl + '/'));
});

app.get('/auth/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.send(renderLogin(null));
});

app.post('/auth/login', asyncHandler(async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  if (!username || !password) return res.status(400).send(renderLogin('Username and password are required.'));
  const pool = await getPool();

  const local = await pool.request()
    .input('username', sql.NVarChar(100), username)
    .query(`SELECT s.*, b.branch_name, b.branch_code FROM dbo.Staff s LEFT JOIN dbo.Branches b ON s.branch_id = b.id WHERE s.username = @username AND s.is_active = 1`);
  const existing = local.recordset[0];

  if (existing && existing.password_hash) {
    const valid = await bcrypt.compare(password, existing.password_hash);
    if (!valid) return res.status(401).send(renderLogin('Invalid credentials.'));
    req.session.user = { id: existing.id, employee_id: existing.employee_id, username: existing.username, full_name: existing.full_name, role: existing.role, branch_id: existing.branch_id, branch_name: existing.branch_name, branch_code: existing.branch_code };
    await pool.request().input('id', sql.Int, existing.id).query('UPDATE dbo.Staff SET last_login = GETDATE(), updated_at = GETDATE() WHERE id = @id');
    return res.redirect('/');
  }

  const staffResult = await pool.request()
    .input('barcode', sql.NVarChar(100), username)
    .query(`SELECT staff_id, surname, given_names, docket_name FROM [VIP_HO].[dbo].[Staff] WHERE barcode = @barcode AND (inactive IS NULL OR inactive = 0)`);
  if (staffResult.recordset.length === 0) return res.status(401).send(renderLogin('Invalid credentials.'));
  const vipStaff = staffResult.recordset[0];
  const pwdResult = await pool.request()
    .input('staff_id', sql.Int, vipStaff.staff_id)
    .query(`SELECT password FROM [VIP_HO].[dbo].[Security_StaffPasswords] WHERE staff_id = @staff_id AND password IS NOT NULL AND password <> ''`);
  if (pwdResult.recordset.length === 0 || ctaDecrypt(pwdResult.recordset[0].password) !== password) {
    return res.status(401).send(renderLogin('Invalid credentials.'));
  }

  const groups = await pool.request()
    .input('staff_id', sql.Int, vipStaff.staff_id)
    .query(`SELECT sg.group_id, sg.group_name FROM [VIP_HO].[dbo].[Security_StaffGroups] ssg JOIN [VIP_HO].[dbo].[Security_Groups] sg ON ssg.group_id = sg.group_id WHERE ssg.staff_id = @staff_id`);
  let role = 'staff';
  for (const g of groups.recordset) {
    const name = ctaDecrypt(g.group_name || '').toLowerCase();
    if (name === 'administrator' || name === 'admin') { role = 'admin'; break; }
    if (name === 'supervisor') role = 'branch_manager';
    if (name === 'noaccess') return res.status(403).send(renderLogin('Account has no access.'));
  }
  const fullName = [vipStaff.given_names, vipStaff.surname].filter(Boolean).join(' ').trim() || vipStaff.docket_name || username;
  let staffId = existing?.id;
  if (staffId) {
    await pool.request().input('id', sql.Int, staffId).input('full_name', sql.NVarChar(255), fullName).input('role', sql.NVarChar(50), role)
      .query(`UPDATE dbo.Staff SET full_name = @full_name, role = @role, password_hash = '', last_login = GETDATE(), updated_at = GETDATE() WHERE id = @id`);
  } else {
    const ins = await pool.request()
      .input('username', sql.NVarChar(100), username)
      .input('full_name', sql.NVarChar(255), fullName)
      .input('role', sql.NVarChar(50), role)
      .input('emp_id', sql.NVarChar(50), 'VIP-' + vipStaff.staff_id)
      .query(`INSERT INTO dbo.Staff (employee_id, username, password_hash, full_name, role, branch_id) OUTPUT INSERTED.id VALUES (@emp_id, @username, '', @full_name, @role, NULL)`);
    staffId = ins.recordset[0].id;
  }

  req.session.pendingAuth = { staffId, fullName, role, username };
  return res.redirect('/auth/select-branch');
}));

app.get('/auth/select-branch', asyncHandler(async (req, res) => {
  if (!req.session.pendingAuth) return res.redirect('/auth/login');
  const pool = await getPool();
  await syncBranches(pool);
  const branches = await pool.request().query(`SELECT b.id, b.branch_code, b.branch_name, b.address, b.city, ISNULL(p.sorting, 999) AS sorting FROM dbo.Branches b LEFT JOIN [posConfig].[dbo].[posConfig] p ON b.branch_code = p.br_code WHERE b.is_active = 1 ORDER BY ISNULL(p.sorting, 999), b.branch_name`);
  res.send(renderBranchSelect(req.session.pendingAuth, branches.recordset, null));
}));

app.post('/auth/select-branch', asyncHandler(async (req, res) => {
  if (!req.session.pendingAuth) return res.redirect('/auth/login');
  const branchId = Number(req.body?.branch_id || 0);
  const pool = await getPool();
  const branch = await pool.request().input('id', sql.Int, branchId).query('SELECT id, branch_code, branch_name FROM dbo.Branches WHERE id = @id AND is_active = 1');
  if (branch.recordset.length === 0) {
    const branches = await pool.request().query('SELECT id, branch_code, branch_name, address FROM dbo.Branches WHERE is_active = 1 ORDER BY branch_name');
    return res.status(400).send(renderBranchSelect(req.session.pendingAuth, branches.recordset, 'Please select a valid branch.'));
  }
  const pending = req.session.pendingAuth;
  // Upsert Staff record — lookup by barcode, dbo.Staff.id is auto-increment
  const staffRec = await pool.request()
    .input('uname', sql.NVarChar(100), pending.username)
    .query('SELECT id FROM dbo.Staff WHERE username = @uname');
  let localId;
  if (staffRec.recordset.length > 0) {
    localId = staffRec.recordset[0].id;
  } else {
    const ins = await pool.request()
      .input('uname', sql.NVarChar(100), pending.username)
      .input('fname', sql.NVarChar(255), pending.fullName)
      .input('role', sql.NVarChar(50), pending.role)
      .query(`INSERT INTO dbo.Staff (employee_id, username, full_name, role, is_active)
              OUTPUT INSERTED.id VALUES ('SSO-' + @uname, @uname, @fname, @role, 1)`);
    localId = ins.recordset[0].id;
  }
  await pool.request().input('id', sql.Int, localId).input('branch_id', sql.Int, branchId).query('UPDATE dbo.Staff SET branch_id = @branch_id, last_login = GETDATE(), updated_at = GETDATE() WHERE id = @id');
  const b = branch.recordset[0];
  req.session.user = { id: localId, username: pending.username, full_name: pending.fullName, role: pending.role, branch_id: b.id, branch_code: b.branch_code, branch_name: b.branch_name };
  delete req.session.pendingAuth;
  res.redirect('/');
}));

app.get('/auth/logout', (req, res) => { res.clearCookie('sso_token', { domain: '.ubesvr.com', path: '/' }); req.session.destroy(() => res.redirect('/auth/login')); });

app.get('/api/me', requireAuth, (req, res) => res.json({ success: true, user: req.session.user }));

app.get('/', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.get('/health', asyncHandler(async (req, res) => {
  res.json({ ok: true, service: 'pwdid-webapp', time: new Date().toISOString() });
}));

app.post('/test-pwd/lookup', requireAuth, asyncHandler(async (req, res) => {
  const id_number = normalizePwdId(req.body?.id_number || req.body?.id || '');
  const endpoint = process.env.PUPPETEER_URL || 'http://192.168.111.112:3000/pwdid/doh-lookup';
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), Number(process.env.PUPPETEER_TIMEOUT_MS || 30000));
  try {
    const r = await fetch(endpoint, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id_number }), signal: ac.signal
    });
    const text = await r.text();
    let payload;
    try { payload = JSON.parse(text); } catch { payload = { ok: false, raw: text }; }
    if (payload && payload.status === 'blocked') {
      payload.note = 'DOH/Cloudflare blocked the browser request. This app does not bypass Cloudflare.';
    }
    res.status(r.ok ? 200 : 502).json(payload);
  } finally { clearTimeout(t); }
}));

app.post('/pwd-ocr-upload', requireAuth, asyncHandler(async (req, res) => {
  const dataUrl = req.body?.dataUrl;
  if (!dataUrl) return res.status(400).json({ success: false, error: 'Missing image data' });
  const m = String(dataUrl).match(/^data:(.+);base64,(.+)$/);
  if (!m) return res.status(400).json({ success: false, error: 'Invalid image format' });
  if (!process.env.GOOGLE_VISION_API_KEY) return res.status(500).json({ success: false, error: 'GOOGLE_VISION_API_KEY is not configured' });

  const googlePayload = {
    requests: [{
      image: { content: m[2] },
      features: [{ type: 'TEXT_DETECTION', maxResults: 10 }],
      imageContext: { languageHints: ['en'] }
    }]
  };
  const r = await fetch(`https://vision.googleapis.com/v1/images:annotate?key=${encodeURIComponent(process.env.GOOGLE_VISION_API_KEY)}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(googlePayload)
  });
  const googleResult = await r.json();
  const extracted = parseGoogleVisionResult(googleResult);

  // Best-effort temp log, same as the Node-RED flow. Failure should not break OCR response.
  getPool().then(pool => pool.request()
    .input('id_number', sql.VarChar(50), extracted.id_number || null)
    .input('full_name', sql.NVarChar(255), extracted.full_name || null)
    .input('disability_type', sql.NVarChar(100), extracted.disability_type || null)
    .input('fulltext', sql.NVarChar(sql.MAX), extracted.rawText || '')
    .query(`IF OBJECT_ID('dbo.PWD_OCR_Temp','U') IS NOT NULL
            INSERT INTO dbo.PWD_OCR_Temp (id_number, full_name, disability_type, scanned_at, fulltext)
            VALUES (@id_number, @full_name, @disability_type, GETDATE(), @fulltext)`)
  ).catch(e => console.warn('PWD_OCR_Temp log skipped:', e.message));

  res.status(extracted.success ? 200 : 422).json(extracted);
}));

app.post('/pwdid/lookup', requireAuth, asyncHandler(async (req, res) => {
  const idNumber = normalizePwdId(req.body?.id_number || req.body?.id || '');
  const pool = await getPool();
  const result = await pool.request()
    .input('id_number', sql.VarChar(50), idNumber)
    .query(`SELECT id, id_number, last_name, first_name, middle_name,
                   CONVERT(VARCHAR, birthday, 23) AS birthday,
                   sex, doh_status,
                   CONVERT(VARCHAR, id_valid_until, 23) AS id_valid_until,
                   encoded_by, verified_doh, fullname, disability, rawdecode,
                   encoded_by_username, encoded_by_full_name, branch_code, branch_name,
                   CONVERT(VARCHAR, created_at, 120) AS created_at,
                   CONVERT(VARCHAR, updated_at, 120) AS updated_at
            FROM dbo.PWDID
            WHERE id_number = @id_number`);
  const rows = result.recordset || [];
  if (rows.length === 0) return res.json({ found: false });
  const r = rows[0];
  let expired = false, near_expiry = false;
  if (r.id_valid_until) {
    const validUntil = new Date(r.id_valid_until + 'T00:00:00');
    const today = new Date(); today.setHours(0,0,0,0);
    expired = today > validUntil;
    if (!expired) {
      const daysLeft = Math.floor((validUntil - today) / 86400000);
      near_expiry = daysLeft <= 90;
      r.days_until_expiry = daysLeft;
    }
  }
  const dohInactive = r.doh_status && /inactive|expired|cancelled|revoked/i.test(r.doh_status);
  res.json({ found: true, expired: expired || !!dohInactive, near_expiry, record: r });
}));

app.post('/pwdid/save', requireAuth, asyncHandler(async (req, res) => {
  const p = req.body || {};
  const idNumber = normalizePwdId(p.id_number || '');
  if (!p.last_name || !p.first_name) return res.status(400).json({ success: false, error: 'id_number, last_name, first_name are required' });
  const pool = await getPool();
  const user = req.session.user;
  const encodedBy = user.full_name || user.username || '';
  await pool.request()
    .input('id_number', sql.VarChar(50), idNumber)
    .input('last_name', sql.NVarChar(100), p.last_name || '')
    .input('first_name', sql.NVarChar(100), p.first_name || '')
    .input('middle_name', sql.NVarChar(100), p.middle_name || '')
    .input('birthday', sql.Date, p.birthday || null)
    .input('sex', sql.VarChar(10), p.sex || '')
    .input('doh_status', sql.NVarChar(100), p.doh_status || '')
    .input('id_valid_until', sql.Date, p.id_valid_until || null)
    .input('encoded_by', sql.NVarChar(100), encodedBy)
    .input('encoded_by_user_id', sql.Int, user.id || null)
    .input('encoded_by_username', sql.NVarChar(100), user.username || '')
    .input('encoded_by_full_name', sql.NVarChar(255), user.full_name || '')
    .input('branch_id', sql.Int, user.branch_id || null)
    .input('branch_code', sql.NVarChar(50), user.branch_code || '')
    .input('branch_name', sql.NVarChar(255), user.branch_name || '')
    .input('verified_doh', sql.Bit, p.verified_doh ? 1 : 0)
    .input('fullname', sql.NVarChar(255), p.fullname || null)
    .input('disability', sql.NVarChar(100), p.disability || null)
    .input('rawdecode', sql.NVarChar(sql.MAX), p.rawdecode || null)
    .query(`MERGE dbo.PWDID AS target
            USING (SELECT @id_number AS id_number) AS source
            ON target.id_number = source.id_number
            WHEN MATCHED THEN UPDATE SET
              last_name=@last_name, first_name=@first_name, middle_name=@middle_name,
              birthday=@birthday, sex=@sex, doh_status=@doh_status, id_valid_until=@id_valid_until,
              encoded_by=@encoded_by, encoded_by_user_id=@encoded_by_user_id, encoded_by_username=@encoded_by_username,
              encoded_by_full_name=@encoded_by_full_name, branch_id=@branch_id, branch_code=@branch_code, branch_name=@branch_name,
              verified_doh=@verified_doh, fullname=@fullname, disability=@disability, rawdecode=@rawdecode, saved_from_app='pwdid-webapp', updated_at=GETDATE()
            WHEN NOT MATCHED THEN INSERT
              (id_number,last_name,first_name,middle_name,birthday,sex,doh_status,id_valid_until,encoded_by,encoded_by_user_id,encoded_by_username,encoded_by_full_name,branch_id,branch_code,branch_name,verified_doh,fullname,disability,rawdecode,saved_from_app)
              VALUES
              (@id_number,@last_name,@first_name,@middle_name,@birthday,@sex,@doh_status,@id_valid_until,@encoded_by,@encoded_by_user_id,@encoded_by_username,@encoded_by_full_name,@branch_id,@branch_code,@branch_name,@verified_doh,@fullname,@disability,@rawdecode,'pwdid-webapp');`);
  await pool.request()
    .input('pwd_id_number', sql.VarChar(50), idNumber)
    .input('staff_id', sql.Int, user.id || null)
    .input('username', sql.NVarChar(100), user.username || '')
    .input('full_name', sql.NVarChar(255), user.full_name || '')
    .input('branch_id', sql.Int, user.branch_id || null)
    .input('branch_code', sql.NVarChar(50), user.branch_code || '')
    .input('branch_name', sql.NVarChar(255), user.branch_name || '')
    .input('ip_address', sql.NVarChar(80), req.ip || '')
    .query(`INSERT INTO dbo.PWDID_Audit (pwd_id_number, action, staff_id, username, full_name, branch_id, branch_code, branch_name, ip_address)
            VALUES (@pwd_id_number, 'save', @staff_id, @username, @full_name, @branch_id, @branch_code, @branch_name, @ip_address)`);
  res.json({ success: true, message: `Record saved successfully by ${encodedBy} at ${user.branch_name || 'selected branch'}.` });
}));

app.get('/pwdid/list', requireAuth, asyncHandler(async (req, res) => {
  const search = String(req.query.search || '').trim();
  const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
  const pageSize = Math.min(Math.max(parseInt(req.query.pageSize, 10) || 50, 1), 200);
  const offset = (page - 1) * pageSize;
  const pool = await getPool();
  const request = pool.request().input('offset', sql.Int, offset).input('pageSize', sql.Int, pageSize);
  let where = '';
  if (search) {
    request.input('search', sql.NVarChar(100), `%${search}%`);
    where = `WHERE id_number LIKE @search OR last_name LIKE @search OR first_name LIKE @search OR fullname LIKE @search`;
  }
  const result = await request.query(`SELECT id, id_number, last_name, first_name, middle_name,
           CONVERT(VARCHAR, birthday, 107) AS birthday, sex, doh_status,
           CONVERT(VARCHAR, id_valid_until, 107) AS id_valid_until,
           CASE WHEN id_valid_until IS NULL THEN 'Unknown'
                WHEN id_valid_until < CAST(GETDATE() AS DATE) THEN 'Expired'
                ELSE 'Valid' END AS expiry_status,
           encoded_by, fullname, disability, rawdecode,
           encoded_by_username, encoded_by_full_name, branch_code, branch_name,
           CONVERT(VARCHAR, created_at, 120) AS created_at,
           CONVERT(VARCHAR, updated_at, 120) AS updated_at
      FROM dbo.PWDID
      ${where}
      ORDER BY updated_at DESC
      OFFSET @offset ROWS FETCH NEXT @pageSize ROWS ONLY`);
  res.json({ success: true, page, pageSize, count: result.recordset.length, records: result.recordset });
}));

app.get('/pwdid/stats', requireAuth, asyncHandler(async (req, res) => {
  const pool = await getPool();
  const result = await pool.request().query(`SELECT COUNT(*) AS total,
      SUM(CASE WHEN id_valid_until >= CAST(GETDATE() AS DATE) THEN 1 ELSE 0 END) AS valid,
      SUM(CASE WHEN id_valid_until < CAST(GETDATE() AS DATE) THEN 1 ELSE 0 END) AS expired,
      SUM(CASE WHEN id_valid_until IS NULL THEN 1 ELSE 0 END) AS unknown,
      SUM(CASE WHEN verified_doh = 1 THEN 1 ELSE 0 END) AS doh_verified
    FROM dbo.PWDID`);
  const r = result.recordset[0] || {};
  res.json({ success: true, total: r.total || 0, valid: r.valid || 0, expired: r.expired || 0, unknown: r.unknown || 0, doh_verified: r.doh_verified || 0 });
}));

app.use(requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.use((err, req, res, next) => {
  console.error(err);
  const status = err.statusCode || 500;
  res.status(status).json({ success: false, ok: false, error: err.message || 'Server error', details: err.details });
});

const server = app.listen(PORT, () => console.log(`PWD ID standalone web app listening on http://0.0.0.0:${PORT}`));

process.on('SIGINT', async () => { server.close(); try { await sql.close(); } catch {} process.exit(0); });
process.on('SIGTERM', async () => { server.close(); try { await sql.close(); } catch {} process.exit(0); });

module.exports = { app, parseGoogleVisionResult, normalizePwdId };
