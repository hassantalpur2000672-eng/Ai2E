// ============================================
// Ai2E — Cloudflare Pages Function  (OPTIMIZED v3)
// Database: Turso (LibSQL)
//
// DB READ/WRITE OPTIMIZATIONS:
//  1. tursoBatch() — multiple stmts in 1 HTTP pipeline call
//     (replaces multiple sequential await dbRun/dbFirst calls)
//  2. /api/mine/start  — 2 writes → 1 batch
//  3. /api/mine/claim  — user+tx+session+referral writes → 1 batch
//     (mining timer runs on FRONTEND; NO per-second DB writes)
//  4. /api/tasks       — tasks+done in 1 batch (2 reads → 1 call)
//  5. /api/tasks/complete — 3 writes → 1 batch
//  6. /api/me          — COUNT+UPDATE with sub-query (no extra read)
//  7. /api/stats       — 2 aggregates → 1 batch
//  8. /api/admin/dashboard — 4 aggregates → 1 batch
//  9. /api/admin/settings  — N updates → 1 batch
// 10. /api/auth/login-full — user+settings+tasks+done in 1 response
//     Frontend uses this on first load; caches 3 min locally.
// ============================================

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// ── Database: Turso Batch Pipeline ───────
// stmts = [{ sql, args }, ...]  → 1 HTTP call for ALL statements
async function tursoBatch(env, stmts) {
  const url = env.TURSO_URL.replace('libsql://', 'https://');
  const requests = stmts.map(s => ({
    type: 'execute',
    stmt: {
      sql: s.sql,
      args: (s.args || []).map(v => {
        if (v === null || v === undefined) return { type: 'null' };
        if (typeof v === 'number') return { type: 'integer', value: String(v) };
        return { type: 'text', value: String(v) };
      })
    }
  }));
  requests.push({ type: 'close' });

  const res = await fetch(`${url}/v2/pipeline`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.TURSO_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ requests })
  });
  const data = await res.json();

  // Return array of result-sets, one per statement
  return (data.results || [])
    .filter(r => r.type !== 'error' && r.response?.result)
    .map(r => {
      const result = r.response.result;
      const cols = result.cols.map(c => c.name);
      return result.rows.map(row => {
        const obj = {};
        cols.forEach((col, i) => { obj[col] = row[i]?.value ?? null; });
        return obj;
      });
    });
}

// Single-statement helpers (thin wrappers, backward-compatible)
async function dbFirst(env, sql, args = []) {
  const [rows] = await tursoBatch(env, [{ sql, args }]);
  return (rows && rows[0]) || null;
}
async function dbAll(env, sql, args = []) {
  const [rows] = await tursoBatch(env, [{ sql, args }]);
  return rows || [];
}
async function dbRun(env, sql, args = []) {
  await tursoBatch(env, [{ sql, args }]);
}

// ── Token helpers (JWT-like) ─────────────
async function makeToken(userId, env) {
  const data = JSON.stringify({ id: userId, ts: Date.now() });
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return btoa(data) + '.' + sigB64;
}

async function verifyToken(token, env) {
  try {
    const [dataB64, sigB64] = token.split('.');
    const data = atob(dataB64);
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sig = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(data));
    if (!valid) return null;
    const parsed = JSON.parse(data);
    if (Date.now() - parsed.ts > 30 * 24 * 60 * 60 * 1000) return null; // 30 days
    return parsed;
  } catch { return null; }
}

// ── Password hashing (NEW: PBKDF2, per-user random salt, max 100k iter) ─
async function legacyHash(password) {
  // Old method (for migration only)
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + 'AI2E_SALT_2025'));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16)); // 16-byte random salt
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },  // Cloudflare limit
    keyMaterial, 256
  );
  const hashArray = Array.from(new Uint8Array(derived));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${saltHex}:${hashHex}`;
}

async function verifyPassword(password, storedHash) {
  if (!storedHash) return false;
  // Check if old format (no colon)
  if (!storedHash.includes(':')) {
    const old = await legacyHash(password);
    return old === storedHash;
  }
  // New format: salt:hash
  const [saltHex, hashHex] = storedHash.split(':');
  if (!saltHex || !hashHex) return false;
  const encoder = new TextEncoder();
  const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },  // Cloudflare limit
    keyMaterial, 256
  );
  const newHash = Array.from(new Uint8Array(derived))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  return newHash === hashHex;
}

// ── Utilities ────────────────────────────
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
}
function err(msg, status = 400) {
  return json({ error: msg }, status);
}
async function getUser(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  const parsed = await verifyToken(token, env);
  if (!parsed) return null;
  return await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [parsed.id]);
}

// ============================================
export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  const url = new URL(request.url);
  const path = url.pathname;

  try {
    // ── AUTH ──────────────────────────────────────
    if (path === '/api/auth/register' && request.method === 'POST') {
      const { username, email, password, ref_code, security_question, security_answer } = await request.json();
      if (!username || !email || !password) return err('All fields required');
      if (password.length < 6) return err('Password min 6 chars');

      const emailNorm    = email.toLowerCase().trim();
      const usernameNorm = username.toLowerCase().trim();

      // BATCH READ: email + username + welcome_bonus + refUser — 1 pipeline call
      const checkStmts = [
        { sql: 'SELECT id FROM users WHERE LOWER(email) = ?',   args: [emailNorm] },
        { sql: 'SELECT id FROM users WHERE username = ?',        args: [usernameNorm] },
        { sql: "SELECT value FROM settings WHERE key = 'welcome_bonus'" },
      ];
      if (ref_code) checkStmts.push({ sql: 'SELECT id FROM users WHERE referral_code = ?', args: [ref_code.toUpperCase()] });

      const checkResults = await tursoBatch(env, checkStmts);
      const emailRow = checkResults[0]?.[0];
      const uRow     = checkResults[1]?.[0];
      const cfgRow   = checkResults[2]?.[0];
      const refUser  = ref_code ? checkResults[3]?.[0] : null;

      if (emailRow) return err('Email already registered');
      if (uRow)     return err('Username taken');

      const bonus  = parseInt(cfgRow?.value || '1000');
      const hashed = await hashPassword(password);
      const myRef  = 'AI2E' + Math.random().toString(36).substr(2, 6).toUpperCase();
      const id     = crypto.randomUUID();

      // BATCH WRITE: user + welcome tx + ref count — 1 pipeline call
      const writeStmts = [
        {
          sql: "INSERT INTO users (id,username,email,password_hash,referral_code,referred_by,points,total_mined,mining_power,login_method,mining_claimed,security_question,security_answer,created_at) VALUES (?,?,?,?,?,?,?,0,1.0,'email',1,?,?,datetime('now'))",
          args: [id, usernameNorm, emailNorm, hashed, myRef,
                 ref_code ? ref_code.toUpperCase() : null,
                 bonus, security_question||null, security_answer||null]
        },
        {
          sql: "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
          args: [crypto.randomUUID(), id, 'welcome_bonus', bonus, '🎉 Welcome bonus']
        },
      ];
      if (refUser && refUser.id !== id) {
        writeStmts.push({ sql: 'UPDATE users SET referral_count=referral_count+1 WHERE id=?', args: [refUser.id] });
        writeStmts.push({ sql: "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", args: [crypto.randomUUID(), refUser.id, 'referral_bonus', 0, '👥 New referral: @'+usernameNorm] });
      }
      await tursoBatch(env, writeStmts);

      // Return user + settings + tasks + leaderboard in 1 batch
      const token = await makeToken(id, env);
      const [userRows, settingsRows, tasksRows, lbRows] = await tursoBatch(env, [
        { sql: 'SELECT * FROM users WHERE id=?', args: [id] },
        { sql: 'SELECT key, value FROM settings' },
        { sql: 'SELECT * FROM tasks WHERE is_active=1 ORDER BY display_order' },
        { sql: `SELECT u.username, u.wallet_address, u.wallet_type,
                        u.points AS total_points, u.total_mined, u.mining_power,
                        (SELECT COUNT(*) FROM users r WHERE r.referred_by=u.referral_code) AS total_referrals,
                        (SELECT COUNT(*) FROM users r WHERE r.referred_by=u.referral_code AND r.total_mined>0) AS active_referrals
                 FROM users u WHERE u.points>0 ORDER BY u.points DESC LIMIT 25` }
      ]);
      const newUser  = userRows?.[0] || null;
      const settings = {};
      (settingsRows || []).forEach(r => { settings[r.key] = r.value; });
      return json({ token, user: newUser, settings, tasks: tasksRows||[], done: [], leaderboard: lbRows||[] });
    }

    if (path === '/api/auth/login' && request.method === 'POST') {
      const { email, password } = await request.json();
      if (!email || !password) return err('Email and password required');
      const emailNorm = email.toLowerCase().trim();
      // 1 read only
      const user = await dbFirst(env, 'SELECT * FROM users WHERE LOWER(email) = ?', [emailNorm]);
      if (!user) return err('Wrong email or password');
      if (user.is_banned == 1) return err('Account banned');
      const valid = await verifyPassword(password, user.password_hash);
      if (!valid) return err('Wrong email or password');
      // Hash upgrade: fire-and-forget, doesn't block response
      if (!user.password_hash.includes(':')) hashPassword(password).then(h => dbRun(env,'UPDATE users SET password_hash=? WHERE id=?',[h,user.id]));
      const token = await makeToken(user.id, env);
      return json({ token, user });
    }


    // ── LOGIN-FULL — OPTIMIZATION #4 ─────────────────────────────────────────
    // Frontend ek call mein user + settings + tasks + done-list pata kare.
    // Replaces 4 separate fetches with 1 call. Frontend 3 min cache kare.
    // Usage: POST /api/auth/login-full  { email, password }
    // Returns: { token, user, settings, tasks, done }
    if (path === '/api/auth/login-full' && request.method === 'POST') {
      const { email, password } = await request.json();
      if (!email || !password) return err('Email and password required');
      const emailNorm = email.toLowerCase().trim();

      // 1 read for user, then 1 batch for settings+tasks+done
      const user = await dbFirst(env, 'SELECT * FROM users WHERE LOWER(email) = ?', [emailNorm]);
      if (!user) return err('Wrong email or password');
      if (user.is_banned == 1) return err('Account banned');
      const valid = await verifyPassword(password, user.password_hash);
      if (!valid) return err('Wrong email or password');
      if (!user.password_hash.includes(':')) hashPassword(password).then(h => dbRun(env,'UPDATE users SET password_hash=? WHERE id=?',[h,user.id]));
      // leaderboard piggybacked — same batch, zero extra HTTP call
      const [settingsRows, tasksRows, doneRows, lbRows] = await tursoBatch(env, [
        { sql: 'SELECT key, value FROM settings' },
        { sql: 'SELECT * FROM tasks WHERE is_active = 1 ORDER BY display_order' },
        { sql: 'SELECT task_id FROM user_tasks WHERE user_id = ?', args: [user.id] },
        { sql: `SELECT u.username, u.wallet_address, u.wallet_type,
                        u.points AS total_points, u.total_mined, u.mining_power,
                        (SELECT COUNT(*) FROM users r WHERE r.referred_by=u.referral_code) AS total_referrals,
                        (SELECT COUNT(*) FROM users r WHERE r.referred_by=u.referral_code AND r.total_mined>0) AS active_referrals
                 FROM users u WHERE u.points>0 ORDER BY u.points DESC LIMIT 25` }
      ]);
      const settings = {};
      (settingsRows || []).forEach(r => { settings[r.key] = r.value; });
      const token = await makeToken(user.id, env);
      return json({ token, user, settings, tasks: tasksRows||[], done: (doneRows||[]).map(d=>d.task_id), leaderboard: lbRows||[] });
    }

    if (path === '/api/auth/wallet' && request.method === 'POST') {
      const { wallet_address, wallet_type, ref_code } = await request.json();
      if (!wallet_address) return err('Wallet address required');
      const addr = wallet_address.toLowerCase();
      let user = await dbFirst(env, 'SELECT * FROM users WHERE wallet_address = ?', [addr]);

      if (!user) {
        const id       = crypto.randomUUID();
        const username = 'w_' + wallet_address.slice(2, 10).toLowerCase();
        const myRef    = 'AI2E' + Math.random().toString(36).substr(2,6).toUpperCase();
        // BATCH READ: welcome_bonus + refUser in 1 call
        const readStmts = [{ sql: "SELECT value FROM settings WHERE key='welcome_bonus'" }];
        if (ref_code) readStmts.push({ sql: 'SELECT id FROM users WHERE referral_code=?', args: [ref_code.toUpperCase()] });
        const readRes = await tursoBatch(env, readStmts);
        const bonus   = parseInt(readRes[0]?.[0]?.value || '1000');
        const refUser = ref_code ? readRes[1]?.[0] : null;
        // BATCH WRITE: insert + welcome tx + ref count — 1 call
        const wStmts = [
          { sql: "INSERT INTO users (id,username,wallet_address,wallet_type,referral_code,referred_by,points,total_mined,mining_power,login_method,mining_claimed,created_at) VALUES (?,?,?,?,?,?,?,0,1.0,?,1,datetime('now'))", args: [id,username,addr,wallet_type||'web3',myRef,ref_code?.toUpperCase()||null,bonus,wallet_type||'wallet'] },
          { sql: "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", args: [crypto.randomUUID(),id,'welcome_bonus',bonus,'🎉 Welcome bonus'] },
        ];
        if (refUser) {
          wStmts.push({ sql:'UPDATE users SET referral_count=referral_count+1 WHERE id=?', args:[refUser.id] });
          wStmts.push({ sql:"INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", args:[crypto.randomUUID(),refUser.id,'referral_bonus',0,'👥 New wallet referral'] });
        }
        // Fetch new user in same batch as writes (piggyback SELECT)
        const [,, freshRows] = await tursoBatch(env, [...wStmts, { sql:'SELECT * FROM users WHERE id=?', args:[id] }]);
        user = freshRows?.[0] || null;
      }
      if (!user || user.is_banned==1) return err('Account banned');
      const token = await makeToken(user.id, env);
      return json({ token, user });
    }

    // ── FORGOT PASSWORD CHECK ─────────────────────
    if (path === '/api/auth/forgot-check' && request.method === 'POST') {
      const { email } = await request.json();
      if (!email) return err('Email required');
      const user = await dbFirst(env, 'SELECT id, security_question FROM users WHERE LOWER(email) = ?', [email.toLowerCase().trim()]);
      if (!user) return err('Is email pe koi account nahi mila');
      return json({ ok: true, security_question: user.security_question || null });
    }

    // ── FORGOT PASSWORD REQUEST ────────────────────
    if (path === '/api/auth/forgot-password' && request.method === 'POST') {
      const { email, answer, question, new_password } = await request.json();
      if (!email || !answer) return err('Email and answer required');
      if (!new_password || new_password.length < 6) return err('New password min 6 characters');
      const emailNorm = email.toLowerCase().trim();
      // BATCH READ: user + existing reset in 1 call
      const [userRows, existingRows] = await tursoBatch(env, [
        { sql: 'SELECT id,username FROM users WHERE LOWER(email)=?', args: [emailNorm] },
        { sql: "SELECT id FROM password_resets WHERE email=? AND status='pending'", args: [emailNorm] }
      ]);
      const user = userRows?.[0];
      if (!user) return err('Account not found');
      if (existingRows?.[0]) return err('Reset request already pending. Admin will review soon.');
      const hashedNew = await hashPassword(new_password);
      await dbRun(env,
        "INSERT INTO password_resets (id,user_id,username,email,verify_question,verify_answer,new_password_hash,status,created_at) VALUES (?,?,?,?,?,?,?,'pending',datetime('now'))",
        [crypto.randomUUID(), user.id, user.username, emailNorm, question||'', answer, hashedNew]
      );
      return json({ ok: true });
    }

    // ── SUPPORT: USER SEND MESSAGE (1 per 24h) ────
    if (path === '/api/support/send' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { message } = await request.json();
      if (!message || message.trim().length < 5) return err('Message bahut chota hai');
      const last = await dbFirst(env, "SELECT id FROM support_messages WHERE user_id = ? AND created_at > datetime('now','-24 hours')", [user.id]);
      if (last) return err('24 ghante mein sirf 1 message bhej sakte hain');
      await dbRun(env,
        "INSERT INTO support_messages (id,user_id,username,email,message,status,created_at) VALUES (?,?,?,?,?,'open',datetime('now'))",
        [crypto.randomUUID(), user.id, user.username, user.email||'', message.trim()]
      );
      return json({ ok: true });
    }

    // ── SUPPORT: USER GET OWN MESSAGES ────────────
    if (path === '/api/support/my-messages' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const msgs = await dbAll(env, 'SELECT * FROM support_messages WHERE user_id = ? ORDER BY created_at DESC LIMIT 10', [user.id]);
      return json(msgs);
    }

    // ── ADMIN: SUPPORT MESSAGES ───────────────────
    if (path === '/api/admin/support' && request.method === 'GET') {
      const k = request.headers.get('X-Admin-Key');
      if (k !== (env.ADMIN_KEY||'Admin@2026')) return err('Forbidden',403);
      return json({ messages: await dbAll(env, 'SELECT * FROM support_messages ORDER BY created_at DESC LIMIT 100') });
    }

    if (path === '/api/admin/support/reply' && request.method === 'POST') {
      const k = request.headers.get('X-Admin-Key');
      if (k !== (env.ADMIN_KEY||'Admin@2026')) return err('Forbidden',403);
      const { msg_id, reply } = await request.json();
      await dbRun(env, "UPDATE support_messages SET admin_reply=?,status='replied',replied_at=datetime('now') WHERE id=?", [reply, msg_id]);
      return json({ ok: true });
    }

    if (path === '/api/admin/support/close' && request.method === 'POST') {
      const k = request.headers.get('X-Admin-Key');
      if (k !== (env.ADMIN_KEY||'Admin@2026')) return err('Forbidden',403);
      const { msg_id } = await request.json();
      await dbRun(env, "UPDATE support_messages SET status='closed' WHERE id=?", [msg_id]);
      return json({ ok: true });
    }

    // ── ADMIN: RESET REQUESTS ─────────────────────
    if (path === '/api/admin/reset-requests' && request.method === 'GET') {
      const k = request.headers.get('X-Admin-Key');
      if (k !== (env.ADMIN_KEY||'Admin@2026')) return err('Forbidden',403);
      return json({ requests: await dbAll(env, "SELECT * FROM password_resets ORDER BY created_at DESC LIMIT 50") });
    }

    if (path === '/api/admin/reset-approve' && request.method === 'POST') {
      const k = request.headers.get('X-Admin-Key');
      if (k !== (env.ADMIN_KEY||'Admin@2026')) return err('Forbidden',403);
      const { reset_id, new_password } = await request.json();
      if (!reset_id) return err('Invalid');
      const reset = await dbFirst(env, 'SELECT * FROM password_resets WHERE id=?', [reset_id]);
      if (!reset) return err('Request nahi mili');
      const pwHash = reset.new_password_hash || await hashPassword('reset123');
      await dbRun(env, 'UPDATE users SET password_hash=? WHERE id=?', [pwHash, reset.user_id]);
      await dbRun(env, "UPDATE password_resets SET status='approved',resolved_at=datetime('now') WHERE id=?", [reset_id]);
      return json({ ok: true });
    }

    if (path === '/api/admin/reset-reject' && request.method === 'POST') {
      const k = request.headers.get('X-Admin-Key');
      if (k !== (env.ADMIN_KEY||'Admin@2026')) return err('Forbidden',403);
      const { reset_id } = await request.json();
      await dbRun(env, "UPDATE password_resets SET status='rejected',resolved_at=datetime('now') WHERE id=?", [reset_id]);
      return json({ ok: true });
    }

    // ── USER ──────────────────────────────────────
    if (path === '/api/me' && request.method === 'GET') {
      // OPTIMIZATION #4: COUNT + UPDATE in 1 batch call (no separate read)
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      // 1 batch: update active_referral_count, then return user via RETURNING-style trick
      // SQLite doesn't support RETURNING in libsql batch, so we do 2 stmts in 1 call
      const [, freshRows] = await tursoBatch(env, [
        { sql: "UPDATE users SET active_referral_count=(SELECT COUNT(*) FROM users WHERE referred_by=? AND total_mined>0) WHERE id=?", args: [user.referral_code, user.id] },
        { sql: 'SELECT * FROM users WHERE id=?', args: [user.id] }
      ]);
      return json(freshRows?.[0] || user);
    }

    if (path === '/api/mine/start' && request.method === 'POST') {
      // OPTIMIZATION #1: 2 writes → 1 batch call
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      if (user.mining_claimed != 1) return err('Already mining');
      const now = new Date().toISOString();
      await tursoBatch(env, [
        { sql: "UPDATE users SET last_mining_start = ?, mining_claimed = 0 WHERE id = ?", args: [now, user.id] },
        { sql: "INSERT INTO mining_sessions (id,user_id,started_at,mining_power) VALUES (?,?,?,?)", args: [crypto.randomUUID(), user.id, now, user.mining_power] }
      ]);
      return json({ success: true, started_at: now });
    }

    if (path === '/api/mine/claim' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      if (user.mining_claimed == 1) return err('Nothing to claim');

      const cfgRows = await dbAll(env, "SELECT key, value FROM settings WHERE key IN ('mining_duration_hours','mining_coins_per_hour')");
      const cfgMap = {};
      cfgRows.forEach(r => cfgMap[r.key] = r.value);
      const durMs = parseInt(cfgMap.mining_duration_hours || '24') * 3600000;
      const cpm = parseFloat(cfgMap.mining_coins_per_hour || '10') * parseFloat(user.mining_power) / 3600000;
      const start = new Date(user.last_mining_start).getTime();
      const elapsed = Math.min(Date.now() - start, durMs);
      const earned = Math.floor(cpm * elapsed);

      if (earned < 100) return err('Mine at least 100 points first');

      const newPts   = parseInt(user.points || 0) + earned;
      const newMined = parseInt(user.total_mined || 0) + earned;

      // ── OPTIMIZATION #2: Build all stmts first, send ONE batch call ──
      const claimStmts = [
        // 1. Update user balance + mark claimed
        {
          sql: 'UPDATE users SET points = ?, total_mined = ?, total_claimed = total_claimed + ?, mining_claimed = 1 WHERE id = ?',
          args: [newPts, newMined, earned, user.id]
        },
        // 2. Transaction record
        {
          sql: "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
          args: [crypto.randomUUID(), user.id, 'mining_claim', earned, '⛏️ Mining claim']
        },
        // 3. Close mining session
        {
          sql: "UPDATE mining_sessions SET claimed_at = datetime('now'), coins_earned = ?, is_claimed = 1 WHERE user_id = ? AND is_claimed = 0",
          args: [earned, user.id]
        },
        // 4. Refresh active_referral_count in same batch (no extra round-trip)
        {
          sql: "UPDATE users SET active_referral_count = (SELECT COUNT(*) FROM users WHERE referred_by = ? AND total_mined > 0) WHERE id = ?",
          args: [user.referral_code, user.id]
        }
      ];

      // ── OPTIMIZATION #3: Referral bonuses collected into same batch ──
      // We still need 1-3 reads to get L1/L2/L3 ids (unavoidable without
      // schema change), but all the bonus WRITES join the batch above.
      if (user.referred_by) {
        const L1 = await dbFirst(env, 'SELECT id, username, referred_by FROM users WHERE referral_code = ?', [user.referred_by]);
        if (L1) {
          const l1Bonus = Math.floor(earned * 0.50);
          if (l1Bonus > 0) {
            claimStmts.push({ sql: 'UPDATE users SET points = points + ? WHERE id = ?', args: [l1Bonus, L1.id] });
            claimStmts.push({ sql: "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", args: [crypto.randomUUID(), L1.id, 'refer_mining_l1', l1Bonus, '⛏️ L1 50%: @' + user.username] });
          }
          if (L1.referred_by) {
            const L2 = await dbFirst(env, 'SELECT id, username, referred_by FROM users WHERE referral_code = ?', [L1.referred_by]);
            if (L2) {
              const l2Bonus = Math.floor(earned * 0.25);
              if (l2Bonus > 0) {
                claimStmts.push({ sql: 'UPDATE users SET points = points + ? WHERE id = ?', args: [l2Bonus, L2.id] });
                claimStmts.push({ sql: "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", args: [crypto.randomUUID(), L2.id, 'refer_mining_l2', l2Bonus, '🌿 L2 25%: @' + user.username] });
              }
              if (L2.referred_by) {
                const L3 = await dbFirst(env, 'SELECT id, username FROM users WHERE referral_code = ?', [L2.referred_by]);
                if (L3) {
                  const l3Bonus = Math.floor(earned * 0.10);
                  if (l3Bonus > 0) {
                    claimStmts.push({ sql: 'UPDATE users SET points = points + ? WHERE id = ?', args: [l3Bonus, L3.id] });
                    claimStmts.push({ sql: "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", args: [crypto.randomUUID(), L3.id, 'refer_mining_l3', l3Bonus, '🔥 L3 10%: @' + user.username] });
                  }
                }
              }
            }
          }
        }
      }

      // Single pipeline call — all writes atomic
      await tursoBatch(env, claimStmts);
      return json({ success: true, earned });
    }

    // ── /api/mine/claim-all — mine + pending tasks + auto-restart ────────
    // Frontend sends pending_task_ids[] earned locally since last claim.
    // Server validates tasks (not already done), awards pts, saves txs,
    // pays referral bonuses, auto-restarts mining — ALL in 1 batch call.
    if (path === '/api/mine/claim-all' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      if (user.mining_claimed == 1) return err('Nothing to claim');

      const cfgRows = await dbAll(env,
        "SELECT key,value FROM settings WHERE key IN ('mining_duration_hours','mining_coins_per_hour')"
      );
      const cfgMap = {};
      cfgRows.forEach(r => { cfgMap[r.key] = r.value; });

      const durMs   = parseInt(cfgMap.mining_duration_hours  || '24') * 3600000;
      const cpm     = parseFloat(cfgMap.mining_coins_per_hour || '10')
                      * parseFloat(user.mining_power || 1) / 3600000;
      const start   = new Date(user.last_mining_start).getTime();
      const elapsed = Math.min(Date.now() - start, durMs);
      const earned  = Math.floor(cpm * elapsed);
      if (earned < 1) return err('No mining rewards yet');

      // Validate pending tasks from frontend in 1 batch (2 reads)
      const reqBody    = await request.json().catch(() => ({}));
      const pendingIds = Array.isArray(reqBody.pending_task_ids) ? reqBody.pending_task_ids.slice(0,50) : [];
      let taskBonus    = 0;
      const taskStmts  = [];
      let validCount   = 0;

      if (pendingIds.length > 0) {
        const placeholders = pendingIds.map(() => '?').join(',');
        const [taskRows, doneRows] = await tursoBatch(env, [
          { sql: `SELECT id,points_reward FROM tasks WHERE id IN (${placeholders}) AND is_active=1`, args: pendingIds },
          { sql: `SELECT task_id FROM user_tasks WHERE user_id=? AND task_id IN (${placeholders})`,  args: [user.id, ...pendingIds] }
        ]);
        const doneSet    = new Set((doneRows||[]).map(r=>r.task_id));
        const validTasks = (taskRows||[]).filter(t => !doneSet.has(t.id));
        validCount = validTasks.length;
        for (const task of validTasks) {
          const pts = parseInt(task.points_reward || 0);
          taskBonus += pts;
          taskStmts.push({ sql: "INSERT OR IGNORE INTO user_tasks (id,user_id,task_id,completed_at) VALUES (?,?,?,datetime('now'))", args: [crypto.randomUUID(), user.id, task.id] });
          taskStmts.push({ sql: "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", args: [crypto.randomUUID(), user.id, 'task_complete', pts, '✅ Task (batch claim)'] });
        }
      }

      const now      = new Date().toISOString();
      const newPts   = parseInt(user.points||0)       + earned + taskBonus;
      const newMined = parseInt(user.total_mined||0)  + earned;
      const newClaim = parseInt(user.total_claimed||0) + earned;

      // Build master batch — everything in 1 pipeline call
      const masterStmts = [
        // 1. Update balance + auto-restart (mining_claimed=0, new start time)
        { sql: 'UPDATE users SET points=?,total_mined=?,total_claimed=?,mining_claimed=0,last_mining_start=? WHERE id=?',
          args: [newPts, newMined, newClaim, now, user.id] },
        // 2. Mining claim tx
        { sql: "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
          args: [crypto.randomUUID(), user.id, 'mining_claim', earned, '⛏️ Mining claim'] },
        // 3. Close old session
        { sql: "UPDATE mining_sessions SET claimed_at=datetime('now'),coins_earned=?,is_claimed=1 WHERE user_id=? AND is_claimed=0",
          args: [earned, user.id] },
        // 4. Open new session (auto-restart)
        { sql: "INSERT INTO mining_sessions (id,user_id,started_at,mining_power) VALUES (?,?,?,?)",
          args: [crypto.randomUUID(), user.id, now, user.mining_power] },
        // 5. Refresh active_referral_count via sub-query
        { sql: "UPDATE users SET active_referral_count=(SELECT COUNT(*) FROM users WHERE referred_by=? AND total_mined>0) WHERE id=?",
          args: [user.referral_code, user.id] },
        // 6. Task count bump
        ...(validCount > 0 ? [{ sql: 'UPDATE users SET total_tasks_completed=total_tasks_completed+? WHERE id=?', args: [validCount, user.id] }] : []),
        // 7+. Task insert + tx rows
        ...taskStmts
      ];

      // Referral bonus writes — append to same batch
      if (user.referred_by) {
        const L1 = await dbFirst(env,'SELECT id,username,referred_by FROM users WHERE referral_code=?',[user.referred_by]);
        if (L1) {
          const l1b=Math.floor(earned*0.50); if(l1b>0){masterStmts.push({sql:'UPDATE users SET points=points+? WHERE id=?',args:[l1b,L1.id]});masterStmts.push({sql:"INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",args:[crypto.randomUUID(),L1.id,'refer_mining_l1',l1b,'⛏️ L1 50%: @'+user.username]});}
          if (L1.referred_by) {
            const L2=await dbFirst(env,'SELECT id,username,referred_by FROM users WHERE referral_code=?',[L1.referred_by]);
            if (L2) {
              const l2b=Math.floor(earned*0.25); if(l2b>0){masterStmts.push({sql:'UPDATE users SET points=points+? WHERE id=?',args:[l2b,L2.id]});masterStmts.push({sql:"INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",args:[crypto.randomUUID(),L2.id,'refer_mining_l2',l2b,'🌿 L2 25%: @'+user.username]});}
              if (L2.referred_by) {
                const L3=await dbFirst(env,'SELECT id,username FROM users WHERE referral_code=?',[L2.referred_by]);
                if (L3) { const l3b=Math.floor(earned*0.10); if(l3b>0){masterStmts.push({sql:'UPDATE users SET points=points+? WHERE id=?',args:[l3b,L3.id]});masterStmts.push({sql:"INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",args:[crypto.randomUUID(),L3.id,'refer_mining_l3',l3b,'🔥 L3 10%: @'+user.username]});}}
              }
            }
          }
        }
      }

      // ONE call — atomic
      await tursoBatch(env, masterStmts);
      return json({ success: true, earned, task_bonus: taskBonus, started_at: now });
    }

    if (path === '/api/tasks' && request.method === 'GET') {
      // OPTIMIZATION: tasks + done list in 1 batch (2 reads → 1 call)
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const [tasksRows, doneRows] = await tursoBatch(env, [
        { sql: 'SELECT * FROM tasks WHERE is_active = 1 ORDER BY display_order' },
        { sql: 'SELECT task_id FROM user_tasks WHERE user_id = ?', args: [user.id] }
      ]);
      return json({ tasks: tasksRows || [], done: (doneRows || []).map(d => d.task_id) });
    }

    if (path === '/api/tasks/complete' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id } = await request.json();
      // 2 reads in 1 batch
      const [taskRows, alreadyRows] = await tursoBatch(env, [
        { sql: 'SELECT * FROM tasks WHERE id=? AND is_active=1', args: [task_id] },
        { sql: 'SELECT id FROM user_tasks WHERE user_id=? AND task_id=?', args: [user.id, task_id] }
      ]);
      const task = taskRows?.[0];
      if (!task) return err('Task not found');
      if (alreadyRows?.[0]) return err('Already completed');
      if (task.task_type==='quiz') return err('Quiz tasks require answer verification');
      if (task.verify_code?.trim()) return err('This task requires a secret code');
      // 3 writes in 1 batch
      await tursoBatch(env, [
        { sql: "INSERT OR IGNORE INTO user_tasks (id,user_id,task_id,completed_at) VALUES (?,?,?,datetime('now'))", args: [crypto.randomUUID(), user.id, task_id] },
        { sql: 'UPDATE users SET points=points+?,total_tasks_completed=total_tasks_completed+1 WHERE id=?', args: [task.points_reward, user.id] },
        { sql: "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", args: [crypto.randomUUID(), user.id, 'task_complete', task.points_reward, '✅ '+task.title] }
      ]);
      return json({ success: true, earned: task.points_reward });
    }

    // VERIFY CODE (server-side fallback — frontend checks first from cache)
    if (path === '/api/tasks/verify-code' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id, code } = await request.json();
      if (!task_id || !code) return err('task_id and code required');
      // 3 reads in 1 batch
      const [taskRows, alreadyRows, attemptRows] = await tursoBatch(env, [
        { sql: 'SELECT * FROM tasks WHERE id=? AND is_active=1', args: [task_id] },
        { sql: 'SELECT id FROM user_tasks WHERE user_id=? AND task_id=?', args: [user.id, task_id] },
        { sql: 'SELECT * FROM quiz_attempts WHERE user_id=? AND task_id=?', args: [user.id, task_id] }
      ]);
      const task=taskRows?.[0], already=alreadyRows?.[0], attempt=attemptRows?.[0];
      if (!task) return err('Task not found');
      if (already) return err('Already completed');
      if (attempt?.failed==1) return json({success:false,failed:true,message:'3 attempts used. Start task again.'});
      const maxAttempts=3, attempts=attempt?parseInt(attempt.attempts):0;
      const isCorrect=(task.verify_code||'').trim().toLowerCase()===(code||'').trim().toLowerCase();
      if (isCorrect) {
        const stmts=[
          {sql:"INSERT OR IGNORE INTO user_tasks (id,user_id,task_id,completed_at) VALUES (?,?,?,datetime('now'))",args:[crypto.randomUUID(),user.id,task_id]},
          {sql:'UPDATE users SET points=points+?,total_tasks_completed=total_tasks_completed+1 WHERE id=?',args:[task.points_reward,user.id]},
          {sql:"INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",args:[crypto.randomUUID(),user.id,'task_complete',task.points_reward,'✅ '+task.title]}
        ];
        if(attempt) stmts.push({sql:'DELETE FROM quiz_attempts WHERE user_id=? AND task_id=?',args:[user.id,task_id]});
        await tursoBatch(env,stmts);
        return json({success:true,earned:task.points_reward});
      }
      const newAttempts=attempts+1, isFailed=newAttempts>=maxAttempts;
      // 1 write (upsert attempt)
      if(attempt) await dbRun(env,'UPDATE quiz_attempts SET attempts=?,failed=? WHERE user_id=? AND task_id=?',[newAttempts,isFailed?1:0,user.id,task_id]);
      else await dbRun(env,"INSERT INTO quiz_attempts (id,user_id,task_id,attempts,failed,created_at) VALUES (?,?,?,?,?,datetime('now'))",[crypto.randomUUID(),user.id,task_id,newAttempts,isFailed?1:0]);
      if(isFailed) return json({success:false,failed:true,message:'Wrong code! 3 attempts failed.'});
      return json({success:false,failed:false,remaining:maxAttempts-newAttempts,message:'Wrong code! '+(maxAttempts-newAttempts)+' attempts left.'});
    }

    // VERIFY CODE RESET — fail hone k baad dobara shuru
    if (path === '/api/tasks/verify-reset' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id } = await request.json();
      await dbRun(env, 'DELETE FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      return json({ success: true });
    }

    // QUIZ VERIFY (server-side fallback — frontend checks first from cache)
    if (path === '/api/tasks/quiz-verify' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id, answer } = await request.json();
      if (!task_id || answer === undefined) return err('Missing fields');
      // 3 reads in 1 batch
      const [taskRows, alreadyRows, attemptRows] = await tursoBatch(env, [
        { sql: "SELECT * FROM tasks WHERE id=? AND is_active=1 AND task_type='quiz'", args: [task_id] },
        { sql: 'SELECT id FROM user_tasks WHERE user_id=? AND task_id=?', args: [user.id, task_id] },
        { sql: 'SELECT * FROM quiz_attempts WHERE user_id=? AND task_id=?', args: [user.id, task_id] }
      ]);
      const task=taskRows?.[0], already=alreadyRows?.[0], attempt=attemptRows?.[0];
      if (!task) return err('Quiz task not found');
      if (already) return err('Already completed');
      if (attempt?.failed==1) return json({success:false,failed:true,message:'3 attempts used. Start again.'});
      const maxAttempts=3, attempts=attempt?parseInt(attempt.attempts):0;
      const isCorrect=(task.quiz_answer||'').trim().toLowerCase()===(answer||'').trim().toLowerCase();
      if (isCorrect) {
        const stmts=[
          {sql:"INSERT OR IGNORE INTO user_tasks (id,user_id,task_id,completed_at) VALUES (?,?,?,datetime('now'))",args:[crypto.randomUUID(),user.id,task_id]},
          {sql:'UPDATE users SET points=points+?,total_tasks_completed=total_tasks_completed+1 WHERE id=?',args:[task.points_reward,user.id]},
          {sql:"INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",args:[crypto.randomUUID(),user.id,'task_complete',task.points_reward,'✅ Quiz: '+task.title]}
        ];
        if(attempt) stmts.push({sql:'DELETE FROM quiz_attempts WHERE user_id=? AND task_id=?',args:[user.id,task_id]});
        await tursoBatch(env,stmts);
        return json({success:true,earned:task.points_reward});
      }
      const newAttempts=attempts+1, isFailed=newAttempts>=maxAttempts;
      if(attempt) await dbRun(env,'UPDATE quiz_attempts SET attempts=?,failed=? WHERE user_id=? AND task_id=?',[newAttempts,isFailed?1:0,user.id,task_id]);
      else await dbRun(env,"INSERT INTO quiz_attempts (id,user_id,task_id,attempts,failed,created_at) VALUES (?,?,?,?,?,datetime('now'))",[crypto.randomUUID(),user.id,task_id,newAttempts,isFailed?1:0]);
      if(isFailed) return json({success:false,failed:true,message:'Wrong answer! 3 attempts failed.'});
      return json({success:false,failed:false,remaining:maxAttempts-newAttempts,message:'Wrong answer! '+(maxAttempts-newAttempts)+' attempts left.'});
    }

    if (path === '/api/tasks/quiz-reset' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id } = await request.json();
      await dbRun(env, 'DELETE FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      return json({ success: true });
    }

    if (path === '/api/leaderboard' && request.method === 'GET') {
      // Top 25 by total balance (points) — highest balance first
      const results = await dbAll(env,
        `SELECT u.username, u.wallet_address, u.wallet_type,
                u.points AS total_points, u.total_mined, u.mining_power,
                (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code) AS total_referrals,
                (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code AND r.total_mined > 0) AS active_referrals
         FROM users u
         WHERE u.points > 0
         ORDER BY u.points DESC
         LIMIT 25`
      );
      return json(results);
    }

    if (path === '/api/referrals' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const results = await dbAll(env, 'SELECT username,wallet_address,total_mined,created_at FROM users WHERE referred_by = ? ORDER BY created_at DESC LIMIT 30', [user.referral_code]);
      return json(results);
    }

    if (path === '/api/transactions' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const results = await dbAll(env, 'SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 30', [user.id]);
      return json(results);
    }

    if (path === '/api/settings' && request.method === 'GET') {
      const results = await dbAll(env, 'SELECT key, value FROM settings');
      const map = {};
      results.forEach(r => map[r.key] = r.value);
      return json(map);
    }

    if (path === '/api/stats' && request.method === 'GET') {
      // OPTIMIZATION: 2 aggregates in 1 batch call
      const [ucRows, tmRows] = await tursoBatch(env, [
        { sql: 'SELECT COUNT(*) as c FROM users' },
        { sql: 'SELECT SUM(total_mined) as s FROM users' }
      ]);
      return json({ users: parseInt(ucRows?.[0]?.c || 0), total_mined: parseInt(tmRows?.[0]?.s || 0) });
    }

    // ── ADS ── Ab ads.js mein manual hain, DB se nahi aate
    // /api/ads removed — ads directly ads.js mein hardcode karo

    // ── ADMIN ─────────────────────────────────────
    if (path.startsWith('/api/admin/')) {
      const adminPass = request.headers.get('X-Admin-Key');
      if (adminPass !== (env.ADMIN_KEY || "Admin@2026")) return err('Forbidden', 403);
      const body = request.method !== 'GET' ? await request.json().catch(() => ({})) : {};

      if (path === '/api/admin/users' && request.method === 'GET') {
        return json(await dbAll(env, `SELECT u.*,
          (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code) AS referral_count,
          (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code AND r.total_mined > 0) AS active_referral_count
          FROM users u ORDER BY u.created_at DESC LIMIT 100`));
      }
      if (path === '/api/admin/users/ban' && request.method === 'POST') {
        const { id, is_banned } = body;
        if (!id) return err('Invalid');
        await dbRun(env, 'UPDATE users SET is_banned=? WHERE id=?', [is_banned ? 1 : 0, id]);
        return json({ ok: true });
      }
      if (path === '/api/admin/users/update' && request.method === 'POST') {
        await dbRun(env, 'UPDATE users SET username=?,points=?,mining_power=?,is_banned=? WHERE id=?', [body.username, body.points, body.mining_power, body.is_banned ? 1 : 0, body.id]);
        return json({ success: true });
      }
      if (path === '/api/admin/tasks' && request.method === 'GET') {
        return json(await dbAll(env, 'SELECT * FROM tasks ORDER BY display_order'));
      }
      if (path === '/api/admin/tasks/save' && request.method === 'POST') {
        const { id, title, description, icon, task_type, url, ad_url, quiz_question, quiz_answer, verify_code, points_reward, timer_seconds, display_order, is_active } = body;
        if (id) {
          await dbRun(env, 'UPDATE tasks SET title=?,description=?,icon=?,task_type=?,url=?,ad_url=?,quiz_question=?,quiz_answer=?,verify_code=?,points_reward=?,timer_seconds=?,display_order=?,is_active=? WHERE id=?', [title, description||null, icon||'🎯', task_type, url||null, ad_url||null, quiz_question||null, quiz_answer||null, verify_code||null, points_reward, timer_seconds||0, display_order||99, is_active?1:0, id]);
        } else {
          await dbRun(env, "INSERT INTO tasks (id,title,description,icon,task_type,url,ad_url,quiz_question,quiz_answer,verify_code,points_reward,timer_seconds,display_order,is_active,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), title, description||null, icon||'🎯', task_type, url||null, ad_url||null, quiz_question||null, quiz_answer||null, verify_code||null, points_reward, timer_seconds||0, display_order||99, is_active?1:0]);
        }
        return json({ success: true });
      }
      if (path === '/api/admin/tasks/delete' && request.method === 'POST') {
        await dbRun(env, 'DELETE FROM tasks WHERE id=?', [body.id]);
        return json({ success: true });
      }
      if (path === '/api/admin/settings' && request.method === 'POST') {
        // OPTIMIZATION: all setting updates in 1 batch call
        const stmts = Object.entries(body).map(([key, value]) => ({
          sql: 'UPDATE settings SET value=? WHERE key=?',
          args: [String(value), key]
        }));
        if (stmts.length) await tursoBatch(env, stmts);
        return json({ success: true });
      }
      if (path === '/api/admin/blog' && request.method === 'GET') {
        return json(await dbAll(env, 'SELECT * FROM blog_posts ORDER BY display_order'));
      }
      if (path === '/api/admin/blog/save' && request.method === 'POST') {
        const { id, title, slug, category, phase, excerpt, content, display_order, status } = body;
        const sl = slug || title.toLowerCase().replace(/[^a-z0-9]+/g, '-');
        if (id) {
          await dbRun(env, 'UPDATE blog_posts SET title=?,slug=?,category=?,phase=?,excerpt=?,content=?,display_order=?,status=? WHERE id=?', [title, sl, category||'roadmap', phase||null, excerpt||null, content||null, display_order||99, status||'published', id]);
        } else {
          await dbRun(env, "INSERT INTO blog_posts (id,title,slug,category,phase,excerpt,content,display_order,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), title, sl, category||'roadmap', phase||null, excerpt||null, content||null, display_order||99, status||'published']);
        }
        return json({ success: true });
      }
      if (path === '/api/admin/blog/delete' && request.method === 'POST') {
        await dbRun(env, 'DELETE FROM blog_posts WHERE id=?', [body.id]);
        return json({ success: true });
      }
      if (path === '/api/admin/dashboard' && request.method === 'GET') {
        // OPTIMIZATION: 4 aggregates in 1 batch call
        const [ucRows, tmRows, tcRows, mcRows] = await tursoBatch(env, [
          { sql: 'SELECT COUNT(*) as c FROM users' },
          { sql: 'SELECT SUM(total_mined) as s FROM users' },
          { sql: 'SELECT COUNT(*) as c FROM tasks WHERE is_active=1' },
          { sql: 'SELECT COUNT(*) as c FROM mining_sessions' }
        ]);
        const recent = await dbAll(env, 'SELECT id,username,email,wallet_address,points,total_mined,mining_power,created_at,login_method,is_banned,(SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code AND r.total_mined > 0) AS active_referral_count FROM users u ORDER BY created_at DESC LIMIT 10');
        return json({ users: parseInt(ucRows?.[0]?.c||0), total_mined: parseInt(tmRows?.[0]?.s||0), tasks: parseInt(tcRows?.[0]?.c||0), sessions: parseInt(mcRows?.[0]?.c||0), recent });
      }

      if (path === '/api/admin/ads' && request.method === 'GET') {
        return json(await dbAll(env, 'SELECT * FROM ads ORDER BY created_at DESC'));
      }
      if (path === '/api/admin/ads/save' && request.method === 'POST') {
        const { id, name, network, position, code, url, pages, is_active, type } = body;
        const pg = Array.isArray(pages) ? pages.join(',') : (pages || 'index,blog,policies,vision');
        const net = network || type || 'script';
        if (id) {
          await dbRun(env, 'UPDATE ads SET name=?,network=?,position=?,code=?,url=?,pages=?,is_active=? WHERE id=?', [name, net, position||'bottom', code||'', url||'', pg, is_active!=null?is_active:1, id]);
        } else {
          await dbRun(env, "INSERT INTO ads (id,name,network,position,code,url,pages,is_active,created_at) VALUES (?,?,?,?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), name, net, position||'bottom', code||'', url||'', pg, is_active!=null?is_active:1]);
        }
        return json({ success: true });
      }
      if (path === '/api/admin/ads/delete' && request.method === 'POST') {
        await dbRun(env, 'DELETE FROM ads WHERE id=?', [body.id]);
        return json({ success: true });
      }
      if (path === '/api/admin/mining' && request.method === 'GET') {
        return json(await dbAll(env, 'SELECT ms.*,u.username FROM mining_sessions ms LEFT JOIN users u ON ms.user_id=u.id ORDER BY ms.started_at DESC LIMIT 100'));
      }
      if (path === '/api/admin/transactions' && request.method === 'GET') {
        return json(await dbAll(env, 'SELECT t.*,u.username FROM transactions t LEFT JOIN users u ON t.user_id=u.id ORDER BY t.created_at DESC LIMIT 100'));
      }
    }

      if (path === '/api/admin/db-init' && request.method === 'POST') {
        await dbRun(env, `CREATE TABLE IF NOT EXISTS password_resets (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, username TEXT, email TEXT, verify_question TEXT, verify_answer TEXT, new_password_hash TEXT, status TEXT DEFAULT 'pending', created_at TEXT, resolved_at TEXT)`);
        await dbRun(env, `CREATE TABLE IF NOT EXISTS support_messages (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, username TEXT, email TEXT, message TEXT, status TEXT DEFAULT 'open', admin_reply TEXT, replied_at TEXT, created_at TEXT)`);
        try { await dbRun(env, 'ALTER TABLE users ADD COLUMN security_question TEXT'); } catch(e) {}
        try { await dbRun(env, 'ALTER TABLE users ADD COLUMN security_answer TEXT'); } catch(e) {}
        try { await dbRun(env, 'ALTER TABLE users ADD COLUMN active_referral_count INTEGER DEFAULT 0'); } catch(e) {}
        try { await dbRun(env, 'ALTER TABLE password_resets ADD COLUMN new_password_hash TEXT'); } catch(e) {}
        return json({ success: true, message: 'Tables ready' });
      }

    return err('Not found', 404);

  } catch (e) {
    return err('Server error: ' + e.message, 500);
  }
}
