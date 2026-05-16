// ============================================
// Ai2E — Dual Turso Database Backend (FULL)
// DB1 (TURSO_URL, TURSO_TOKEN): Users, Auth, Tasks, Referrals, Settings, Support, Password Resets
// DB2 (TURSO_1_URL, TURSO_1_TOKEN): Mining Sessions, Transactions, Mining Cache
// Auto-Init: Old users automatically get DB2 rows on first mining start/claim/login
// All features included: quiz, verify-code, ad tasks, claim-and-start, admin panel
// ============================================

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Admin-Key',
};

// ──────────────────────────────────────────
// Turso HTTP Helper (generic)
// ──────────────────────────────────────────
async function tursoRequest(url, token, sql, args = []) {
  const endpoint = url.replace('libsql://', 'https://');
  const res = await fetch(`${endpoint}/v2/pipeline`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      requests: [
        { type: 'execute', stmt: { sql, args: args.map(v => {
          if (v === null || v === undefined) return { type: 'null' };
          if (typeof v === 'number') return { type: 'integer', value: String(v) };
          return { type: 'text', value: String(v) };
        }) } },
        { type: 'close' }
      ]
    })
  });
  const data = await res.json();
  if (data.results?.[0]?.type === 'error') throw new Error(data.results[0].error.message);
  const result = data.results?.[0]?.response?.result;
  if (!result) return [];
  const cols = result.cols.map(c => c.name);
  return result.rows.map(row => {
    const obj = {};
    cols.forEach((col, i) => { obj[col] = row[i]?.value ?? null; });
    return obj;
  });
}

// DB1 helpers (original Turso)
async function db1(env, sql, args = []) {
  return tursoRequest(env.TURSO_URL, env.TURSO_TOKEN, sql, args);
}
async function db1First(env, sql, args = []) { return (await db1(env, sql, args))[0] || null; }
async function db1All(env, sql, args = [])   { return db1(env, sql, args); }
async function db1Run(env, sql, args = [])   { return db1(env, sql, args); }

// DB2 helpers (new Turso)
async function db2(env, sql, args = []) {
  return tursoRequest(env.TURSO_1_URL, env.TURSO_1_TOKEN, sql, args);
}
async function db2First(env, sql, args = []) { return (await db2(env, sql, args))[0] || null; }
async function db2All(env, sql, args = [])   { return db2(env, sql, args); }
async function db2Run(env, sql, args = [])   { return db2(env, sql, args); }

// ──────────────────────────────────────────
// AUTO-INIT: Ensure user exists in DB2 (mining cache)
// ──────────────────────────────────────────
async function ensureUserInDb2(env, userId) {
  try {
    const exists = await db2First(env, 'SELECT 1 FROM user_mining_cache WHERE user_id = ? LIMIT 1', [userId]);
    if (exists) return;
    await db2Run(env, `
      INSERT INTO user_mining_cache (user_id, total_points, total_mined, last_sync)
      VALUES (?, 0, 0, datetime('now'))
    `, [userId]);
    console.log(`Auto-init DB2 for user ${userId}`);
  } catch (e) {
    console.error('ensureUserInDb2 error:', e);
  }
}

// ──────────────────────────────────────────
// Password & Token Utilities
// ──────────────────────────────────────────
async function legacyHash(password) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + 'AI2E_SALT_2025'));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  const hashHex = Array.from(new Uint8Array(derived)).map(b => b.toString(16).padStart(2, '0')).join('');
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${saltHex}:${hashHex}`;
}
async function verifyPassword(password, storedHash) {
  if (!storedHash) return false;
  if (!storedHash.includes(':')) return (await legacyHash(password)) === storedHash;
  const [saltHex, hashHex] = storedHash.split(':');
  const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  const newHash = Array.from(new Uint8Array(derived)).map(b => b.toString(16).padStart(2, '0')).join('');
  return newHash === hashHex;
}
async function makeToken(userId, env) {
  const data = JSON.stringify({ id: userId, ts: Date.now() });
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return btoa(data) + '.' + btoa(String.fromCharCode(...new Uint8Array(sig)));
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
    if (Date.now() - parsed.ts > 30 * 24 * 60 * 60 * 1000) return null;
    return parsed;
  } catch { return null; }
}

// ──────────────────────────────────────────
// Utilities
// ──────────────────────────────────────────
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
}
function err(msg, status = 400) {
  return json({ error: msg }, status);
}
const _tokenCache = new Map();
async function getUser(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  if (_tokenCache.has(token)) return _tokenCache.get(token);
  const parsed = await verifyToken(token, env);
  if (!parsed) return null;
  const user = await db1First(env, 'SELECT * FROM users WHERE id = ?', [parsed.id]);
  _tokenCache.set(token, user);
  return user;
}
function esc(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function fNum(n) {
  n = parseInt(n) || 0;
  if (n >= 1000000) return (n/1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n/1000).toFixed(1) + 'K';
  return n.toString();
}

// ──────────────────────────────────────────
// MAIN HANDLER
// ──────────────────────────────────────────
export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  const url = new URL(request.url);
  const path = url.pathname;

  try {
    // ========== AUTH & USER (DB1) ==========
    if ((path === '/api/register' || path === '/api/auth/register') && request.method === 'POST') {
      const body = await request.json();
      const { username, email, password, ref_code, security_question, security_answer } = body;
      if (!username || !email || !password) return err('All fields required');
      if (password.length < 6) return err('Password min 6 chars');

      const emailNorm = email.toLowerCase().trim();
      const exists = await db1First(env, 'SELECT id FROM users WHERE email = ?', [emailNorm]);
      if (exists) return err('Email already registered');
      const uExists = await db1First(env, 'SELECT id FROM users WHERE username = ?', [username.toLowerCase()]);
      if (uExists) return err('Username taken');

      const hashed = await hashPassword(password);
      const myRef = 'AI2E' + Math.random().toString(36).substr(2, 6).toUpperCase();
      const id = crypto.randomUUID();
      const cfg = await db1First(env, "SELECT value FROM settings WHERE key = 'welcome_bonus'");
      const bonus = parseInt(cfg?.value || '1000');

      await db1Run(env, `
        INSERT INTO users (id, username, email, password, referral_code, referred_by, points, total_mined,
          mining_power, login_method, mining_claimed, security_question, security_answer, created_at)
        VALUES (?,?,?,?,?,?,?,0,1.0,'email',1,?,?,datetime('now'))
      `, [id, username.toLowerCase(), emailNorm, hashed, myRef, ref_code || null, bonus, security_question||null, security_answer||null]);

      // DB2: welcome bonus transaction + cache init
      await db2Run(env, `
        INSERT INTO transactions (id, user_id, type, amount, description, created_at)
        VALUES (?,?,?,?,?,datetime('now'))
      `, [crypto.randomUUID(), id, 'welcome_bonus', bonus, '🎉 Welcome bonus']);
      await ensureUserInDb2(env, id);

      if (ref_code) {
        const refUser = await db1First(env, 'SELECT id FROM users WHERE referral_code = ?', [ref_code]);
        if (refUser && refUser.id !== id) {
          await db1Run(env, 'UPDATE users SET referral_count = referral_count + 1 WHERE id = ?', [refUser.id]);
        }
      }

      const token = await makeToken(id, env);
      const user = await db1First(env, 'SELECT * FROM users WHERE id = ?', [id]);
      return json({ token, user });
    }

    if ((path === '/api/login' || path === '/api/auth/login') && request.method === 'POST') {
      const { email, password } = await request.json();
      const emailNorm = email.toLowerCase().trim();
      let user = await db1First(env, 'SELECT * FROM users WHERE email = ?', [emailNorm]);
      if (!user) return err('Wrong email or password', 401);
      if (user.is_banned == 1) return err('Account banned', 403);

      const valid = await verifyPassword(password, user.password || user.password_hash);
      if (!valid) return err('Wrong email or password', 401);

      if (user.password && !user.password.includes(':')) {
        const newHash = await hashPassword(password);
        await db1Run(env, 'UPDATE users SET password = ? WHERE id = ?', [newHash, user.id]);
      }

      await ensureUserInDb2(env, user.id);
      const token = await makeToken(user.id, env);
      return json({ token, user });
    }

    if (path === '/api/auth/wallet' && request.method === 'POST') {
      const { wallet_address, wallet_type, ref_code } = await request.json();
      if (!wallet_address) return err('Wallet address required');
      const addr = wallet_address.toLowerCase();
      let user = await db1First(env, 'SELECT * FROM users WHERE wallet_address = ?', [addr]);
      if (!user) {
        const id = crypto.randomUUID();
        const username = 'w_' + addr.slice(2, 10);
        const myRef = 'AI2E' + Math.random().toString(36).substr(2, 6).toUpperCase();
        const cfg = await db1First(env, "SELECT value FROM settings WHERE key = 'welcome_bonus'");
        const bonus = parseInt(cfg?.value || '1000');
        await db1Run(env, `
          INSERT INTO users (id, username, wallet_address, wallet_type, referral_code, referred_by,
            points, total_mined, mining_power, login_method, mining_claimed, created_at)
          VALUES (?,?,?,?,?,?,?,0,1.0,?,1,datetime('now'))
        `, [id, username, addr, wallet_type||'web3', myRef, ref_code||null, bonus, wallet_type||'wallet']);
        await db2Run(env, `
          INSERT INTO transactions (id, user_id, type, amount, description, created_at)
          VALUES (?,?,?,?,?,datetime('now'))
        `, [crypto.randomUUID(), id, 'welcome_bonus', bonus, '🎉 Welcome bonus']);
        await ensureUserInDb2(env, id);
        user = await db1First(env, 'SELECT * FROM users WHERE id = ?', [id]);
      }
      if (user.is_banned == 1) return err('Account banned', 403);
      await ensureUserInDb2(env, user.id);
      const token = await makeToken(user.id, env);
      return json({ token, user });
    }

    // ========== FORGOT PASSWORD (DB1) ==========
    if (path === '/api/auth/forgot-check' && request.method === 'POST') {
      const { email } = await request.json();
      const user = await db1First(env, 'SELECT id, security_question FROM users WHERE LOWER(email) = ?', [email.toLowerCase()]);
      if (!user) return err('No account found');
      return json({ ok: true, security_question: user.security_question || null });
    }
    if (path === '/api/auth/forgot-password' && request.method === 'POST') {
      const { email, answer, question, new_password } = await request.json();
      const emailNorm = email.toLowerCase();
      const user = await db1First(env, 'SELECT id, username FROM users WHERE LOWER(email) = ?', [emailNorm]);
      if (!user) return err('Account not found');
      const existing = await db1First(env, "SELECT id FROM password_resets WHERE user_id = ? AND status = 'pending'", [user.id]);
      if (existing) return err('Reset request already pending');
      const hashedNew = await hashPassword(new_password);
      await db1Run(env, `
        INSERT INTO password_resets (id,user_id,username,email,verify_question,verify_answer,new_password_hash,status,created_at)
        VALUES (?,?,?,?,?,?,?,'pending',datetime('now'))
      `, [crypto.randomUUID(), user.id, user.username, emailNorm, question||'', answer, hashedNew]);
      return json({ ok: true });
    }

    // ========== SUPPORT (DB1) ==========
    if (path === '/api/support/send' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { message } = await request.json();
      if (!message || message.trim().length < 5) return err('Message too short');
      const last = await db1First(env, "SELECT id FROM support_messages WHERE user_id = ? AND created_at > datetime('now','-24 hours')", [user.id]);
      if (last) return err('Only one message per 24 hours');
      await db1Run(env, `
        INSERT INTO support_messages (id,user_id,username,email,message,status,created_at)
        VALUES (?,?,?,?,?,'open',datetime('now'))
      `, [crypto.randomUUID(), user.id, user.username, user.email||'', message.trim()]);
      return json({ ok: true });
    }
    if (path === '/api/support/my-messages' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const msgs = await db1All(env, 'SELECT * FROM support_messages WHERE user_id = ? ORDER BY created_at DESC LIMIT 10', [user.id]);
      return json(msgs);
    }

    // ========== MINING (DB1 + DB2) ==========
    if ((path === '/api/mine/start' || path === '/api/mining/start') && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      if (user.mining_claimed != 1) return err('Already mining');
      const now = new Date().toISOString();
      await db1Run(env, "UPDATE users SET last_mining_start = ?, mining_claimed = 0 WHERE id = ?", [now, user.id]);
      await db2Run(env, "INSERT INTO mining_sessions (id, user_id, started_at, mining_power) VALUES (?,?,?,?)",
        [crypto.randomUUID(), user.id, now, user.mining_power || 1.0]);
      await ensureUserInDb2(env, user.id);
      return json({ success: true });
    }

    if ((path === '/api/mine/claim' || path === '/api/mining/claim') && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      if (user.mining_claimed == 1) return err('Nothing to claim');

      const cfgRows = await db1All(env, "SELECT key, value FROM settings WHERE key IN ('mining_duration_hours','mining_coins_per_hour')");
      const cfg = {};
      cfgRows.forEach(r => cfg[r.key] = r.value);
      const durMs = parseInt(cfg.mining_duration_hours || '24') * 3600000;
      const cpm = parseFloat(cfg.mining_coins_per_hour || '10') * parseFloat(user.mining_power) / 3600000;
      const elapsed = Math.min(Date.now() - new Date(user.last_mining_start).getTime(), durMs);
      const earned = Math.floor(cpm * elapsed);
      if (earned < 1) return err('Nothing mined yet');

      const newPts = (user.points || 0) + earned;
      const newMined = (user.total_mined || 0) + earned;

      await db1Run(env, `
        UPDATE users SET points = ?, total_mined = ?, total_claimed = COALESCE(total_claimed,0) + ?, mining_claimed = 1
        WHERE id = ?
      `, [newPts, newMined, earned, user.id]);

      await db2Run(env, `
        INSERT INTO transactions (id, user_id, type, amount, description, created_at)
        VALUES (?,?,?,?,?,datetime('now'))
      `, [crypto.randomUUID(), user.id, 'mining_claim', earned, '⛏️ Mining claim']);

      await db2Run(env, `
        UPDATE mining_sessions SET claimed_at = datetime('now'), coins_earned = ?, is_claimed = 1
        WHERE user_id = ? AND is_claimed = 0
      `, [earned, user.id]);

      // Referral tree (L1=50%, L2=25%, L3=10%)
      if (user.referred_by) {
        const L1 = await db1First(env, 'SELECT * FROM users WHERE referral_code = ?', [user.referred_by]);
        if (L1) {
          const l1Bonus = Math.floor(earned * 0.50);
          if (l1Bonus > 0) {
            await db1Run(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l1Bonus, L1.id]);
            await db2Run(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
              [crypto.randomUUID(), L1.id, 'refer_mining_l1', l1Bonus, '⛏️ L1 50%: @' + user.username]);
            if (L1.referred_by) {
              const L2 = await db1First(env, 'SELECT * FROM users WHERE referral_code = ?', [L1.referred_by]);
              if (L2) {
                const l2Bonus = Math.floor(earned * 0.25);
                if (l2Bonus > 0) {
                  await db1Run(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l2Bonus, L2.id]);
                  await db2Run(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
                    [crypto.randomUUID(), L2.id, 'refer_mining_l2', l2Bonus, '🌿 L2 25%: @' + user.username]);
                  if (L2.referred_by) {
                    const L3 = await db1First(env, 'SELECT * FROM users WHERE referral_code = ?', [L2.referred_by]);
                    if (L3) {
                      const l3Bonus = Math.floor(earned * 0.10);
                      if (l3Bonus > 0) {
                        await db1Run(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l3Bonus, L3.id]);
                        await db2Run(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
                          [crypto.randomUUID(), L3.id, 'refer_mining_l3', l3Bonus, '🔥 L3 10%: @' + user.username]);
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      await ensureUserInDb2(env, user.id);
      const updatedUser = await db1First(env, 'SELECT * FROM users WHERE id = ?', [user.id]);
      return json({ success: true, earned, user: updatedUser });
    }

    if (path === '/api/mine/claim-and-start' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      if (user.mining_claimed == 1) return err('Nothing to claim');

      const cfgRows = await db1All(env, "SELECT key, value FROM settings WHERE key IN ('mining_duration_hours','mining_coins_per_hour')");
      const cfg = {};
      cfgRows.forEach(r => cfg[r.key] = r.value);
      const durMs = parseInt(cfg.mining_duration_hours || '24') * 3600000;
      const cpm = parseFloat(cfg.mining_coins_per_hour || '10') * parseFloat(user.mining_power) / 3600000;
      const elapsed = Math.min(Date.now() - new Date(user.last_mining_start).getTime(), durMs);
      const earned = Math.floor(cpm * elapsed);
      if (earned < 1) return err('Nothing mined yet');

      const newPts = (user.points || 0) + earned;
      const newMined = (user.total_mined || 0) + earned;
      const now = new Date().toISOString();

      await db1Run(env, `
        UPDATE users SET points = ?, total_mined = ?, total_claimed = COALESCE(total_claimed,0) + ?, mining_claimed = 0, last_mining_start = ?
        WHERE id = ?
      `, [newPts, newMined, earned, now, user.id]);

      await db2Run(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
        [crypto.randomUUID(), user.id, 'mining_claim', earned, '⛏️ Mining claim']);
      await db2Run(env, "UPDATE mining_sessions SET claimed_at = datetime('now'), coins_earned = ?, is_claimed = 1 WHERE user_id = ? AND is_claimed = 0",
        [earned, user.id]);
      await db2Run(env, "INSERT INTO mining_sessions (id,user_id,started_at,mining_power) VALUES (?,?,?,?)",
        [crypto.randomUUID(), user.id, now, user.mining_power]);

      // Referral tree (same as claim)
      if (user.referred_by) {
        const L1 = await db1First(env, 'SELECT * FROM users WHERE referral_code = ?', [user.referred_by]);
        if (L1) {
          const l1Bonus = Math.floor(earned * 0.50);
          if (l1Bonus > 0) {
            await db1Run(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l1Bonus, L1.id]);
            await db2Run(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
              [crypto.randomUUID(), L1.id, 'refer_mining_l1', l1Bonus, '⛏️ L1 50%: @' + user.username]);
            if (L1.referred_by) {
              const L2 = await db1First(env, 'SELECT * FROM users WHERE referral_code = ?', [L1.referred_by]);
              if (L2) {
                const l2Bonus = Math.floor(earned * 0.25);
                if (l2Bonus > 0) {
                  await db1Run(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l2Bonus, L2.id]);
                  await db2Run(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
                    [crypto.randomUUID(), L2.id, 'refer_mining_l2', l2Bonus, '🌿 L2 25%: @' + user.username]);
                  if (L2.referred_by) {
                    const L3 = await db1First(env, 'SELECT * FROM users WHERE referral_code = ?', [L2.referred_by]);
                    if (L3) {
                      const l3Bonus = Math.floor(earned * 0.10);
                      if (l3Bonus > 0) {
                        await db1Run(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l3Bonus, L3.id]);
                        await db2Run(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
                          [crypto.randomUUID(), L3.id, 'refer_mining_l3', l3Bonus, '🔥 L3 10%: @' + user.username]);
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      await ensureUserInDb2(env, user.id);
      const updatedUser = await db1First(env, 'SELECT * FROM users WHERE id = ?', [user.id]);
      return json({ success: true, earned, user: updatedUser, last_mining_start: now });
    }

    // ========== TASKS (DB1) ==========
    if (path === '/api/tasks' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const tasks = await db1All(env, 'SELECT * FROM tasks WHERE is_active = 1 ORDER BY display_order');
      const done = await db1All(env, 'SELECT task_id FROM user_tasks WHERE user_id = ?', [user.id]);
      return json({ tasks, done: done.map(d => d.task_id) });
    }

    // Task complete (link/youtube/twitter type)
    if (path === '/api/tasks/complete' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id } = await request.json();
      const task = await db1First(env, 'SELECT * FROM tasks WHERE id = ? AND is_active = 1', [task_id]);
      if (!task) return err('Task not found');
      const already = await db1First(env, 'SELECT id FROM user_tasks WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      if (already) return err('Already completed');
      if (task.task_type === 'quiz') return err('Use /api/tasks/quiz-verify for quiz tasks');
      if (task.task_type === 'ad') return err('Use /api/tasks/ad-complete for ad tasks');
      if (task.verify_code && task.verify_code.trim() !== '') return err('Use /api/tasks/verify-code for code tasks');

      await db1Run(env, "INSERT INTO user_tasks (id,user_id,task_id,completed_at) VALUES (?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, task_id]);
      await db1Run(env, 'UPDATE users SET points = points + ?, total_tasks_completed = total_tasks_completed + 1 WHERE id = ?', [task.points_reward, user.id]);
      await db2Run(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, 'task_complete', task.points_reward, '✅ ' + task.title]);
      return json({ success: true, earned: task.points_reward });
    }

    // Quiz verify
    if (path === '/api/tasks/quiz-verify' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id, answer } = await request.json();
      const task = await db1First(env, 'SELECT * FROM tasks WHERE id = ? AND is_active = 1 AND task_type = "quiz"', [task_id]);
      if (!task) return err('Quiz task not found');
      const already = await db1First(env, 'SELECT id FROM user_tasks WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      if (already) return err('Already completed');
      let attempt = await db1First(env, 'SELECT * FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      const maxAttempts = 3;
      const attempts = attempt ? attempt.attempts : 0;
      if (attempt && attempt.failed == 1) return json({ success: false, failed: true, message: 'You have failed. Reset the task.' });
      const correct = (task.quiz_answer || '').trim().toLowerCase();
      const given = (answer || '').trim().toLowerCase();
      if (correct === given) {
        await db1Run(env, "INSERT INTO user_tasks (id,user_id,task_id,completed_at) VALUES (?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, task_id]);
        await db1Run(env, 'UPDATE users SET points = points + ?, total_tasks_completed = total_tasks_completed + 1 WHERE id = ?', [task.points_reward, user.id]);
        await db2Run(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, 'task_complete', task.points_reward, '✅ Quiz: ' + task.title]);
        if (attempt) await db1Run(env, 'DELETE FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
        return json({ success: true, earned: task.points_reward });
      } else {
        const newAttempts = attempts + 1;
        const isFailed = newAttempts >= maxAttempts;
        if (attempt) {
          await db1Run(env, 'UPDATE quiz_attempts SET attempts = ?, failed = ? WHERE user_id = ? AND task_id = ?', [newAttempts, isFailed ? 1 : 0, user.id, task_id]);
        } else {
          await db1Run(env, "INSERT INTO quiz_attempts (id,user_id,task_id,attempts,failed,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, task_id, newAttempts, isFailed ? 1 : 0]);
        }
        const remaining = maxAttempts - newAttempts;
        if (isFailed) return json({ success: false, failed: true, message: 'Wrong answer 3 times. Reset the task.' });
        return json({ success: false, failed: false, remaining, message: `Wrong answer! ${remaining} attempts left.` });
      }
    }

    // Quiz reset
    if (path === '/api/tasks/quiz-reset' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id } = await request.json();
      await db1Run(env, 'DELETE FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      return json({ success: true });
    }

    // Verify code task
    if (path === '/api/tasks/verify-code' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id, code } = await request.json();
      const task = await db1First(env, 'SELECT * FROM tasks WHERE id = ? AND is_active = 1', [task_id]);
      if (!task) return err('Task not found');
      const already = await db1First(env, 'SELECT id FROM user_tasks WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      if (already) return err('Already completed');
      let attempt = await db1First(env, 'SELECT * FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      const maxAttempts = 3;
      const attempts = attempt ? attempt.attempts : 0;
      if (attempt && attempt.failed == 1) return json({ success: false, failed: true, message: 'You have failed. Reset the task.' });
      const correct = (task.verify_code || '').trim().toLowerCase();
      const given = (code || '').trim().toLowerCase();
      if (correct === given) {
        await db1Run(env, "INSERT INTO user_tasks (id,user_id,task_id,completed_at) VALUES (?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, task_id]);
        await db1Run(env, 'UPDATE users SET points = points + ?, total_tasks_completed = total_tasks_completed + 1 WHERE id = ?', [task.points_reward, user.id]);
        await db2Run(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, 'task_complete', task.points_reward, '✅ ' + task.title]);
        if (attempt) await db1Run(env, 'DELETE FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
        return json({ success: true, earned: task.points_reward });
      } else {
        const newAttempts = attempts + 1;
        const isFailed = newAttempts >= maxAttempts;
        if (attempt) {
          await db1Run(env, 'UPDATE quiz_attempts SET attempts = ?, failed = ? WHERE user_id = ? AND task_id = ?', [newAttempts, isFailed ? 1 : 0, user.id, task_id]);
        } else {
          await db1Run(env, "INSERT INTO quiz_attempts (id,user_id,task_id,attempts,failed,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, task_id, newAttempts, isFailed ? 1 : 0]);
        }
        const remaining = maxAttempts - newAttempts;
        if (isFailed) return json({ success: false, failed: true, message: 'Wrong code 3 times. Reset the task.' });
        return json({ success: false, failed: false, remaining, message: `Wrong code! ${remaining} attempts left.` });
      }
    }

    // Verify code reset
    if (path === '/api/tasks/verify-reset' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id } = await request.json();
      await db1Run(env, 'DELETE FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      return json({ success: true });
    }

    // Ad task complete (separate endpoint to handle timer)
    if (path === '/api/tasks/ad-complete' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id } = await request.json();
      const task = await db1First(env, 'SELECT * FROM tasks WHERE id = ? AND is_active = 1 AND task_type = "ad"', [task_id]);
      if (!task) return err('Ad task not found');
      const already = await db1First(env, 'SELECT id FROM user_tasks WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      if (already) return err('Already completed');
      await db1Run(env, "INSERT INTO user_tasks (id,user_id,task_id,completed_at) VALUES (?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, task_id]);
      await db1Run(env, 'UPDATE users SET points = points + ?, total_tasks_completed = total_tasks_completed + 1 WHERE id = ?', [task.points_reward, user.id]);
      await db2Run(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, 'task_complete', task.points_reward, '✅ Ad: ' + task.title]);
      return json({ success: true, earned: task.points_reward });
    }

    // ========== OTHER USER ENDPOINTS (DB1 + DB2) ==========
    if (path === '/api/leaderboard' && request.method === 'GET') {
      const lb = await db1All(env, 'SELECT username, total_mined, mining_power FROM users ORDER BY total_mined DESC LIMIT 100');
      return json(lb);
    }
    if (path === '/api/referrals' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const refs = await db1All(env, 'SELECT username, wallet_address, total_mined, created_at FROM users WHERE referred_by = ? ORDER BY created_at DESC LIMIT 30', [user.referral_code]);
      return json(refs);
    }
    if (path === '/api/transactions' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const txs = await db2All(env, 'SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 30', [user.id]);
      return json(txs);
    }
    if (path === '/api/me' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const activeRefs = await db1First(env, 'SELECT COUNT(*) as c FROM users WHERE referred_by = ? AND total_mined > 0', [user.referral_code]);
      if (activeRefs) await db1Run(env, 'UPDATE users SET active_referral_count = ? WHERE id = ?', [parseInt(activeRefs.c), user.id]);
      const updated = await db1First(env, 'SELECT * FROM users WHERE id = ?', [user.id]);
      return json(updated);
    }
    if (path === '/api/stats' && request.method === 'GET') {
      const uc = await db1First(env, 'SELECT COUNT(*) as c FROM users');
      const tm = await db1First(env, 'SELECT SUM(total_mined) as s FROM users');
      return json({ users: parseInt(uc?.c || 0), total_mined: parseInt(tm?.s || 0) });
    }
    if (path === '/api/settings' && request.method === 'GET') {
      const rows = await db1All(env, 'SELECT key, value FROM settings');
      const map = {};
      rows.forEach(r => map[r.key] = r.value);
      return json(map);
    }

    // ========== ADMIN (mix of DB1 and DB2) ==========
    if (path.startsWith('/api/admin/')) {
      if (request.headers.get('X-Admin-Key') !== (env.ADMIN_KEY || 'Admin@2026')) return err('Forbidden', 403);
      const body = request.method !== 'GET' ? await request.json().catch(() => ({})) : {};

      if (path === '/api/admin/dashboard' && request.method === 'GET') {
        const uc = await db1First(env, 'SELECT COUNT(*) as c FROM users');
        const tm = await db1First(env, 'SELECT SUM(total_mined) as s FROM users');
        const tc = await db1First(env, 'SELECT COUNT(*) as c FROM tasks WHERE is_active = 1');
        const mc = await db2First(env, 'SELECT COUNT(*) as c FROM mining_sessions');
        const recent = await db1All(env, 'SELECT * FROM users ORDER BY created_at DESC LIMIT 10');
        return json({ users: uc?.c || 0, total_mined: tm?.s || 0, tasks: tc?.c || 0, sessions: mc?.c || 0, recent });
      }
      if (path === '/api/admin/users' && request.method === 'GET') {
        return json(await db1All(env, `SELECT u.*,
          (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code) AS referral_count,
          (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code AND r.total_mined > 0) AS active_referral_count
          FROM users u ORDER BY u.created_at DESC LIMIT 100`));
      }
      if (path === '/api/admin/users/ban' && request.method === 'POST') {
        await db1Run(env, 'UPDATE users SET is_banned=? WHERE id=?', [body.is_banned ? 1 : 0, body.id]);
        return json({ ok: true });
      }
      if (path === '/api/admin/users/update' && request.method === 'POST') {
        await db1Run(env, 'UPDATE users SET username=?, points=?, mining_power=?, is_banned=? WHERE id=?', [body.username, body.points, body.mining_power, body.is_banned ? 1 : 0, body.id]);
        return json({ ok: true });
      }
      if (path === '/api/admin/tasks' && request.method === 'GET') {
        return json(await db1All(env, 'SELECT * FROM tasks ORDER BY display_order'));
      }
      if (path === '/api/admin/tasks/save' && request.method === 'POST') {
        const { id, title, description, icon, task_type, url, ad_url, quiz_question, quiz_answer, verify_code, points_reward, timer_seconds, display_order, is_active } = body;
        if (id) {
          await db1Run(env, `UPDATE tasks SET title=?, description=?, icon=?, task_type=?, url=?, ad_url=?, quiz_question=?, quiz_answer=?, verify_code=?, points_reward=?, timer_seconds=?, display_order=?, is_active=? WHERE id=?`,
            [title, description||null, icon||'🎯', task_type, url||null, ad_url||null, quiz_question||null, quiz_answer||null, verify_code||null, points_reward, timer_seconds||0, display_order||99, is_active?1:0, id]);
        } else {
          await db1Run(env, `INSERT INTO tasks (id,title,description,icon,task_type,url,ad_url,quiz_question,quiz_answer,verify_code,points_reward,timer_seconds,display_order,is_active,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))`,
            [crypto.randomUUID(), title, description||null, icon||'🎯', task_type, url||null, ad_url||null, quiz_question||null, quiz_answer||null, verify_code||null, points_reward, timer_seconds||0, display_order||99, is_active?1:0]);
        }
        return json({ ok: true });
      }
      if (path === '/api/admin/tasks/delete' && request.method === 'POST') {
        await db1Run(env, 'DELETE FROM tasks WHERE id=?', [body.id]);
        return json({ ok: true });
      }
      if (path === '/api/admin/settings' && request.method === 'POST') {
        for (const [key, value] of Object.entries(body)) {
          await db1Run(env, 'UPDATE settings SET value=? WHERE key=?', [String(value), key]);
        }
        return json({ ok: true });
      }
      if (path === '/api/admin/support' && request.method === 'GET') {
        return json({ messages: await db1All(env, 'SELECT * FROM support_messages ORDER BY created_at DESC LIMIT 100') });
      }
      if (path === '/api/admin/support/reply' && request.method === 'POST') {
        await db1Run(env, "UPDATE support_messages SET admin_reply=?, status='replied', replied_at=datetime('now') WHERE id=?", [body.reply, body.msg_id]);
        return json({ ok: true });
      }
      if (path === '/api/admin/support/close' && request.method === 'POST') {
        await db1Run(env, "UPDATE support_messages SET status='closed' WHERE id=?", [body.msg_id]);
        return json({ ok: true });
      }
      if (path === '/api/admin/reset-requests' && request.method === 'GET') {
        return json({ requests: await db1All(env, "SELECT * FROM password_resets ORDER BY created_at DESC LIMIT 50") });
      }
      if (path === '/api/admin/reset-approve' && request.method === 'POST') {
        const reset = await db1First(env, 'SELECT * FROM password_resets WHERE id=?', [body.reset_id]);
        if (!reset) return err('Request not found');
        await db1Run(env, 'UPDATE users SET password=? WHERE id=?', [reset.new_password_hash, reset.user_id]);
        await db1Run(env, "UPDATE password_resets SET status='approved', resolved_at=datetime('now') WHERE id=?", [body.reset_id]);
        return json({ ok: true });
      }
      if (path === '/api/admin/reset-reject' && request.method === 'POST') {
        await db1Run(env, "UPDATE password_resets SET status='rejected', resolved_at=datetime('now') WHERE id=?", [body.reset_id]);
        return json({ ok: true });
      }
      if (path === '/api/admin/mining' && request.method === 'GET') {
        const sessions = await db2All(env, 'SELECT ms.*, u.username FROM mining_sessions ms LEFT JOIN users u ON ms.user_id = u.id ORDER BY ms.started_at DESC LIMIT 100');
        return json(sessions);
      }
      if (path === '/api/admin/transactions' && request.method === 'GET') {
        const txs = await db2All(env, 'SELECT t.*, u.username FROM transactions t LEFT JOIN users u ON t.user_id = u.id ORDER BY t.created_at DESC LIMIT 100');
        return json(txs);
      }
    }

    return err('Not found', 404);
  } catch (e) {
    console.error('Server error:', e);
    return err('Server error: ' + e.message, 500);
  }
}
