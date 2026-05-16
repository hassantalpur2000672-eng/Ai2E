// ============================================
// Ai2E — 3-DATABASE BACKEND
// DB1 Turso:           Users, Auth, Mining, Transactions, Settings  (TURSO_URL, TURSO_TOKEN)
// DB2 Supabase Tasks:  tasks, user_tasks, quiz_attempts             (SUPABASE_TASKS_URL, SUPABASE_TASKS_KEY)
// DB3 Supabase Mining: leaderboard, referral_log                    (SUPABASE_MINING_URL, SUPABASE_MINING_KEY)
//
// AUTO-INIT: Old users pehli baar Supabase endpoints use karein to
//            unki rows automatically ban jaati hain — koi error nahi
// ============================================

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Admin-Key',
};

// ============================================
// DB1 — TURSO (main database — bilkul original jaisa)
// ============================================

async function turso(env, sql, args = []) {
  const url = env.TURSO_URL.replace('libsql://', 'https://');
  const res = await fetch(`${url}/v2/pipeline`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.TURSO_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      requests: [
        {
          type: 'execute',
          stmt: {
            sql,
            args: args.map(v => {
              if (v === null || v === undefined) return { type: 'null' };
              if (typeof v === 'number') return { type: 'integer', value: String(v) };
              return { type: 'text', value: String(v) };
            })
          }
        },
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

async function dbFirst(env, sql, args = []) { return (await turso(env, sql, args))[0] || null; }
async function dbAll(env, sql, args = [])   { return await turso(env, sql, args); }
async function dbRun(env, sql, args = [])   { return await turso(env, sql, args); }

// ============================================
// DB2 — SUPABASE TASKS (tasks, user_tasks, quiz_attempts)
// ============================================

async function sbTasks(env, endpoint, method = 'GET', body = null) {
  try {
    const res = await fetch(`${env.SUPABASE_TASKS_URL}/rest/v1/${endpoint}`, {
      method,
      headers: {
        'apikey': env.SUPABASE_TASKS_KEY,
        'Authorization': `Bearer ${env.SUPABASE_TASKS_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': method === 'POST' ? 'return=representation' : 'return=minimal',
      },
      body: body ? JSON.stringify(body) : null,
    });
    if (method === 'DELETE' || method === 'PATCH') return { ok: true };
    if (!res.ok) {
      const txt = await res.text();
      console.error('SB Tasks Error:', res.status, txt);
      return method === 'GET' ? [] : { ok: false, error: txt };
    }
    return await res.json();
  } catch (e) {
    console.error('SB Tasks Exception:', e.message);
    return method === 'GET' ? [] : { ok: false };
  }
}

// ============================================
// DB3 — SUPABASE MINING (leaderboard, referral_log)
// ============================================

async function sbMining(env, endpoint, method = 'GET', body = null) {
  try {
    const res = await fetch(`${env.SUPABASE_MINING_URL}/rest/v1/${endpoint}`, {
      method,
      headers: {
        'apikey': env.SUPABASE_MINING_KEY,
        'Authorization': `Bearer ${env.SUPABASE_MINING_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': method === 'POST' ? 'return=representation' : 'return=minimal',
      },
      body: body ? JSON.stringify(body) : null,
    });
    if (method === 'DELETE' || method === 'PATCH') return { ok: true };
    if (!res.ok) {
      const txt = await res.text();
      console.error('SB Mining Error:', res.status, txt);
      return method === 'GET' ? [] : { ok: false, error: txt };
    }
    return await res.json();
  } catch (e) {
    console.error('SB Mining Exception:', e.message);
    return method === 'GET' ? [] : { ok: false };
  }
}

// ============================================
// AUTO-INIT — Old users ka data Supabase mein nahi hota
// Pehli baar use karne par silently bana do
// ============================================

async function ensureLeaderboard(env, user) {
  try {
    const existing = await sbMining(env, `leaderboard?user_id=eq.${user.id}&limit=1`);
    if (existing && existing.length > 0) return;
    await sbMining(env, 'leaderboard', 'POST', {
      user_id: user.id,
      username: user.username,
      total_mined: parseInt(user.total_mined || 0),
      points: parseInt(user.points || 0),
    });
  } catch (e) { console.error('ensureLeaderboard:', e.message); }
}

// ============================================
// PASSWORD & TOKEN — Exactly original se copy
// ============================================

async function legacyHash(password) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + 'AI2E_SALT_2025'));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const hashHex = Array.from(new Uint8Array(derived)).map(b => b.toString(16).padStart(2, '0')).join('');
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${saltHex}:${hashHex}`;
}

async function verifyPassword(password, storedHash) {
  if (!storedHash) return false;
  if (!storedHash.includes(':')) return (await legacyHash(password)) === storedHash;
  const [saltHex, hashHex] = storedHash.split(':');
  if (!saltHex || !hashHex) return false;
  const encoder = new TextEncoder();
  const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
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

// ============================================
// UTILITIES
// ============================================

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' }
  });
}
function err(msg, status = 400) { return json({ error: msg }, status); }

async function getUser(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  const parsed = await verifyToken(token, env);
  if (!parsed) return null;
  return await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [parsed.id]);
}

function adminCheck(request, env) {
  return request.headers.get('X-Admin-Key') === (env.ADMIN_KEY || 'Admin@2026');
}

// ============================================
// MAIN HANDLER
// ============================================

export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  const url  = new URL(request.url);
  const path = url.pathname;

  try {

    // ============================================
    // AUTH — DB1 Turso (original se same)
    // ============================================

    if (path === '/api/auth/register' && request.method === 'POST') {
      const { username, email, password, ref_code, security_question, security_answer } = await request.json();
      if (!username || !email || !password) return err('All fields required');
      if (password.length < 6) return err('Password min 6 chars');

      const emailNorm = email.toLowerCase().trim();
      const exists = await dbFirst(env, 'SELECT id FROM users WHERE LOWER(email) = ?', [emailNorm]);
      if (exists) return err('Email already registered');
      const uExists = await dbFirst(env, 'SELECT id FROM users WHERE username = ?', [username.toLowerCase()]);
      if (uExists) return err('Username taken');

      const hashed = await hashPassword(password);
      const myRef  = 'AI2E' + Math.random().toString(36).substr(2, 6).toUpperCase();
      const id     = crypto.randomUUID();
      const cfg    = await dbFirst(env, "SELECT value FROM settings WHERE key = 'welcome_bonus'");
      const bonus  = parseInt(cfg?.value || '1000');

      // DB1 Turso — user insert (original jaisa)
      await dbRun(env,
        `INSERT INTO users (id,username,email,password_hash,referral_code,referred_by,points,total_mined,mining_power,login_method,mining_claimed,security_question,security_answer,created_at)
         VALUES (?,?,?,?,?,?,?,0,1.0,'email',1,?,?,datetime('now'))`,
        [id, username.toLowerCase(), emailNorm, hashed, myRef, ref_code || null, bonus, security_question || null, security_answer || null]
      );
      await dbRun(env,
        "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
        [crypto.randomUUID(), id, 'welcome_bonus', bonus, '🎉 Welcome bonus']
      );

      // Referral count — DB1 Turso
      if (ref_code) {
        const refUser = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [ref_code]);
        if (refUser && refUser.id !== id) {
          await dbRun(env, 'UPDATE users SET referral_count = referral_count + 1 WHERE id = ?', [refUser.id]);
          // DB3 Supabase Mining — referral log (background, non-blocking)
          Promise.resolve().then(() =>
            sbMining(env, 'referral_log', 'POST', {
              referrer_id: refUser.id,
              referrer_username: refUser.username,
              referred_id: id,
              referred_username: username.toLowerCase(),
              ref_code,
              created_at: new Date().toISOString(),
            })
          ).catch(() => {});
        }
      }

      // DB3 Supabase Mining — leaderboard row (background)
      Promise.resolve().then(() =>
        sbMining(env, 'leaderboard', 'POST', {
          user_id: id,
          username: username.toLowerCase(),
          total_mined: 0,
          points: bonus,
        })
      ).catch(() => {});

      const token = await makeToken(id, env);
      const user  = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [id]);
      return json({ token, user });
    }

    if (path === '/api/auth/login' && request.method === 'POST') {
      const { email, password } = await request.json();
      if (!email || !password) return err('Email and password required');
      const emailNorm = email.toLowerCase().trim();
      let user = await dbFirst(env, 'SELECT * FROM users WHERE email = ?', [emailNorm]);
      if (!user) user = await dbFirst(env, 'SELECT * FROM users WHERE LOWER(email) = ?', [emailNorm]);
      if (!user) return err('Wrong email or password');
      if (user.is_banned == 1) return err('Account banned');

      const valid = await verifyPassword(password, user.password_hash);
      if (!valid) return err('Wrong email or password');

      // Hash upgrade (old format → new PBKDF2)
      if (user.password_hash && !user.password_hash.includes(':')) {
        const newHash = await hashPassword(password);
        await dbRun(env, 'UPDATE users SET password_hash = ? WHERE id = ?', [newHash, user.id]);
      }

      // Auto-init old user in Supabase leaderboard (background — login slow nahi hoga)
      Promise.resolve().then(() => ensureLeaderboard(env, user)).catch(() => {});

      const token = await makeToken(user.id, env);
      return json({ token, user });
    }

    if (path === '/api/auth/wallet' && request.method === 'POST') {
      const { wallet_address, wallet_type, ref_code } = await request.json();
      if (!wallet_address) return err('Wallet address required');
      const addr = wallet_address.toLowerCase();
      let user = await dbFirst(env, 'SELECT * FROM users WHERE wallet_address = ?', [addr]);

      if (!user) {
        const id       = crypto.randomUUID();
        const username = 'w_' + wallet_address.slice(2, 10).toLowerCase();
        const myRef    = 'AI2E' + Math.random().toString(36).substr(2, 6).toUpperCase();
        const cfg      = await dbFirst(env, "SELECT value FROM settings WHERE key = 'welcome_bonus'");
        const bonus    = parseInt(cfg?.value || '1000');

        await dbRun(env,
          `INSERT INTO users (id,username,wallet_address,wallet_type,referral_code,referred_by,points,total_mined,mining_power,login_method,mining_claimed,created_at)
           VALUES (?,?,?,?,?,?,?,0,1.0,?,1,datetime('now'))`,
          [id, username, addr, wallet_type || 'web3', myRef, ref_code || null, bonus, wallet_type || 'wallet']
        );
        await dbRun(env,
          "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
          [crypto.randomUUID(), id, 'welcome_bonus', bonus, '🎉 Welcome bonus']
        );
        if (ref_code) {
          const refUser = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [ref_code]);
          if (refUser) await dbRun(env, 'UPDATE users SET referral_count = referral_count + 1 WHERE id = ?', [refUser.id]);
        }
        user = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [id]);
        Promise.resolve().then(() => ensureLeaderboard(env, user)).catch(() => {});
      }

      if (user.is_banned == 1) return err('Account banned');
      Promise.resolve().then(() => ensureLeaderboard(env, user)).catch(() => {});
      const token = await makeToken(user.id, env);
      return json({ token, user });
    }

    if (path === '/api/auth/forgot-check' && request.method === 'POST') {
      const { email } = await request.json();
      if (!email) return err('Email required');
      const user = await dbFirst(env, 'SELECT id, security_question FROM users WHERE LOWER(email) = ?', [email.toLowerCase().trim()]);
      if (!user) return err('Is email pe koi account nahi mila');
      return json({ ok: true, security_question: user.security_question || null });
    }

    if (path === '/api/auth/forgot-password' && request.method === 'POST') {
      const { email, answer, question, new_password } = await request.json();
      if (!email || !answer) return err('Email aur answer zaroor chahiye');
      if (!new_password || new_password.length < 6) return err('New password min 6 characters');
      const emailNorm = email.toLowerCase().trim();
      const user = await dbFirst(env, 'SELECT id, username FROM users WHERE LOWER(email) = ?', [emailNorm]);
      if (!user) return err('Account nahi mila');
      const existing = await dbFirst(env, "SELECT id FROM password_resets WHERE user_id = ? AND status = 'pending'", [user.id]);
      if (existing) return err('Reset request already pending hai. Admin jald review karega.');
      const hashedNew = await hashPassword(new_password);
      await dbRun(env,
        "INSERT INTO password_resets (id,user_id,username,email,verify_question,verify_answer,new_password_hash,status,created_at) VALUES (?,?,?,?,?,?,?,'pending',datetime('now'))",
        [crypto.randomUUID(), user.id, user.username, emailNorm, question || '', answer, hashedNew]
      );
      return json({ ok: true });
    }

    // ============================================
    // USER — DB1 Turso
    // ============================================

    if (path === '/api/me' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const refs = await dbFirst(env, 'SELECT COUNT(*) as c FROM users WHERE referred_by = ? AND total_mined > 0', [user.referral_code]);
      const activeRefs = parseInt(refs?.c || 0);
      try { await dbRun(env, 'UPDATE users SET active_referral_count = ? WHERE id = ?', [activeRefs, user.id]); } catch (e) {}
      const updated = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [user.id]);
      return json({ ...updated, active_referral_count: activeRefs });
    }

    // ============================================
    // MINING — DB1 Turso (bilkul original jaisa)
    // Leaderboard DB3 background mein sync hoti hai
    // ============================================

    if (path === '/api/mine/start' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      if (user.mining_claimed != 1) return err('Already mining');
      const now = new Date().toISOString();
      await dbRun(env, "UPDATE users SET last_mining_start = ?, mining_claimed = 0 WHERE id = ?", [now, user.id]);
      await dbRun(env, "INSERT INTO mining_sessions (id,user_id,started_at,mining_power) VALUES (?,?,?,?)", [crypto.randomUUID(), user.id, now, user.mining_power]);
      return json({ success: true });
    }

    if (path === '/api/mine/claim' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      if (user.mining_claimed == 1) return err('Nothing to claim');

      const cfgRows = await dbAll(env, "SELECT key, value FROM settings WHERE key IN ('mining_duration_hours','mining_coins_per_hour')");
      const cfgMap  = {};
      cfgRows.forEach(r => cfgMap[r.key] = r.value);
      const durMs   = parseInt(cfgMap.mining_duration_hours || '24') * 3600000;
      const cpm     = parseFloat(cfgMap.mining_coins_per_hour || '10') * parseFloat(user.mining_power) / 3600000;
      const elapsed = Math.min(Date.now() - new Date(user.last_mining_start).getTime(), durMs);
      const earned  = Math.floor(cpm * elapsed);

      if (earned < 100) return err('Mine at least 100 points first');

      const newPts   = parseInt(user.points || 0) + earned;
      const newMined = parseInt(user.total_mined || 0) + earned;

      // DB1 Turso — bilkul original jaisa
      await dbRun(env, 'UPDATE users SET points = ?, total_mined = ?, total_claimed = total_claimed + ?, mining_claimed = 1 WHERE id = ?', [newPts, newMined, earned, user.id]);
      await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, 'mining_claim', earned, '⛏️ Mining claim']);
      await dbRun(env, "UPDATE mining_sessions SET claimed_at = datetime('now'), coins_earned = ?, is_claimed = 1 WHERE user_id = ? AND is_claimed = 0", [earned, user.id]);

      // Referral tree L1=50%, L2=25%, L3=10% — DB1 Turso (original jaisa)
      if (user.referred_by) {
        const L1 = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [user.referred_by]);
        if (L1) {
          const l1Bonus = Math.floor(earned * 0.50);
          if (l1Bonus > 0) {
            await dbRun(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l1Bonus, L1.id]);
            await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), L1.id, 'refer_mining_l1', l1Bonus, '⛏️ L1 50%: @' + user.username]);
            if (L1.referred_by) {
              const L2 = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [L1.referred_by]);
              if (L2) {
                const l2Bonus = Math.floor(earned * 0.25);
                if (l2Bonus > 0) {
                  await dbRun(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l2Bonus, L2.id]);
                  await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), L2.id, 'refer_mining_l2', l2Bonus, '🌿 L2 25%: @' + user.username]);
                  if (L2.referred_by) {
                    const L3 = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [L2.referred_by]);
                    if (L3) {
                      const l3Bonus = Math.floor(earned * 0.10);
                      if (l3Bonus > 0) {
                        await dbRun(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l3Bonus, L3.id]);
                        await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), L3.id, 'refer_mining_l3', l3Bonus, '🔥 L3 10%: @' + user.username]);
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      // DB3 Leaderboard sync (background — claim fail nahi hogi agar ye fail ho)
      Promise.resolve().then(async () => {
        await ensureLeaderboard(env, user);
        await sbMining(env, `leaderboard?user_id=eq.${user.id}`, 'PATCH', {
          total_mined: newMined,
          points: newPts,
        });
      }).catch(() => {});

      return json({ success: true, earned });
    }

    if (path === '/api/mine/claim-and-start' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      if (user.mining_claimed == 1) return err('Nothing to claim');

      const cfgRows = await dbAll(env, "SELECT key, value FROM settings WHERE key IN ('mining_duration_hours','mining_coins_per_hour')");
      const cfgMap  = {};
      cfgRows.forEach(r => cfgMap[r.key] = r.value);
      const durMs   = parseInt(cfgMap.mining_duration_hours || '24') * 3600000;
      const cpm     = parseFloat(cfgMap.mining_coins_per_hour || '10') * parseFloat(user.mining_power) / 3600000;
      const elapsed = Math.min(Date.now() - new Date(user.last_mining_start).getTime(), durMs);
      const earned  = Math.floor(cpm * elapsed);

      if (earned < 100) return err('Mine at least 100 points first');

      const newPts   = parseInt(user.points || 0) + earned;
      const newMined = parseInt(user.total_mined || 0) + earned;
      const now      = new Date().toISOString();

      // DB1 Turso — claim + auto start (original jaisa)
      await dbRun(env, 'UPDATE users SET points = ?, total_mined = ?, total_claimed = total_claimed + ?, mining_claimed = 0, last_mining_start = ? WHERE id = ?', [newPts, newMined, earned, now, user.id]);
      await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, 'mining_claim', earned, '⛏️ Mining claim']);
      await dbRun(env, "UPDATE mining_sessions SET claimed_at = datetime('now'), coins_earned = ?, is_claimed = 1 WHERE user_id = ? AND is_claimed = 0", [earned, user.id]);
      await dbRun(env, "INSERT INTO mining_sessions (id,user_id,started_at,mining_power) VALUES (?,?,?,?)", [crypto.randomUUID(), user.id, now, user.mining_power]);

      // Referral tree — DB1 Turso
      if (user.referred_by) {
        const L1 = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [user.referred_by]);
        if (L1) {
          const l1Bonus = Math.floor(earned * 0.50);
          if (l1Bonus > 0) {
            await dbRun(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l1Bonus, L1.id]);
            await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), L1.id, 'refer_mining_l1', l1Bonus, '⛏️ L1 50%: @' + user.username]);
            if (L1.referred_by) {
              const L2 = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [L1.referred_by]);
              if (L2) {
                const l2Bonus = Math.floor(earned * 0.25);
                if (l2Bonus > 0) {
                  await dbRun(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l2Bonus, L2.id]);
                  await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), L2.id, 'refer_mining_l2', l2Bonus, '🌿 L2 25%: @' + user.username]);
                  if (L2.referred_by) {
                    const L3 = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [L2.referred_by]);
                    if (L3) {
                      const l3Bonus = Math.floor(earned * 0.10);
                      if (l3Bonus > 0) {
                        await dbRun(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l3Bonus, L3.id]);
                        await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), L3.id, 'refer_mining_l3', l3Bonus, '🔥 L3 10%: @' + user.username]);
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      // DB3 Leaderboard sync (background)
      Promise.resolve().then(async () => {
        await ensureLeaderboard(env, user);
        await sbMining(env, `leaderboard?user_id=eq.${user.id}`, 'PATCH', { total_mined: newMined, points: newPts });
      }).catch(() => {});

      const updatedUser = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [user.id]);
      return json({ success: true, earned, user: updatedUser, mining_started: true, last_mining_start: now });
    }

    // ============================================
    // TASKS — DB2 Supabase Tasks
    // Auto-init: old users ke liye user_tasks rows nahi hoti — first call pe kaam karta hai
    // ============================================

    if (path === '/api/tasks' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      // DB2 Supabase Tasks
      const tasks = await sbTasks(env, 'tasks?is_active=eq.true&order=display_order.asc');
      const done  = await sbTasks(env, `user_tasks?user_id=eq.${user.id}`);
      return json({ tasks, done: done.map(d => d.task_id) });
    }

    if (path === '/api/tasks/complete' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id } = await request.json();

      // DB2 Supabase Tasks — task check
      const taskArr = await sbTasks(env, `tasks?id=eq.${task_id}&is_active=eq.true`);
      const task    = taskArr[0];
      if (!task) return err('Task not found');

      const alreadyArr = await sbTasks(env, `user_tasks?user_id=eq.${user.id}&task_id=eq.${task_id}`);
      if (alreadyArr && alreadyArr.length > 0) return err('Already completed');

      if (task.task_type === 'quiz') return err('Quiz tasks require answer verification');
      if (task.verify_code && task.verify_code.trim() !== '') return err('This task requires a secret code to complete');

      // DB2 Supabase Tasks — completion save
      await sbTasks(env, 'user_tasks', 'POST', {
        id: crypto.randomUUID(),
        user_id: user.id,
        task_id,
        completed_at: new Date().toISOString(),
      });

      // DB1 Turso — points update
      await dbRun(env, 'UPDATE users SET points = points + ?, total_tasks_completed = total_tasks_completed + 1 WHERE id = ?', [task.points_reward, user.id]);
      await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, 'task_complete', task.points_reward, '✅ ' + task.title]);

      // DB3 Leaderboard sync (background)
      Promise.resolve().then(async () => {
        const updated = await dbFirst(env, 'SELECT points, total_mined FROM users WHERE id = ?', [user.id]);
        await ensureLeaderboard(env, user);
        await sbMining(env, `leaderboard?user_id=eq.${user.id}`, 'PATCH', { points: updated.points });
      }).catch(() => {});

      return json({ success: true, earned: task.points_reward });
    }

    if (path === '/api/tasks/verify-code' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id, code } = await request.json();
      if (!task_id || !code) return err('Task ID aur code zaroori hain');

      const taskArr = await sbTasks(env, `tasks?id=eq.${task_id}&is_active=eq.true`);
      const task    = taskArr[0];
      if (!task) return err('Task nahi mila');

      const alreadyArr = await sbTasks(env, `user_tasks?user_id=eq.${user.id}&task_id=eq.${task_id}`);
      if (alreadyArr && alreadyArr.length > 0) return err('Already completed');

      const attemptArr = await sbTasks(env, `quiz_attempts?user_id=eq.${user.id}&task_id=eq.${task_id}`);
      const attempt    = attemptArr[0] || null;
      const maxAttempts = 3;
      if (attempt && attempt.failed == true) return json({ success: false, failed: true, message: 'Aap fail ho chuke hain. Dobara task shuru karen.' });

      const isCorrect = (task.verify_code || '').trim().toLowerCase() === (code || '').trim().toLowerCase();
      if (isCorrect) {
        await sbTasks(env, 'user_tasks', 'POST', { id: crypto.randomUUID(), user_id: user.id, task_id, completed_at: new Date().toISOString() });
        await dbRun(env, 'UPDATE users SET points = points + ?, total_tasks_completed = total_tasks_completed + 1 WHERE id = ?', [task.points_reward, user.id]);
        await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, 'task_complete', task.points_reward, '✅ ' + task.title]);
        if (attempt) await sbTasks(env, `quiz_attempts?user_id=eq.${user.id}&task_id=eq.${task_id}`, 'DELETE');
        return json({ success: true, earned: task.points_reward });
      } else {
        const newAttempts = (attempt?.attempts || 0) + 1;
        const isFailed    = newAttempts >= maxAttempts;
        if (attempt) {
          await sbTasks(env, `quiz_attempts?user_id=eq.${user.id}&task_id=eq.${task_id}`, 'PATCH', { attempts: newAttempts, failed: isFailed });
        } else {
          await sbTasks(env, 'quiz_attempts', 'POST', { id: crypto.randomUUID(), user_id: user.id, task_id, attempts: newAttempts, failed: isFailed, created_at: new Date().toISOString() });
        }
        const remaining = maxAttempts - newAttempts;
        if (isFailed) return json({ success: false, failed: true, message: 'Galat code! 3 baar fail ho gaye. Dobara task shuru karen.' });
        return json({ success: false, failed: false, remaining, message: `Galat code! ${remaining} maukay baki hain.` });
      }
    }

    if (path === '/api/tasks/verify-reset' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id } = await request.json();
      await sbTasks(env, `quiz_attempts?user_id=eq.${user.id}&task_id=eq.${task_id}`, 'DELETE');
      return json({ success: true });
    }

    if (path === '/api/tasks/quiz-verify' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id, answer } = await request.json();
      if (!task_id || answer === undefined) return err('Missing fields');

      const taskArr = await sbTasks(env, `tasks?id=eq.${task_id}&is_active=eq.true&task_type=eq.quiz`);
      const task    = taskArr[0];
      if (!task) return err('Quiz task not found');

      const alreadyArr = await sbTasks(env, `user_tasks?user_id=eq.${user.id}&task_id=eq.${task_id}`);
      if (alreadyArr && alreadyArr.length > 0) return err('Already completed');

      const attemptArr = await sbTasks(env, `quiz_attempts?user_id=eq.${user.id}&task_id=eq.${task_id}`);
      const attempt    = attemptArr[0] || null;
      const maxAttempts = 3;
      if (attempt && attempt.failed == true) return json({ success: false, failed: true, message: 'Aap fail ho chuke hain. Dobara task shuru karen.' });

      const isCorrect = (task.quiz_answer || '').trim().toLowerCase() === (answer || '').trim().toLowerCase();
      if (isCorrect) {
        await sbTasks(env, 'user_tasks', 'POST', { id: crypto.randomUUID(), user_id: user.id, task_id, completed_at: new Date().toISOString() });
        await dbRun(env, 'UPDATE users SET points = points + ?, total_tasks_completed = total_tasks_completed + 1 WHERE id = ?', [task.points_reward, user.id]);
        await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, 'task_complete', task.points_reward, '✅ Quiz: ' + task.title]);
        if (attempt) await sbTasks(env, `quiz_attempts?user_id=eq.${user.id}&task_id=eq.${task_id}`, 'DELETE');
        return json({ success: true, earned: task.points_reward });
      } else {
        const newAttempts = (attempt?.attempts || 0) + 1;
        const isFailed    = newAttempts >= maxAttempts;
        if (attempt) {
          await sbTasks(env, `quiz_attempts?user_id=eq.${user.id}&task_id=eq.${task_id}`, 'PATCH', { attempts: newAttempts, failed: isFailed });
        } else {
          await sbTasks(env, 'quiz_attempts', 'POST', { id: crypto.randomUUID(), user_id: user.id, task_id, attempts: newAttempts, failed: isFailed, created_at: new Date().toISOString() });
        }
        const remaining = maxAttempts - newAttempts;
        if (isFailed) return json({ success: false, failed: true, message: 'Galat jawab! 3 baar fail ho gaye. Dobara task shuru karen.' });
        return json({ success: false, failed: false, remaining, message: `Galat jawab! ${remaining} maukay baki hain.` });
      }
    }

    if (path === '/api/tasks/quiz-reset' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id } = await request.json();
      await sbTasks(env, `quiz_attempts?user_id=eq.${user.id}&task_id=eq.${task_id}`, 'DELETE');
      return json({ success: true });
    }

    // ============================================
    // LEADERBOARD — DB3 Supabase Mining
    // ============================================

    if (path === '/api/leaderboard' && request.method === 'GET') {
      const lb = await sbMining(env, 'leaderboard?order=total_mined.desc&limit=100');
      return json(lb);
    }

    // ============================================
    // REFERRALS — DB1 Turso (original jaisa)
    // ============================================

    if (path === '/api/referrals' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const results = await dbAll(env, 'SELECT username,wallet_address,total_mined,created_at FROM users WHERE referred_by = ? ORDER BY created_at DESC LIMIT 30', [user.referral_code]);
      return json(results);
    }

    if (path === '/api/transactions' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      return json(await dbAll(env, 'SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 30', [user.id]));
    }

    if (path === '/api/settings' && request.method === 'GET') {
      const results = await dbAll(env, 'SELECT key, value FROM settings');
      const map = {};
      results.forEach(r => map[r.key] = r.value);
      return json(map);
    }

    if (path === '/api/stats' && request.method === 'GET') {
      const uc = await dbFirst(env, 'SELECT COUNT(*) as c FROM users');
      const tm = await dbFirst(env, 'SELECT SUM(total_mined) as s FROM users');
      return json({ users: parseInt(uc?.c || 0), total_mined: parseInt(tm?.s || 0) });
    }

    // ============================================
    // SUPPORT — DB1 Turso (original jaisa)
    // ============================================

    if (path === '/api/support/send' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { message } = await request.json();
      if (!message || message.trim().length < 5) return err('Message bahut chota hai');
      const last = await dbFirst(env, "SELECT id FROM support_messages WHERE user_id = ? AND created_at > datetime('now','-24 hours')", [user.id]);
      if (last) return err('24 ghante mein sirf 1 message bhej sakte hain');
      await dbRun(env,
        "INSERT INTO support_messages (id,user_id,username,email,message,status,created_at) VALUES (?,?,?,?,?,'open',datetime('now'))",
        [crypto.randomUUID(), user.id, user.username, user.email || '', message.trim()]
      );
      return json({ ok: true });
    }

    if (path === '/api/support/my-messages' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      return json(await dbAll(env, 'SELECT * FROM support_messages WHERE user_id = ? ORDER BY created_at DESC LIMIT 10', [user.id]));
    }

    // ============================================
    // ADMIN — DB1 Turso + DB2 Tasks + DB3 Mining
    // ============================================

    if (path.startsWith('/api/admin/')) {
      if (!adminCheck(request, env)) return err('Forbidden', 403);
      const body = request.method !== 'GET' ? await request.json().catch(() => ({})) : {};

      if (path === '/api/admin/dashboard' && request.method === 'GET') {
        const [uc, tm, tc, mc] = await Promise.all([
          dbFirst(env, 'SELECT COUNT(*) as c FROM users'),
          dbFirst(env, 'SELECT SUM(total_mined) as s FROM users'),
          sbTasks(env, 'tasks?is_active=eq.true&select=id'),
          dbFirst(env, 'SELECT COUNT(*) as c FROM mining_sessions'),
        ]);
        const recent = await dbAll(env, 'SELECT id,username,email,wallet_address,points,total_mined,mining_power,created_at,login_method,is_banned,(SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code AND r.total_mined > 0) AS active_referral_count FROM users u ORDER BY created_at DESC LIMIT 10');
        return json({ users: parseInt(uc?.c||0), total_mined: parseInt(tm?.s||0), tasks: Array.isArray(tc) ? tc.length : 0, sessions: parseInt(mc?.c||0), recent });
      }

      if (path === '/api/admin/users' && request.method === 'GET') {
        return json(await dbAll(env, `SELECT u.*,
          (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code) AS referral_count,
          (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code AND r.total_mined > 0) AS active_referral_count
          FROM users u ORDER BY u.created_at DESC LIMIT 100`));
      }

      if (path === '/api/admin/users/ban' && request.method === 'POST') {
        if (!body.id) return err('Invalid');
        await dbRun(env, 'UPDATE users SET is_banned=? WHERE id=?', [body.is_banned ? 1 : 0, body.id]);
        return json({ ok: true });
      }

      if (path === '/api/admin/users/update' && request.method === 'POST') {
        await dbRun(env, 'UPDATE users SET username=?,points=?,mining_power=?,is_banned=? WHERE id=?', [body.username, body.points, body.mining_power, body.is_banned ? 1 : 0, body.id]);
        return json({ success: true });
      }

      // DB2 Supabase Tasks — task management
      if (path === '/api/admin/tasks' && request.method === 'GET') {
        return json(await sbTasks(env, 'tasks?order=display_order.asc'));
      }

      if (path === '/api/admin/tasks/save' && request.method === 'POST') {
        const { id, title, description, icon, task_type, url, ad_url, quiz_question, quiz_answer, verify_code, points_reward, timer_seconds, display_order, is_active } = body;
        const taskData = { title, description: description||null, icon: icon||'🎯', task_type, url: url||null, ad_url: ad_url||null, quiz_question: quiz_question||null, quiz_answer: quiz_answer||null, verify_code: verify_code||null, points_reward, timer_seconds: timer_seconds||0, display_order: display_order||99, is_active: is_active !== false };
        if (id) {
          await sbTasks(env, `tasks?id=eq.${id}`, 'PATCH', taskData);
        } else {
          await sbTasks(env, 'tasks', 'POST', { id: crypto.randomUUID(), ...taskData, created_at: new Date().toISOString() });
        }
        return json({ success: true });
      }

      if (path === '/api/admin/tasks/delete' && request.method === 'POST') {
        await sbTasks(env, `tasks?id=eq.${body.id}`, 'DELETE');
        return json({ success: true });
      }

      if (path === '/api/admin/settings' && request.method === 'POST') {
        for (const [key, value] of Object.entries(body)) {
          await dbRun(env, 'UPDATE settings SET value=? WHERE key=?', [String(value), key]);
        }
        return json({ success: true });
      }

      if (path === '/api/admin/support' && request.method === 'GET') {
        return json({ messages: await dbAll(env, 'SELECT * FROM support_messages ORDER BY created_at DESC LIMIT 100') });
      }

      if (path === '/api/admin/support/reply' && request.method === 'POST') {
        await dbRun(env, "UPDATE support_messages SET admin_reply=?,status='replied',replied_at=datetime('now') WHERE id=?", [body.reply, body.msg_id]);
        return json({ ok: true });
      }

      if (path === '/api/admin/support/close' && request.method === 'POST') {
        await dbRun(env, "UPDATE support_messages SET status='closed' WHERE id=?", [body.msg_id]);
        return json({ ok: true });
      }

      if (path === '/api/admin/reset-requests' && request.method === 'GET') {
        return json({ requests: await dbAll(env, "SELECT * FROM password_resets ORDER BY created_at DESC LIMIT 50") });
      }

      if (path === '/api/admin/reset-approve' && request.method === 'POST') {
        if (!body.reset_id) return err('Invalid');
        const reset = await dbFirst(env, 'SELECT * FROM password_resets WHERE id=?', [body.reset_id]);
        if (!reset) return err('Request nahi mili');
        const pwHash = reset.new_password_hash || await hashPassword('reset123');
        await dbRun(env, 'UPDATE users SET password_hash=? WHERE id=?', [pwHash, reset.user_id]);
        await dbRun(env, "UPDATE password_resets SET status='approved',resolved_at=datetime('now') WHERE id=?", [body.reset_id]);
        return json({ ok: true });
      }

      if (path === '/api/admin/reset-reject' && request.method === 'POST') {
        await dbRun(env, "UPDATE password_resets SET status='rejected',resolved_at=datetime('now') WHERE id=?", [body.reset_id]);
        return json({ ok: true });
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

      if (path === '/api/admin/mining' && request.method === 'GET') {
        return json(await dbAll(env, 'SELECT ms.*,u.username FROM mining_sessions ms LEFT JOIN users u ON ms.user_id=u.id ORDER BY ms.started_at DESC LIMIT 100'));
      }

      if (path === '/api/admin/transactions' && request.method === 'GET') {
        return json(await dbAll(env, 'SELECT t.*,u.username FROM transactions t LEFT JOIN users u ON t.user_id=u.id ORDER BY t.created_at DESC LIMIT 100'));
      }

      if (path === '/api/admin/ads' && request.method === 'GET') {
        return json(await dbAll(env, 'SELECT * FROM ads ORDER BY created_at DESC'));
      }

      if (path === '/api/admin/ads/save' && request.method === 'POST') {
        const { id, name, network, position, code, url, pages, is_active, type } = body;
        const pg  = Array.isArray(pages) ? pages.join(',') : (pages || 'index,blog,policies,vision');
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

      // DB3 Supabase Mining — leaderboard admin view
      if (path === '/api/admin/leaderboard' && request.method === 'GET') {
        return json(await sbMining(env, 'leaderboard?order=total_mined.desc&limit=100'));
      }
    }

    // DB Init — ek baar run karo, sab tables ban jayen
    if (path === '/api/admin/db-init' && request.method === 'POST') {
      await dbRun(env, `CREATE TABLE IF NOT EXISTS password_resets (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, username TEXT, email TEXT, verify_question TEXT, verify_answer TEXT, new_password_hash TEXT, status TEXT DEFAULT 'pending', created_at TEXT, resolved_at TEXT)`);
      await dbRun(env, `CREATE TABLE IF NOT EXISTS support_messages (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, username TEXT, email TEXT, message TEXT, status TEXT DEFAULT 'open', admin_reply TEXT, replied_at TEXT, created_at TEXT)`);
      try { await dbRun(env, 'ALTER TABLE users ADD COLUMN security_question TEXT'); } catch (e) {}
      try { await dbRun(env, 'ALTER TABLE users ADD COLUMN security_answer TEXT'); } catch (e) {}
      try { await dbRun(env, 'ALTER TABLE users ADD COLUMN active_referral_count INTEGER DEFAULT 0'); } catch (e) {}
      try { await dbRun(env, 'ALTER TABLE password_resets ADD COLUMN new_password_hash TEXT'); } catch (e) {}
      return json({ success: true, message: 'Tables ready' });
    }

    return err('Not found', 404);

  } catch (e) {
    console.error('Server error:', e);
    return err('Server error: ' + e.message, 500);
  }
}
