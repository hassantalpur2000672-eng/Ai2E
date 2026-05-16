// ============================================
// Ai2E — 3-DATABASE BACKEND
// DB1 Turso:           Auth, Users, Transactions, Mining sessions (TURSO_URL, TURSO_TOKEN)
// DB2 Supabase Tasks:  Tasks, Task completions, Leaderboard     (SUPABASE_TASKS_URL, SUPABASE_TASKS_KEY)
// DB3 Supabase Mining: Mining claims, User points, Referrals    (SUPABASE_MINING_URL, SUPABASE_MINING_KEY)
//
// OLD USERS: Turso mein exist karte hain — pehli baar Supabase use karne par auto-init hoga
// NEW USERS: Register pe teeno DBs mein init hoga
// ============================================

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Admin-Key',
};

// ============================================
// DB1 — TURSO HELPER
// ============================================

async function turso(env, sql, args = []) {
  try {
    const url = env.TURSO_URL.replace('libsql://', 'https://');
    const res = await fetch(`${url}/v2/pipeline`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${env.TURSO_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        requests: [
          { type: 'execute', stmt: { sql, args: args.map(v => {
            if (v === null || v === undefined) return { type: 'null' };
            if (typeof v === 'number') return { type: 'integer', value: String(v) };
            return { type: 'text', value: String(v) };
          })}},
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
  } catch (e) { console.error('Turso Error:', e); throw e; }
}

async function dbFirst(env, sql, args = []) { return (await turso(env, sql, args))[0] || null; }
async function dbAll(env, sql, args = [])   { return await turso(env, sql, args); }
async function dbRun(env, sql, args = [])   { return await turso(env, sql, args); }

// ============================================
// DB2 — SUPABASE TASKS HELPER
// ============================================

async function sbTasks(env, endpoint, method = 'GET', body = null) {
  try {
    const res = await fetch(`${env.SUPABASE_TASKS_URL}/rest/v1/${endpoint}`, {
      method,
      headers: {
        'apikey': env.SUPABASE_TASKS_KEY,
        'Authorization': `Bearer ${env.SUPABASE_TASKS_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation'
      },
      body: body ? JSON.stringify(body) : null
    });
    if (!res.ok) throw new Error(`SB Tasks ${res.status}: ${await res.text()}`);
    return ['DELETE','PATCH'].includes(method) ? { ok: true } : await res.json();
  } catch (e) { console.error('SB Tasks Error:', e); return method === 'GET' ? [] : { ok: false }; }
}

// ============================================
// DB3 — SUPABASE MINING HELPER
// ============================================

async function sbMining(env, endpoint, method = 'GET', body = null) {
  try {
    const res = await fetch(`${env.SUPABASE_MINING_URL}/rest/v1/${endpoint}`, {
      method,
      headers: {
        'apikey': env.SUPABASE_MINING_KEY,
        'Authorization': `Bearer ${env.SUPABASE_MINING_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation'
      },
      body: body ? JSON.stringify(body) : null
    });
    if (!res.ok) throw new Error(`SB Mining ${res.status}: ${await res.text()}`);
    return ['DELETE','PATCH'].includes(method) ? { ok: true } : await res.json();
  } catch (e) { console.error('SB Mining Error:', e); return method === 'GET' ? [] : { ok: false }; }
}

// ============================================
// AUTO-INIT — OLD USER KO NEW DBs MEIN BANANA
// Jab bhi koi Supabase operation hone wali ho, pehle check karo row hai ya nahi
// Agar nahi hai (old user) to Turso data se bana do — silently, automatically
// ============================================

async function ensureUserInMiningDB(env, user) {
  try {
    // Email ya wallet address use karo identifier ke liye
    const userIdentifier = user.email || user.wallet_address;
    if (!userIdentifier) {
      console.log('No valid identifier for user init in mining DB');
      return;
    }
    
    // user_points row check karo
    const existing = await sbMining(env, `user_points?user_email=eq.${encodeURIComponent(userIdentifier)}&limit=1`);
    if (existing && existing.length > 0) return; // already hai

    // Nahi hai — old user hai, Turso se data lekar init karo
    await sbMining(env, 'user_points', 'POST', {
      user_email: userIdentifier,
      total_points: parseInt(user.total_mined || 0),   // Turso ka purana total
      mining_balance: parseInt(user.points || 0),        // Turso ka points balance
      daily_streak: 0
    });
    console.log(`Auto-init mining DB for old user: ${userIdentifier}`);
  } catch (e) {
    console.error('ensureUserInMiningDB error:', e);
  }
}

async function ensureUserInTasksDB(env, user) {
  try {
    // Email ya wallet address use karo
    const userIdentifier = user.email || user.wallet_address;
    const username = user.username || 'user_' + (userIdentifier || '').substring(0, 8);
    
    if (!userIdentifier) {
      console.log('No valid identifier for user init in tasks DB');
      return;
    }
    
    // Tasks mein user-specific row nahi hoti (task_completions mein email se track hota hai)
    // Leaderboard row ensure karo
    const existing = await sbTasks(env, `leaderboard?user_email=eq.${encodeURIComponent(userIdentifier)}&limit=1`);
    if (existing && existing.length > 0) return;

    await sbTasks(env, 'leaderboard', 'POST', {
      user_email: userIdentifier,
      username: username,
      total_points: parseInt(user.total_mined || 0)
    });
    console.log(`Auto-init tasks DB for old user: ${userIdentifier}`);
  } catch (e) {
    console.error('ensureUserInTasksDB error:', e);
  }
}

// ============================================
// SAFE WRAPPER — Error hone pe crash nahi karna
// ============================================

async function safe(fn, def = null) {
  try { return await fn(); } catch (e) { console.error('Safe failed:', e); return def; }
}

// ============================================
// PASSWORD & TOKEN UTILS
// ============================================

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
  if (!saltHex || !hashHex) return false;
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

// ============================================
// UTILITIES
// ============================================

// Cache headers — browser automatically cache karta hai, har baar server hit nahi hota
function json(data, status = 200, cacheSeconds = 0) {
  const cacheHeader = cacheSeconds > 0
    ? { 'Cache-Control': `private, max-age=${cacheSeconds}` }
    : { 'Cache-Control': 'no-store' };
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json', ...cacheHeader }
  });
}

function jsonPublic(data, status = 200, cacheSeconds = 60) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS,
      'Content-Type': 'application/json',
      'Cache-Control': `public, max-age=${cacheSeconds}, stale-while-revalidate=${cacheSeconds * 2}`
    }
  });
}

function err(msg, status = 400) {
  return new Response(JSON.stringify({ error: msg }), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
  });
}

// Token in-memory cache — same request mein dobara Turso nahi jaata
const _tokenCache = new Map();

async function getUser(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  if (_tokenCache.has(token)) return _tokenCache.get(token);
  const parsed = await verifyToken(token, env);
  if (!parsed) return null;
  const user = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [parsed.id]);
  _tokenCache.set(token, user);
  return user;
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
    // AUTH — DB1 Turso
    // ============================================

    // Register — /api/register ya /api/auth/register dono
    if ((path === '/api/register' || path === '/api/auth/register') && request.method === 'POST') {
      const body = await request.json();
      const { username, password } = body;
      const email        = (body.email || '').toLowerCase().trim();
      const refCode      = body.referralCode || body.ref_code || null;
      const walletAddr   = body.wallet || body.wallet_address || null;
      const walletType   = body.walletType || body.wallet_type || null;
      const secQ         = body.securityQuestion || body.security_question || null;
      const secA         = body.securityAnswer || body.security_answer || null;

      if (!username || !email || !password) return err('Missing fields');
      if (password.length < 6) return err('Password min 6 chars');

      const emailExists = await dbFirst(env, 'SELECT id FROM users WHERE LOWER(email) = ?', [email]);
      if (emailExists) return err('Email already registered', 409);
      const userExists = await dbFirst(env, 'SELECT id FROM users WHERE LOWER(username) = ?', [username.toLowerCase()]);
      if (userExists) return err('Username taken', 409);

      const hashed    = await hashPassword(password);
      const userId    = crypto.randomUUID();
      const myRefCode = 'AI2E' + Math.random().toString(36).substr(2, 6).toUpperCase();

      // Turso mein user banao
      const cfg   = await dbFirst(env, "SELECT value FROM settings WHERE key = 'welcome_bonus'");
      const bonus = parseInt(cfg?.value || '1000');

      // Register query — sirf wo columns use karo jo exist karte hain
      await dbRun(env,
        `INSERT INTO users (id, username, email, password, wallet_address, wallet_type,
         referral_code, referred_by, security_question, security_answer,
         points, total_mined, mining_power, mining_claimed, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1.0, 1, datetime('now'))`,
        [userId, username.toLowerCase(), email, hashed, walletAddr, walletType,
         myRefCode, refCode, secQ, secA, bonus]
      );
      
      await dbRun(env,
        "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
        [crypto.randomUUID(), userId, 'welcome_bonus', bonus, '🎉 Welcome bonus']
      );

      // Referral count Turso mein update
      if (refCode) {
        safe(async () => {
          const ref = await dbFirst(env, 'SELECT id, email FROM users WHERE referral_code = ?', [refCode]);
          if (ref && ref.id !== userId) {
            await dbRun(env, 'UPDATE users SET referral_count = COALESCE(referral_count,0) + 1 WHERE id = ?', [ref.id]);
            // Supabase Mining mein referral log
            await sbMining(env, 'referrals', 'POST', {
              referrer_email: ref.email,
              referred_email: email,
              referral_code: refCode,
              bonus_points: 500
            });
          }
        });
      }

      // Supabase Mining mein init (new user — points 0 se start)
      safe(async () => {
        await sbMining(env, 'user_points', 'POST', {
          user_email: email,
          total_points: 0,
          mining_balance: 0,
          daily_streak: 0
        });
      });

      // Supabase Tasks leaderboard mein init
      safe(async () => {
        await sbTasks(env, 'leaderboard', 'POST', {
          user_email: email,
          username: username.toLowerCase(),
          total_points: 0
        });
      });

      const token = await makeToken(userId, env);
      const newUser = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [userId]);
      return json({ success: true, token, user: newUser });
    }

    // Login — /api/login ya /api/auth/login dono
    if ((path === '/api/login' || path === '/api/auth/login') && request.method === 'POST') {
      const { email: rawEmail, password } = await request.json();
      if (!rawEmail || !password) return err('Email aur password chahiye');
      const email = rawEmail.toLowerCase().trim();

      const user = await dbFirst(env, 'SELECT * FROM users WHERE LOWER(email) = ?', [email]);
      if (!user) return err('Wrong email or password', 401);
      if (user.is_banned == 1) return err('Account banned', 403);

      // Password field flexible — password ya password_hash dono check karo
      const storedHash = user.password || user.password_hash;
      if (!storedHash) return err('Password not set for this account', 500);
      
      const valid = await verifyPassword(password, storedHash);
      if (!valid) return err('Wrong email or password', 401);

      // Old hash format? Upgrade silently (column exist kare toh hi)
      if (storedHash && !storedHash.includes(':')) {
        safe(async () => {
          const newHash = await hashPassword(password);
          // Try password column, agar nahi hai toh password_hash try karo
          try {
            await dbRun(env, 'UPDATE users SET password = ? WHERE id = ?', [newHash, user.id]);
          } catch (e1) {
            try {
              await dbRun(env, 'UPDATE users SET password_hash = ? WHERE id = ?', [newHash, user.id]);
            } catch (e2) {
              console.log('Could not update password hash:', e2.message);
            }
          }
        });
      }

      // Last login update (safe wrapper — column missing ho toh crash na ho)
      safe(async () => {
        await dbRun(env, "UPDATE users SET last_login = datetime('now') WHERE id = ?", [user.id]);
      });

      // Auto-init old user in Supabase DBs (background mein — login slow nahi hoga)
      safe(() => ensureUserInMiningDB(env, user));
      safe(() => ensureUserInTasksDB(env, user));

      const token = await makeToken(user.id, env);
      return json({ success: true, token, user });
    }

    // Wallet login
    if ((path === '/api/auth/wallet' || path === '/api/wallet') && request.method === 'POST') {
      const { wallet_address, wallet_type, ref_code } = await request.json();
      if (!wallet_address) return err('Wallet address required');
      const addr = wallet_address.toLowerCase();

      let user = await dbFirst(env, 'SELECT * FROM users WHERE wallet_address = ?', [addr]);
      if (!user) {
        const id       = crypto.randomUUID();
        const username = 'w_' + addr.slice(2, 10);
        const myRef    = 'AI2E' + Math.random().toString(36).substr(2, 6).toUpperCase();
        const cfg      = await dbFirst(env, "SELECT value FROM settings WHERE key = 'welcome_bonus'");
        const bonus    = parseInt(cfg?.value || '1000');

        await dbRun(env,
          `INSERT INTO users (id,username,wallet_address,wallet_type,referral_code,referred_by,
           points,total_mined,mining_power,login_method,mining_claimed,created_at)
           VALUES (?,?,?,?,?,?,?,0,1.0,?,1,datetime('now'))`,
          [id, username, addr, wallet_type||'web3', myRef, ref_code||null, bonus, wallet_type||'wallet']
        );
        safe(async () => {
          await sbMining(env, 'user_points', 'POST', { 
            user_email: addr, 
            total_points: 0, 
            mining_balance: 0, 
            daily_streak: 0 
          });
          await sbTasks(env, 'leaderboard', 'POST', {
            user_email: addr,
            username: username,
            total_points: 0
          });
        });
        user = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [id]);
      }

      if (user.is_banned == 1) return err('Account banned', 403);
      safe(() => ensureUserInMiningDB(env, user));
      safe(() => ensureUserInTasksDB(env, user));
      const token = await makeToken(user.id, env);
      return json({ success: true, token, user });
    }

    // Forgot password check
    if (path === '/api/auth/forgot-check' && request.method === 'POST') {
      const { email } = await request.json();
      if (!email) return err('Email required');
      const user = await dbFirst(env, 'SELECT id, security_question FROM users WHERE LOWER(email) = ?', [email.toLowerCase().trim()]);
      if (!user) return err('Is email pe account nahi mila');
      return json({ ok: true, security_question: user.security_question || null });
    }

    // Forgot password request
    if (path === '/api/auth/forgot-password' && request.method === 'POST') {
      const { email, answer, question, new_password } = await request.json();
      if (!email || !answer) return err('Email aur answer chahiye');
      if (!new_password || new_password.length < 6) return err('New password min 6 chars');
      const emailNorm = email.toLowerCase().trim();
      const user = await dbFirst(env, 'SELECT id, username FROM users WHERE LOWER(email) = ?', [emailNorm]);
      if (!user) return err('Account nahi mila');
      const existing = await dbFirst(env, "SELECT id FROM password_resets WHERE user_id = ? AND status = 'pending'", [user.id]);
      if (existing) return err('Reset request already pending hai');
      const hashedNew = await hashPassword(new_password);
      await dbRun(env,
        "INSERT INTO password_resets (id,user_id,username,email,verify_question,verify_answer,new_password_hash,status,created_at) VALUES (?,?,?,?,?,?,?,'pending',datetime('now'))",
        [crypto.randomUUID(), user.id, user.username, emailNorm, question||'', answer, hashedNew]
      );
      return json({ ok: true });
    }

    // ============================================
    // USER — DB1 Turso
    // ============================================

    if ((path === '/api/me' || path === '/api/profile') && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);

      // Active referral count update
      safe(async () => {
        const refs = await dbFirst(env, 'SELECT COUNT(*) as c FROM users WHERE referred_by = ? AND total_mined > 0', [user.referral_code]);
        await dbRun(env, 'UPDATE users SET active_referral_count = ? WHERE id = ?', [parseInt(refs?.c||0), user.id]);
      });

      const updated = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [user.id]);
      return json(updated, 200, 300); // 5 min browser cache
    }

    // Support: send message
    if (path === '/api/support/send' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { message } = await request.json();
      if (!message || message.trim().length < 5) return err('Message bahut chota hai');
      const last = await dbFirst(env, "SELECT id FROM support_messages WHERE user_id = ? AND created_at > datetime('now','-24 hours')", [user.id]);
      if (last) return err('24 ghante mein sirf 1 message');
      await dbRun(env,
        "INSERT INTO support_messages (id,user_id,username,email,message,status,created_at) VALUES (?,?,?,?,?,'open',datetime('now'))",
        [crypto.randomUUID(), user.id, user.username, user.email||'', message.trim()]
      );
      return json({ ok: true });
    }

    if (path === '/api/support/my-messages' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      return json(await dbAll(env, 'SELECT * FROM support_messages WHERE user_id = ? ORDER BY created_at DESC LIMIT 10', [user.id]));
    }

    // ============================================
    // MINING — DB1 Turso (core) + DB3 Supabase Mining (auto-init + log)
    // Old user: pehli baar mining kare to auto-init Supabase
    // New user: register pe already init hai
    // ============================================

    if ((path === '/api/mine/start' || path === '/api/mining/start') && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      if (user.mining_claimed != 1) return err('Already mining');

      const now = new Date().toISOString();
      const userIdentifier = user.email || user.wallet_address;

      // DB1 Turso — core mining start
      await dbRun(env, "UPDATE users SET last_mining_start = ?, mining_claimed = 0 WHERE id = ?", [now, user.id]);
      await dbRun(env, "INSERT INTO mining_sessions (id,user_id,started_at,mining_power) VALUES (?,?,?,?)",
        [crypto.randomUUID(), user.id, now, user.mining_power || 1.0]);

      // DB3 Supabase Mining — auto-init old user + session log (background)
      safe(async () => {
        await ensureUserInMiningDB(env, user);
        if (userIdentifier) {
          await sbMining(env, 'mining_sessions', 'POST', {
            session_id: crypto.randomUUID(),
            user_email: userIdentifier,
            status: 'active',
            started_at: now
          });
        }
      });

      return json({ success: true, last_mining_start: now });
    }

    if ((path === '/api/mine/claim' || path === '/api/mining/claim') && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      if (user.mining_claimed == 1) return err('Nothing to claim');

      const userIdentifier = user.email || user.wallet_address;

      // Mining calculation
      const cfgRows = await dbAll(env, "SELECT key, value FROM settings WHERE key IN ('mining_duration_hours','mining_coins_per_hour')");
      const cfg = {};
      cfgRows.forEach(r => cfg[r.key] = r.value);
      const durMs   = parseInt(cfg.mining_duration_hours || '24') * 3600000;
      const cpm     = parseFloat(cfg.mining_coins_per_hour || '10') * parseFloat(user.mining_power || 1.0) / 3600000;
      const elapsed = Math.min(Date.now() - new Date(user.last_mining_start).getTime(), durMs);
      const earned  = Math.floor(cpm * elapsed);

      if (earned < 1) return err('Kuch mine nahi hua abhi');

      const newPts   = parseInt(user.points   || 0) + earned;
      const newMined = parseInt(user.total_mined || 0) + earned;

      // DB1 Turso — points update
      await dbRun(env,
        'UPDATE users SET points = ?, total_mined = ?, total_claimed = COALESCE(total_claimed,0) + ?, mining_claimed = 1 WHERE id = ?',
        [newPts, newMined, earned, user.id]);
      await dbRun(env,
        "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
        [crypto.randomUUID(), user.id, 'mining_claim', earned, '⛏️ Mining claim']);
      await dbRun(env,
        "UPDATE mining_sessions SET claimed_at = datetime('now'), coins_earned = ?, is_claimed = 1 WHERE user_id = ? AND is_claimed = 0",
        [earned, user.id]);

      // Referral tree L1=50%, L2=25%, L3=10% — DB1 Turso
      if (user.referred_by) {
        const L1 = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [user.referred_by]);
        if (L1) {
          const l1 = Math.floor(earned * 0.50);
          if (l1 > 0) {
            await dbRun(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l1, L1.id]);
            await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
              [crypto.randomUUID(), L1.id, 'refer_mining_l1', l1, '⛏️ L1 50%: @' + user.username]);
            if (L1.referred_by) {
              const L2 = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [L1.referred_by]);
              if (L2) {
                const l2 = Math.floor(earned * 0.25);
                if (l2 > 0) {
                  await dbRun(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l2, L2.id]);
                  await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
                    [crypto.randomUUID(), L2.id, 'refer_mining_l2', l2, '🌿 L2 25%: @' + user.username]);
                  if (L2.referred_by) {
                    const L3 = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [L2.referred_by]);
                    if (L3) {
                      const l3 = Math.floor(earned * 0.10);
                      if (l3 > 0) {
                        await dbRun(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l3, L3.id]);
                        await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
                          [crypto.randomUUID(), L3.id, 'refer_mining_l3', l3, '🔥 L3 10%: @' + user.username]);
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      // DB3 Supabase Mining — auto-init old user + points log (background)
      safe(async () => {
        await ensureUserInMiningDB(env, user);
        if (userIdentifier) {
          // Claim log
          await sbMining(env, 'mining_claims', 'POST', {
            user_email: userIdentifier,
            points_claimed: earned,
            claim_type: 'manual'
          });
          // user_points update (total_points Supabase mein bhi sync karo)
          const current = await sbMining(env, `user_points?user_email=eq.${encodeURIComponent(userIdentifier)}`);
          if (current && current[0]) {
            await sbMining(env, `user_points?user_email=eq.${encodeURIComponent(userIdentifier)}`, 'PATCH', {
              total_points: (current[0].total_points || 0) + earned,
              last_claim_at: new Date().toISOString()
            });
          }
        }
      });

      const updatedUser = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [user.id]);
      return json({ success: true, earned, user: updatedUser });
    }

    // Claim + auto start (ek hi request mein dono)
    if (path === '/api/mine/claim-and-start' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      if (user.mining_claimed == 1) return err('Nothing to claim');

      const userIdentifier = user.email || user.wallet_address;

      const cfgRows = await dbAll(env, "SELECT key, value FROM settings WHERE key IN ('mining_duration_hours','mining_coins_per_hour')");
      const cfg = {};
      cfgRows.forEach(r => cfg[r.key] = r.value);
      const durMs   = parseInt(cfg.mining_duration_hours || '24') * 3600000;
      const cpm     = parseFloat(cfg.mining_coins_per_hour || '10') * parseFloat(user.mining_power || 1.0) / 3600000;
      const elapsed = Math.min(Date.now() - new Date(user.last_mining_start).getTime(), durMs);
      const earned  = Math.floor(cpm * elapsed);

      if (earned < 1) return err('Kuch mine nahi hua abhi');

      const newPts   = parseInt(user.points   || 0) + earned;
      const newMined = parseInt(user.total_mined || 0) + earned;
      const now      = new Date().toISOString();

      // DB1 Turso — claim + naya session start
      await dbRun(env,
        'UPDATE users SET points=?, total_mined=?, total_claimed=COALESCE(total_claimed,0)+?, mining_claimed=0, last_mining_start=? WHERE id=?',
        [newPts, newMined, earned, now, user.id]);
      await dbRun(env,
        "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
        [crypto.randomUUID(), user.id, 'mining_claim', earned, '⛏️ Mining claim']);
      await dbRun(env,
        "UPDATE mining_sessions SET claimed_at=datetime('now'), coins_earned=?, is_claimed=1 WHERE user_id=? AND is_claimed=0",
        [earned, user.id]);
      await dbRun(env,
        "INSERT INTO mining_sessions (id,user_id,started_at,mining_power) VALUES (?,?,?,?)",
        [crypto.randomUUID(), user.id, now, user.mining_power || 1.0]);

      // Referral tree — same L1/L2/L3
      if (user.referred_by) {
        const L1 = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [user.referred_by]);
        if (L1) {
          const l1 = Math.floor(earned * 0.50);
          if (l1 > 0) {
            await dbRun(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l1, L1.id]);
            await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
              [crypto.randomUUID(), L1.id, 'refer_mining_l1', l1, '⛏️ L1 50%: @' + user.username]);
            if (L1.referred_by) {
              const L2 = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [L1.referred_by]);
              if (L2) {
                const l2 = Math.floor(earned * 0.25);
                if (l2 > 0) {
                  await dbRun(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l2, L2.id]);
                  await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
                    [crypto.randomUUID(), L2.id, 'refer_mining_l2', l2, '🌿 L2 25%: @' + user.username]);
                  if (L2.referred_by) {
                    const L3 = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [L2.referred_by]);
                    if (L3) {
                      const l3 = Math.floor(earned * 0.10);
                      if (l3 > 0) {
                        await dbRun(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l3, L3.id]);
                        await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
                          [crypto.randomUUID(), L3.id, 'refer_mining_l3', l3, '🔥 L3 10%: @' + user.username]);
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      // DB3 Supabase Mining — background sync
      safe(async () => {
        await ensureUserInMiningDB(env, user);
        if (userIdentifier) {
          await sbMining(env, 'mining_claims', 'POST', { user_email: userIdentifier, points_claimed: earned, claim_type: 'manual' });
          const current = await sbMining(env, `user_points?user_email=eq.${encodeURIComponent(userIdentifier)}`);
          if (current && current[0]) {
            await sbMining(env, `user_points?user_email=eq.${encodeURIComponent(userIdentifier)}`, 'PATCH', {
              total_points: (current[0].total_points || 0) + earned,
              last_claim_at: now
            });
          }
          await sbMining(env, 'mining_sessions', 'POST', {
            session_id: crypto.randomUUID(), user_email: userIdentifier, status: 'active', started_at: now
          });
        }
      });

      const updatedUser = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [user.id]);
      return json({ success: true, earned, user: updatedUser, mining_started: true, last_mining_start: now });
    }

    // ============================================
    // TASKS — DB2 Supabase Tasks
    // Auto-init: old user pehli baar tasks khole to leaderboard row ban jaye
    // ============================================

    if (path === '/api/tasks' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);

      const userIdentifier = user.email || user.wallet_address;

      const tasks = await safe(() => sbTasks(env, 'tasks?is_active=eq.true&order=display_order.asc'), []);
      const done  = await safe(() => sbTasks(env, `task_completions?user_email=eq.${encodeURIComponent(userIdentifier)}`), []);

      return json({ tasks, done: done.map(d => d.task_id) }, 200, 1800); // 30 min cache
    }

    if (path === '/api/tasks/complete' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { taskId } = await request.json();

      const userIdentifier = user.email || user.wallet_address;
      if (!userIdentifier) return err('Invalid user identifier');

      // DB2 Supabase Tasks — completion save
      const result = await safe(() => sbTasks(env, 'task_completions', 'POST', {
        user_email: userIdentifier,
        task_id: taskId,
        completed_at: new Date().toISOString()
      }), { ok: false });

      // Leaderboard update (auto-init old user)
      safe(async () => {
        await ensureUserInTasksDB(env, user);
        const lb = await sbTasks(env, `leaderboard?user_email=eq.${encodeURIComponent(userIdentifier)}`);
        const task = await safe(() => sbTasks(env, `tasks?id=eq.${taskId}`), []);
        const pts  = task[0]?.points_reward || 0;
        if (lb[0]) {
          await sbTasks(env, `leaderboard?user_email=eq.${encodeURIComponent(userIdentifier)}`, 'PATCH', {
            total_points: (lb[0].total_points || 0) + pts
          });
        }
      });

      return json(result);
    }

    if (path === '/api/leaderboard' && request.method === 'GET') {
      const lb = await safe(() => sbTasks(env, 'leaderboard?order=total_points.desc&limit=100'), []);
      return json(lb, 200, 600); // 10 min cache
    }

    // ============================================
    // REFERRALS — DB3 Supabase Mining
    // ============================================

    if (path === '/api/referrals' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const userIdentifier = user.email || user.wallet_address;
      if (!userIdentifier) return json([], 200, 600);
      
      const refs = await safe(() =>
        sbMining(env, `referrals?referrer_email=eq.${encodeURIComponent(userIdentifier)}&order=created_at.desc&limit=30`), []);
      return json(refs, 200, 600); // 10 min cache
    }

    // ============================================
    // PUBLIC STATS — DB1 Turso
    // ============================================

    if (path === '/api/stats' && request.method === 'GET') {
      const uc = await safe(async () => parseInt((await dbFirst(env, 'SELECT COUNT(*) as c FROM users'))?.c || 0), 0);
      const tm = await safe(async () => parseInt((await dbFirst(env, 'SELECT SUM(total_mined) as s FROM users'))?.s || 0), 0);
      return jsonPublic({ users: uc, total_mined: tm }, 200, 900); // 15 min public cache
    }

    if (path === '/api/settings' && request.method === 'GET') {
      const rows = await dbAll(env, 'SELECT key, value FROM settings');
      const map  = {};
      rows.forEach(r => map[r.key] = r.value);
      return json(map, 200, 900);
    }

    if (path === '/api/transactions' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      return json(await dbAll(env, 'SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 30', [user.id]));
    }

    // ============================================
    // ADMIN — DB1 Turso + DB2 Tasks + DB3 Mining
    // ============================================

    if (path.startsWith('/api/admin/')) {
      if (request.headers.get('X-Admin-Key') !== (env.ADMIN_KEY || 'Admin@2026'))
        return err('Forbidden', 403);

      const body = request.method !== 'GET' ? await request.json().catch(() => ({})) : {};

      if (path === '/api/admin/dashboard') {
        const uc     = await safe(async () => parseInt((await dbFirst(env, 'SELECT COUNT(*) as c FROM users'))?.c || 0), 0);
        const tm     = await safe(async () => parseInt((await dbFirst(env, 'SELECT SUM(total_mined) as s FROM users'))?.s || 0), 0);
        const tc     = await safe(async () => (await sbTasks(env, 'tasks?is_active=eq.true')).length, 0);
        const recent = await safe(() => dbAll(env, 'SELECT * FROM users ORDER BY created_at DESC LIMIT 10'), []);
        return json({ users: uc, total_mined: tm, tasks: tc, recent });
      }

      if (path === '/api/admin/users' && request.method === 'GET') {
        return json(await dbAll(env,
          `SELECT u.*,
           (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code) AS referral_count,
           (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code AND r.total_mined > 0) AS active_referral_count
           FROM users u ORDER BY u.created_at DESC LIMIT 100`));
      }

      if (path === '/api/admin/users/ban' && request.method === 'POST') {
        await dbRun(env, 'UPDATE users SET is_banned=? WHERE id=?', [body.is_banned ? 1 : 0, body.id]);
        return json({ ok: true });
      }

      if (path === '/api/admin/users/update' && request.method === 'POST') {
        await dbRun(env, 'UPDATE users SET username=?,points=?,mining_power=?,is_banned=? WHERE id=?',
          [body.username, body.points, body.mining_power, body.is_banned ? 1 : 0, body.id]);
        return json({ ok: true });
      }

      if (path === '/api/admin/tasks' && request.method === 'GET') {
        return json(await safe(() => sbTasks(env, 'tasks?order=display_order.asc'), []));
      }

      if (path === '/api/admin/tasks/save' && request.method === 'POST') {
        const { id, title, task_type, points_reward, display_order, is_active } = body;
        if (id) {
          await sbTasks(env, `tasks?id=eq.${id}`, 'PATCH', { title, task_type, points_reward, display_order, is_active });
        } else {
          await sbTasks(env, 'tasks', 'POST', {
            id: crypto.randomUUID(), title, task_type, points_reward,
            display_order: display_order || 99, is_active: is_active !== false
          });
        }
        return json({ ok: true });
      }

      if (path === '/api/admin/tasks/delete' && request.method === 'POST') {
        await sbTasks(env, `tasks?id=eq.${body.id}`, 'DELETE');
        return json({ ok: true });
      }

      if (path === '/api/admin/support' && request.method === 'GET') {
        return json({ messages: await dbAll(env, 'SELECT * FROM support_messages ORDER BY created_at DESC LIMIT 100') });
      }

      if (path === '/api/admin/support/reply' && request.method === 'POST') {
        await dbRun(env, "UPDATE support_messages SET admin_reply=?,status='replied',replied_at=datetime('now') WHERE id=?", [body.reply, body.msg_id]);
        return json({ ok: true });
      }

      if (path === '/api/admin/reset-requests' && request.method === 'GET') {
        return json({ requests: await dbAll(env, "SELECT * FROM password_resets ORDER BY created_at DESC LIMIT 50") });
      }

      if (path === '/api/admin/reset-approve' && request.method === 'POST') {
        const reset = await dbFirst(env, 'SELECT * FROM password_resets WHERE id=?', [body.reset_id]);
        if (!reset) return err('Request nahi mili');
        
        // Try password column first, fallback to password_hash
        try {
          await dbRun(env, 'UPDATE users SET password=? WHERE id=?', [reset.new_password_hash, reset.user_id]);
        } catch (e) {
          await dbRun(env, 'UPDATE users SET password_hash=? WHERE id=?', [reset.new_password_hash, reset.user_id]);
        }
        
        await dbRun(env, "UPDATE password_resets SET status='approved',resolved_at=datetime('now') WHERE id=?", [body.reset_id]);
        return json({ ok: true });
      }

      if (path === '/api/admin/settings' && request.method === 'POST') {
        for (const [key, value] of Object.entries(body)) {
          await dbRun(env, 'UPDATE settings SET value=? WHERE key=?', [String(value), key]);
        }
        return json({ ok: true });
      }
    }

    return err('Not found', 404);

  } catch (e) {
    console.error('Server error:', e);
    return err('Server error: ' + e.message, 500);
  }
}
