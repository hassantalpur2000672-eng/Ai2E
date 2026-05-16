// ============================================
// Ai2E — 3-DATABASE BACKEND (FIXED)
// DB1 Turso:           Auth, Users, Transactions, Mining sessions
// DB2 Supabase Tasks:  Tasks, Task completions, Leaderboard
// DB3 Supabase Mining: Mining claims, User points, Referrals
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
    if (!res.ok) {
      const errText = await res.text();
      console.error(`SB Tasks Error ${res.status}:`, errText);
      throw new Error(`SB Tasks ${res.status}`);
    }
    return ['DELETE','PATCH'].includes(method) ? { ok: true } : await res.json();
  } catch (e) { 
    console.error('SB Tasks Error:', e); 
    return method === 'GET' ? [] : { ok: false }; 
  }
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
    if (!res.ok) {
      const errText = await res.text();
      console.error(`SB Mining Error ${res.status}:`, errText);
      throw new Error(`SB Mining ${res.status}`);
    }
    return ['DELETE','PATCH'].includes(method) ? { ok: true } : await res.json();
  } catch (e) { 
    console.error('SB Mining Error:', e); 
    return method === 'GET' ? [] : { ok: false }; 
  }
}

// ============================================
// AUTO-INIT — OLD USER KO NEW DBs MEIN BANANA
// ============================================

async function ensureUserInMiningDB(env, user) {
  try {
    const userIdentifier = user.email || user.wallet_address;
    if (!userIdentifier) return;
    
    const existing = await sbMining(env, `user_points?user_email=eq.${encodeURIComponent(userIdentifier)}&limit=1`);
    if (existing && existing.length > 0) return;

    await sbMining(env, 'user_points', 'POST', {
      user_email: userIdentifier,
      total_points: parseInt(user.total_mined || 0),
      mining_balance: parseInt(user.points || 0),
      daily_streak: 0
    });
    console.log(`Auto-init mining DB for old user: ${userIdentifier}`);
  } catch (e) {
    console.error('ensureUserInMiningDB error:', e);
  }
}

async function ensureUserInTasksDB(env, user) {
  try {
    const userIdentifier = user.email || user.wallet_address;
    const username = user.username || 'user_' + (userIdentifier || '').substring(0, 8);
    
    if (!userIdentifier) return;
    
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
// SAFE WRAPPER
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
  const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  const newHash = Array.from(new Uint8Array(derived)).map(b => b.toString(16).padStart(2, '0')).join('');
  return newHash === hashHex;
}

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
    if (Date.now() - parsed.ts > 30 * 24 * 60 * 60 * 1000) return null;
    return parsed;
  } catch { return null; }
}

// ============================================
// JSON HELPERS
// ============================================

function json(data, status = 200, cacheSeconds = 0) {
  const headers = { ...CORS, 'Content-Type': 'application/json' };
  if (cacheSeconds > 0) headers['Cache-Control'] = `public, max-age=${cacheSeconds}`;
  return new Response(JSON.stringify(data), { status, headers });
}

function jsonPublic(data, status = 200, cacheSeconds = 0) {
  const headers = { ...CORS, 'Content-Type': 'application/json', 'Cache-Control': `public, max-age=${cacheSeconds}` };
  return new Response(JSON.stringify(data), { status, headers });
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
// MAIN HANDLER
// ============================================

export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  const url = new URL(request.url);
  const path = url.pathname;

  try {

    // ============================================
    // AUTH — DB1 Turso
    // ============================================

    if (path === '/api/auth/register' && request.method === 'POST') {
      const { username, email, password, wallet_address, referral_code } = await request.json();
      
      if (!username || (!email && !wallet_address) || !password) 
        return err('Username, email/wallet aur password chahiye');

      const existing = await dbFirst(env, 
        'SELECT id FROM users WHERE username = ? OR email = ? OR wallet_address = ?', 
        [username, email || null, wallet_address || null]);
      
      if (existing) return err('Username, email ya wallet already use mein hai');

      const userId = crypto.randomUUID();
      const userRefCode = Math.random().toString(36).substring(2, 10).toUpperCase();
      const passHash = await hashPassword(password);

      await dbRun(env, `INSERT INTO users (id, username, email, wallet_address, password, referral_code, referred_by, points, total_mined, mining_power, is_banned, login_method, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 1.0, 0, 'email', datetime('now'))`,
        [userId, username, email || null, wallet_address || null, passHash, userRefCode, referral_code || null]);

      const user = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [userId]);
      const token = await makeToken(userId, env);

      // NEW USER — Teeno DBs mein init karo
      const userIdentifier = email || wallet_address;
      
      // DB3 Mining — user_points
      await safe(() => sbMining(env, 'user_points', 'POST', {
        user_email: userIdentifier,
        total_points: 0,
        mining_balance: 0,
        daily_streak: 0
      }));

      // DB2 Tasks — leaderboard
      await safe(() => sbTasks(env, 'leaderboard', 'POST', {
        user_email: userIdentifier,
        username: username,
        total_points: 0
      }));

      // Referral agar di hai to DB3 mein save karo
      if (referral_code) {
        const referrer = await dbFirst(env, 'SELECT email, wallet_address FROM users WHERE referral_code = ?', [referral_code]);
        if (referrer) {
          const referrerIdentifier = referrer.email || referrer.wallet_address;
          await safe(() => sbMining(env, 'referrals', 'POST', {
            referrer_email: referrerIdentifier,
            referred_email: userIdentifier,
            referred_username: username,
            created_at: new Date().toISOString()
          }));
        }
      }

      return json({ user, token });
    }

    if (path === '/api/auth/login' && request.method === 'POST') {
      const { username, password } = await request.json();
      if (!username || !password) return err('Username aur password chahiye');

      const user = await dbFirst(env, 'SELECT * FROM users WHERE username = ? OR email = ? OR wallet_address = ?', [username, username, username]);
      if (!user) return err('User nahi mila', 404);
      if (user.is_banned) return err('Account banned hai', 403);

      const valid = await verifyPassword(password, user.password);
      if (!valid) return err('Wrong password', 401);

      const token = await makeToken(user.id, env);
      return json({ user, token });
    }

    if (path === '/api/auth/me' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      return json(user);
    }

    // ============================================
    // MINING — DB3 Supabase Mining
    // ============================================

    if (path === '/api/mining/start' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      if (user.is_banned) return err('Banned user', 403);

      const userIdentifier = user.email || user.wallet_address;
      if (!userIdentifier) return err('Invalid user identifier');

      // Auto-init old user agar pehli baar mining kar raha hai
      await ensureUserInMiningDB(env, user);

      const sessionId = crypto.randomUUID();
      
      // DB1 Turso mein bhi session save karo (compatibility)
      await safe(() => dbRun(env, 
        "INSERT INTO mining_sessions (id, user_id, started_at, claimed) VALUES (?, ?, datetime('now'), 0)",
        [sessionId, user.id]
      ));

      return json({ 
        sessionId, 
        miningPower: parseFloat(user.mining_power) || 1.0,
        startedAt: new Date().toISOString()
      });
    }

    if (path === '/api/mining/claim' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      
      const { sessionId, amount } = await request.json();
      if (!sessionId || !amount) return err('Session ID aur amount chahiye');

      const userIdentifier = user.email || user.wallet_address;
      if (!userIdentifier) return err('Invalid user identifier');

      // Auto-init old user
      await ensureUserInMiningDB(env, user);

      const finalAmount = Math.floor(parseFloat(amount));
      
      // DB3 Supabase Mining mein claim save karo
      const claimResult = await safe(() => sbMining(env, 'mining_claims', 'POST', {
        user_email: userIdentifier,
        session_id: sessionId,
        amount_claimed: finalAmount,
        claimed_at: new Date().toISOString()
      }), { ok: false });

      if (!claimResult || !claimResult.ok) {
        return err('Claim save nahi hua', 500);
      }

      // DB3 mein user_points update karo
      const currentPoints = await sbMining(env, `user_points?user_email=eq.${encodeURIComponent(userIdentifier)}`);
      if (currentPoints && currentPoints[0]) {
        const newBalance = (currentPoints[0].mining_balance || 0) + finalAmount;
        const newTotal = (currentPoints[0].total_points || 0) + finalAmount;
        
        await sbMining(env, `user_points?user_email=eq.${encodeURIComponent(userIdentifier)}`, 'PATCH', {
          mining_balance: newBalance,
          total_points: newTotal
        });
      }

      // DB1 Turso mein bhi update karo (compatibility)
      await safe(() => dbRun(env, 
        'UPDATE users SET points = points + ?, total_mined = total_mined + ? WHERE id = ?',
        [finalAmount, finalAmount, user.id]
      ));

      await safe(() => dbRun(env, 
        'UPDATE mining_sessions SET claimed = 1 WHERE id = ?',
        [sessionId]
      ));

      return json({ 
        success: true, 
        newBalance: (currentPoints[0]?.mining_balance || 0) + finalAmount,
        claimed: finalAmount 
      });
    }

    // ============================================
    // TASKS — DB2 Supabase Tasks
    // ============================================

    if (path === '/api/tasks' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);

      const userIdentifier = user.email || user.wallet_address;
      if (!userIdentifier) return err('Invalid user identifier');

      // Auto-init old user
      await ensureUserInTasksDB(env, user);

      const tasks = await safe(() => sbTasks(env, 'tasks?is_active=eq.true&order=display_order.asc'), []);
      const done  = await safe(() => sbTasks(env, `task_completions?user_email=eq.${encodeURIComponent(userIdentifier)}`), []);

      return json({ tasks, done: done.map(d => d.task_id) }, 200, 1800);
    }

    if (path === '/api/tasks/complete' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { taskId } = await request.json();

      const userIdentifier = user.email || user.wallet_address;
      if (!userIdentifier) return err('Invalid user identifier');

      // Auto-init old user
      await ensureUserInTasksDB(env, user);

      // Check if already completed
      const existing = await sbTasks(env, `task_completions?user_email=eq.${encodeURIComponent(userIdentifier)}&task_id=eq.${taskId}`);
      if (existing && existing.length > 0) {
        return err('Task already completed');
      }

      // DB2 Supabase Tasks — completion save
      const result = await safe(() => sbTasks(env, 'task_completions', 'POST', {
        user_email: userIdentifier,
        task_id: taskId,
        completed_at: new Date().toISOString()
      }), { ok: false });

      if (!result || !result.ok) {
        return err('Task completion save nahi hua');
      }

      // Leaderboard update
      const task = await safe(() => sbTasks(env, `tasks?id=eq.${taskId}`), []);
      const pts = task[0]?.points_reward || 0;

      const lb = await sbTasks(env, `leaderboard?user_email=eq.${encodeURIComponent(userIdentifier)}`);
      if (lb && lb[0]) {
        await sbTasks(env, `leaderboard?user_email=eq.${encodeURIComponent(userIdentifier)}`, 'PATCH', {
          total_points: (lb[0].total_points || 0) + pts
        });
      }

      // DB1 Turso mein bhi update (compatibility)
      await safe(() => dbRun(env, 
        'UPDATE users SET points = points + ?, total_mined = total_mined + ? WHERE id = ?',
        [pts, pts, user.id]
      ));

      return json({ success: true, points_earned: pts });
    }

    if (path === '/api/leaderboard' && request.method === 'GET') {
      const lb = await safe(() => sbTasks(env, 'leaderboard?order=total_points.desc&limit=100'), []);
      return json(lb, 200, 600);
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
      return json(refs, 200, 600);
    }

    // ============================================
    // PUBLIC STATS — DB1 Turso
    // ============================================

    if (path === '/api/stats' && request.method === 'GET') {
      const uc = await safe(async () => parseInt((await dbFirst(env, 'SELECT COUNT(*) as c FROM users'))?.c || 0), 0);
      const tm = await safe(async () => parseInt((await dbFirst(env, 'SELECT SUM(total_mined) as s FROM users'))?.s || 0), 0);
      return jsonPublic({ users: uc, total_mined: tm }, 200, 900);
    }

    if (path === '/api/settings' && request.method === 'GET') {
      const rows = await dbAll(env, 'SELECT key, value FROM settings');
      const map = {};
      rows.forEach(r => map[r.key] = r.value);
      return json(map, 200, 900);
    }

    if (path === '/api/transactions' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      return json(await dbAll(env, 'SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 30', [user.id]));
    }

    // ============================================
    // ADMIN — All DBs
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
        const { id, title, description, icon, task_type, url, points_reward, display_order, is_active } = body;
        if (id) {
          await sbTasks(env, `tasks?id=eq.${id}`, 'PATCH', { 
            title, description, icon, task_type, url, 
            points_reward, display_order, is_active 
          });
        } else {
          await sbTasks(env, 'tasks', 'POST', {
            id: crypto.randomUUID(), 
            title, 
            description: description || null,
            icon: icon || '🎯',
            task_type, 
            url: url || null,
            points_reward,
            display_order: display_order || 99, 
            is_active: is_active !== false
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
        
        await dbRun(env, 'UPDATE users SET password=? WHERE id=?', [reset.new_password_hash, reset.user_id]);
        await dbRun(env, "UPDATE password_resets SET status='approved',resolved_at=datetime('now') WHERE id=?", [body.reset_id]);
        return json({ ok: true });
      }

      if (path === '/api/admin/settings' && request.method === 'POST') {
        for (const [key, value] of Object.entries(body)) {
          await dbRun(env, 'UPDATE settings SET value=? WHERE key=?', [String(value), key]);
        }
        return json({ ok: true });
      }

      if (path === '/api/admin/mining-claims' && request.method === 'GET') {
        const claims = await safe(() => sbMining(env, 'mining_claims?order=claimed_at.desc&limit=100'), []);
        return json(claims);
      }
    }

    return err('Not found', 404);

  } catch (e) {
    console.error('Server error:', e);
    return err('Server error: ' + e.message, 500);
  }
}
