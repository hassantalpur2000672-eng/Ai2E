// ============================================
// Ai2E — 3-DATABASE PRODUCTION BACKEND
// DB1 (Turso): Auth & Users | DB2 (Supabase): Tasks & Leaderboard | DB3 (Supabase): Mining & Referrals
// ============================================

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Admin-Key',
};

// ============================================
// DATABASE CLIENTS
// ============================================

// Turso Helper
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
async function dbAll(env, sql, args = []) { return await turso(env, sql, args); }
async function dbRun(env, sql, args = []) { return await turso(env, sql, args); }

// Supabase Tasks Helper
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
    if (!res.ok) throw new Error(`SB Tasks: ${res.status}`);
    return method === 'DELETE' || method === 'PATCH' ? { ok: true } : await res.json();
  } catch (e) { console.error('Supabase Tasks Error:', e); return method === 'GET' ? [] : { ok: false }; }
}

// Supabase Mining Helper
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
    if (!res.ok) throw new Error(`SB Mining: ${res.status}`);
    return method === 'DELETE' || method === 'PATCH' ? { ok: true } : await res.json();
  } catch (e) { console.error('Supabase Mining Error:', e); return method === 'GET' ? [] : { ok: false }; }
}

// Safe call wrapper
async function safe(fn, def = null) {
  try { return await fn(); } catch (e) { console.error('Safe call failed:', e); return def; }
}

// ============================================
// PASSWORD & TOKEN UTILS
// ============================================

async function legacyHash(password) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + 'AI2E_SALT_2025'));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
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
  return new Response(JSON.stringify(data), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
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

// ============================================
// MAIN REQUEST HANDLER
// ============================================

export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  const url = new URL(request.url);
  const path = url.pathname;

  try {

    // ============================================
    // AUTH ENDPOINTS (Turso DB)
    // ============================================

    if (path === '/api/register' && request.method === 'POST') {
      const { username, email, password, referralCode, wallet, walletType, securityQuestion, securityAnswer } = await request.json();
      if (!username || !email || !password) return err('Missing fields');

      const exists = await dbFirst(env, 'SELECT id FROM users WHERE email = ? OR username = ?', [email, username]);
      if (exists) return err('Email or username exists', 409);

      const hashedPassword = await hashPassword(password);
      const userId = crypto.randomUUID();
      const userRefCode = crypto.randomUUID().slice(0, 8).toUpperCase();

      await dbRun(env,
        `INSERT INTO users (id, username, email, password, wallet_address, wallet_type, 
         referral_code, referred_by, security_question, security_answer, created_at) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [userId, username, email, hashedPassword, wallet || null, walletType || null, userRefCode, referralCode || null, securityQuestion || null, securityAnswer || null]
      );

      // Init user in Mining DB (non-blocking)
      safe(async () => {
        await sbMining(env, 'user_points', 'POST', { user_email: email, total_points: 0, mining_balance: 0, daily_streak: 0 });
      });

      // Referral bonus
      if (referralCode) {
        safe(async () => {
          const ref = await dbFirst(env, 'SELECT email FROM users WHERE referral_code = ?', [referralCode]);
          if (ref) await sbMining(env, 'referrals', 'POST', { referrer_email: ref.email, referred_email: email, referral_code: referralCode, bonus_points: 500 });
        });
      }

      const token = await makeToken(userId, env);
      return json({ success: true, token, user: { id: userId, username, email, referralCode: userRefCode } });
    }

    if (path === '/api/login' && request.method === 'POST') {
      const { email, password } = await request.json();
      if (!email || !password) return err('Missing credentials');

      const user = await dbFirst(env, 'SELECT * FROM users WHERE email = ?', [email]);
      if (!user) return err('Invalid credentials', 401);
      if (user.is_banned === 1 || user.is_banned === '1') return err('Account banned', 403);

      const valid = await verifyPassword(password, user.password);
      if (!valid) return err('Invalid credentials', 401);

      await dbRun(env, 'UPDATE users SET last_login = datetime("now") WHERE id = ?', [user.id]);

      const token = await makeToken(user.id, env);
      return json({
        success: true,
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          walletAddress: user.wallet_address,
          walletType: user.wallet_type,
          referralCode: user.referral_code
        }
      });
    }

    if (path === '/api/profile' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);

      const miningData = await safe(async () => {
        const data = await sbMining(env, `user_points?user_email=eq.${user.email}`);
        return data[0] || {};
      }, {});

      return json({
        id: user.id,
        username: user.username,
        email: user.email,
        walletAddress: user.wallet_address,
        walletType: user.wallet_type,
        referralCode: user.referral_code,
        totalMined: miningData.total_points || 0,
        miningBalance: miningData.mining_balance || 0,
        dailyStreak: miningData.daily_streak || 0,
        createdAt: user.created_at
      });
    }

    // ============================================
    // TASKS ENDPOINTS (Supabase Tasks DB)
    // ============================================

    if (path === '/api/tasks' && request.method === 'GET') {
      const tasks = await safe(async () => {
        return await sbTasks(env, 'tasks?is_active=eq.true&order=display_order.asc');
      }, []);
      return json(tasks);
    }

    if (path === '/api/tasks/complete' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);

      const { taskId } = await request.json();
      const result = await safe(async () => {
        return await sbTasks(env, 'task_completions', 'POST', {
          user_email: user.email,
          task_id: taskId,
          completed_at: new Date().toISOString()
        });
      }, { ok: false });

      return json(result);
    }

    if (path === '/api/leaderboard' && request.method === 'GET') {
      const lb = await safe(async () => {
        return await sbTasks(env, 'leaderboard?order=total_points.desc&limit=100');
      }, []);
      return json(lb);
    }

    // ============================================
    // MINING ENDPOINTS (Supabase Mining DB)
    // ============================================

    if (path === '/api/mining/start' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);

      const sessionId = crypto.randomUUID();
      await safe(async () => {
        await sbMining(env, 'mining_sessions', 'POST', {
          session_id: sessionId,
          user_email: user.email,
          status: 'active',
          started_at: new Date().toISOString()
        });
      });

      return json({ success: true, sessionId });
    }

    if (path === '/api/mining/claim' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);

      const { points } = await request.json();
      if (!points || points <= 0) return err('Invalid points');

      await safe(async () => {
        await sbMining(env, 'mining_claims', 'POST', {
          user_email: user.email,
          points_claimed: points,
          claim_type: 'manual'
        });
      });

      await safe(async () => {
        const current = await sbMining(env, `user_points?user_email=eq.${user.email}`);
        const pts = (current[0]?.total_points || 0) + points;
        await sbMining(env, `user_points?user_email=eq.${user.email}`, 'PATCH', {
          total_points: pts,
          last_claim_at: new Date().toISOString()
        });
      });

      return json({ success: true, points });
    }

    if (path === '/api/referrals' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);

      const refs = await safe(async () => {
        return await sbMining(env, `referrals?referrer_email=eq.${user.email}&order=created_at.desc&limit=30`);
      }, []);

      return json(refs);
    }

    // ============================================
    // PUBLIC STATS
    // ============================================

    if (path === '/api/stats' && request.method === 'GET') {
      const uc = await safe(async () => {
        const r = await dbFirst(env, 'SELECT COUNT(*) as c FROM users');
        return parseInt(r?.c || 0);
      }, 0);

      const tm = await safe(async () => {
        const data = await sbMining(env, 'user_points?select=total_points');
        return data.reduce((sum, u) => sum + (u.total_points || 0), 0);
      }, 0);

      return json({ users: uc, total_mined: tm });
    }

    // ============================================
    // ADMIN ENDPOINTS
    // ============================================

    if (path.startsWith('/api/admin/')) {
      const adminPass = request.headers.get('X-Admin-Key');
      if (adminPass !== (env.ADMIN_KEY || "Admin@2026")) return err('Forbidden', 403);

      const body = request.method !== 'GET' ? await request.json().catch(() => ({})) : {};

      if (path === '/api/admin/dashboard') {
        const uc = await safe(async () => parseInt((await dbFirst(env, 'SELECT COUNT(*) as c FROM users'))?.c || 0), 0);
        const tm = await safe(async () => {
          const data = await sbMining(env, 'user_points?select=total_points');
          return data.reduce((sum, u) => sum + (u.total_points || 0), 0);
        }, 0);
        const tc = await safe(async () => (await sbTasks(env, 'tasks?is_active=eq.true')).length, 0);
        const recent = await safe(async () => await dbAll(env, 'SELECT * FROM users ORDER BY created_at DESC LIMIT 10'), []);

        return json({ users: uc, total_mined: tm, tasks: tc, recent });
      }

      if (path === '/api/admin/users') {
        const users = await dbAll(env, 'SELECT * FROM users ORDER BY created_at DESC LIMIT 100');
        return json(users);
      }

      if (path === '/api/admin/users/ban' && request.method === 'POST') {
        await dbRun(env, 'UPDATE users SET is_banned=? WHERE id=?', [body.is_banned ? 1 : 0, body.id]);
        return json({ ok: true });
      }

      if (path === '/api/admin/tasks') {
        const tasks = await safe(async () => await sbTasks(env, 'tasks?order=display_order.asc'), []);
        return json(tasks);
      }

      if (path === '/api/admin/tasks/save' && request.method === 'POST') {
        const { id, title, task_type, points_reward, display_order, is_active } = body;
        if (id) {
          await sbTasks(env, `tasks?id=eq.${id}`, 'PATCH', { title, task_type, points_reward, display_order, is_active });
        } else {
          await sbTasks(env, 'tasks', 'POST', { id: crypto.randomUUID(), title, task_type, points_reward, display_order: display_order || 99, is_active: is_active !== false });
        }
        return json({ ok: true });
      }

      if (path === '/api/admin/tasks/delete' && request.method === 'POST') {
        await sbTasks(env, `tasks?id=eq.${body.id}`, 'DELETE');
        return json({ ok: true });
      }
    }

    return err('Not found', 404);

  } catch (e) {
    console.error('Server error:', e);
    return err('Server error: ' + e.message, 500);
  }
}
