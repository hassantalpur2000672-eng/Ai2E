 // ============================================
// AirDrop Zone — Cloudflare Pages Function
// Database: Turso (LibSQL)
// ============================================
// DB MIGRATION REQUIRED — run these SQL commands in Turso once:
//   ALTER TABLE tasks ADD COLUMN quiz_question TEXT;
//   ALTER TABLE tasks ADD COLUMN quiz_answer TEXT;
//   ALTER TABLE tasks ADD COLUMN verify_code TEXT;
//   CREATE TABLE IF NOT EXISTS quiz_attempts (
//     id TEXT PRIMARY KEY,
//     user_id TEXT NOT NULL,
//     task_id TEXT NOT NULL,
//     attempts INTEGER DEFAULT 0,
//     failed INTEGER DEFAULT 0,
//     created_at TEXT
//   );
// ============================================

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

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

async function dbFirst(env, sql, args = []) {
  const rows = await turso(env, sql, args);
  return rows[0] || null;
}

async function dbAll(env, sql, args = []) {
  return await turso(env, sql, args);
}

async function dbRun(env, sql, args = []) {
  return await turso(env, sql, args);
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

async function hashPassword(password) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + 'ADZ_SALT_2025'));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

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

export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  const url = new URL(request.url);
  const path = url.pathname;

  try {

    // ── AUTH ──────────────────────────────────────
    if (path === '/api/auth/register' && request.method === 'POST') {
      const { username, email, password, ref_code } = await request.json();
      if (!username || !email || !password) return err('All fields required');
      if (password.length < 6) return err('Password min 6 chars');

      const exists = await dbFirst(env, 'SELECT id FROM users WHERE email = ?', [email]);
      if (exists) return err('Email already registered');

      const uExists = await dbFirst(env, 'SELECT id FROM users WHERE username = ?', [username.toLowerCase()]);
      if (uExists) return err('Username taken');

      const hashed = await hashPassword(password);
      const myRef = 'ADZ' + Math.random().toString(36).substr(2, 7).toUpperCase();
      const id = crypto.randomUUID();
      const cfg = await dbFirst(env, "SELECT value FROM settings WHERE key = 'welcome_bonus'");
      const bonus = parseInt(cfg?.value || '1000');

      await dbRun(env, `INSERT INTO users (id,username,email,password_hash,referral_code,referred_by,points,total_mined,mining_power,login_method,mining_claimed,created_at) VALUES (?,?,?,?,?,?,?,0,1.0,'email',1,datetime('now'))`,
        [id, username.toLowerCase(), email, hashed, myRef, ref_code || null, bonus]);

      await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
        [crypto.randomUUID(), id, 'welcome_bonus', bonus, '🎉 Welcome bonus']);

      if (ref_code) {
        const refUser = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [ref_code]);
        if (refUser && refUser.id !== id) {
          const cfgR = await dbFirst(env, "SELECT value FROM settings WHERE key = 'referral_bonus'");
          const rb = parseInt(cfgR?.value || '500');
          await dbRun(env, 'UPDATE users SET points = points + ?, referral_count = referral_count + 1 WHERE id = ?', [rb, refUser.id]);
          await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
            [crypto.randomUUID(), refUser.id, 'referral_bonus', rb, '👥 New referral: @' + username]);
        }
      }

      const token = await makeToken(id, env);
      const user = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [id]);
      return json({ token, user });
    }

    if (path === '/api/auth/login' && request.method === 'POST') {
      const { email, password } = await request.json();
      if (!email || !password) return err('Email and password required');
      const hashed = await hashPassword(password);
      const user = await dbFirst(env, 'SELECT * FROM users WHERE email = ? AND password_hash = ?', [email, hashed]);
      if (!user) return err('Wrong email or password');
      if (user.is_banned == 1) return err('Account banned');
      const token = await makeToken(user.id, env);
      return json({ token, user });
    }

    if (path === '/api/auth/wallet' && request.method === 'POST') {
      const { wallet_address, wallet_type, ref_code } = await request.json();
      if (!wallet_address) return err('Wallet address required');
      const addr = wallet_address.toLowerCase();
      let user = await dbFirst(env, 'SELECT * FROM users WHERE wallet_address = ?', [addr]);

      if (!user) {
        const id = crypto.randomUUID();
        const username = 'w_' + wallet_address.slice(2, 10).toLowerCase();
        const myRef = 'ADZ' + Math.random().toString(36).substr(2, 7).toUpperCase();
        const cfg = await dbFirst(env, "SELECT value FROM settings WHERE key = 'welcome_bonus'");
        const bonus = parseInt(cfg?.value || '1000');

        await dbRun(env, `INSERT INTO users (id,username,wallet_address,wallet_type,referral_code,referred_by,points,total_mined,mining_power,login_method,mining_claimed,created_at) VALUES (?,?,?,?,?,?,?,0,1.0,?,1,datetime('now'))`,
          [id, username, addr, wallet_type || 'web3', myRef, ref_code || null, bonus, wallet_type || 'wallet']);

        await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
          [crypto.randomUUID(), id, 'welcome_bonus', bonus, '🎉 Welcome bonus']);

        if (ref_code) {
          const refUser = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [ref_code]);
          if (refUser) {
            const cfgR = await dbFirst(env, "SELECT value FROM settings WHERE key = 'referral_bonus'");
            const rb = parseInt(cfgR?.value || '500');
            await dbRun(env, 'UPDATE users SET points = points + ?, referral_count = referral_count + 1 WHERE id = ?', [rb, refUser.id]);
          }
        }
        user = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [id]);
      }

      if (user.is_banned == 1) return err('Account banned');
      const token = await makeToken(user.id, env);
      return json({ token, user });
    }

    // ── USER ──────────────────────────────────────
    if (path === '/api/me' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const refs = await dbAll(env, 'SELECT COUNT(*) as c FROM users WHERE referred_by = ? AND total_mined > 0', [user.referral_code]);
      const activeRefs = parseInt(refs[0]?.c || 0);
      const cfgPPR = await dbFirst(env, "SELECT value FROM settings WHERE key = 'referral_power_per_ref'");
      const cfgMax = await dbFirst(env, "SELECT value FROM settings WHERE key = 'max_mining_power'");
      const ppr = parseFloat(cfgPPR?.value || '0.1');
      const maxP = parseFloat(cfgMax?.value || '10.0');
      const newPow = Math.min(1.0 + activeRefs * ppr, maxP);
      await dbRun(env, 'UPDATE users SET mining_power = ?, active_referral_count = ? WHERE id = ?', [newPow, activeRefs, user.id]);
      const updated = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [user.id]);
      return json(updated);
    }

    if (path === '/api/mine/start' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      if (user.mining_claimed != 1) return err('Already mining');
      const now = new Date().toISOString();
      await dbRun(env, "UPDATE users SET last_mining_start = ?, mining_claimed = 0 WHERE id = ?", [now, user.id]);
      await dbRun(env, "INSERT INTO mining_sessions (id,user_id,started_at,mining_power) VALUES (?,?,?,?)",
        [crypto.randomUUID(), user.id, now, user.mining_power]);
      return json({ success: true });
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

      const newPts = parseInt(user.points || 0) + earned;
      const newMined = parseInt(user.total_mined || 0) + earned;
      await dbRun(env, 'UPDATE users SET points = ?, total_mined = ?, total_claimed = total_claimed + ?, mining_claimed = 1 WHERE id = ?',
        [newPts, newMined, earned, user.id]);
      await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
        [crypto.randomUUID(), user.id, 'mining_claim', earned, '⛏️ Mining claim']);
      await dbRun(env, "UPDATE mining_sessions SET claimed_at = datetime('now'), coins_earned = ?, is_claimed = 1 WHERE user_id = ? AND is_claimed = 0",
        [earned, user.id]);

      if (user.referred_by && newMined === earned) {
        const refUser = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [user.referred_by]);
        if (refUser) {
          const cfgPPR = await dbFirst(env, "SELECT value FROM settings WHERE key = 'referral_power_per_ref'");
          const cfgMaxP = await dbFirst(env, "SELECT value FROM settings WHERE key = 'max_mining_power'");
          const cfgARB = await dbFirst(env, "SELECT value FROM settings WHERE key = 'active_referral_bonus'");
          const ppr = parseFloat(cfgPPR?.value || '0.1'), maxP = parseFloat(cfgMaxP?.value || '10.0');
          const newAR = parseInt(refUser.active_referral_count || 0) + 1;
          const newPow = Math.min(1.0 + newAR * ppr, maxP);
          const arb = parseInt(cfgARB?.value || '200');
          await dbRun(env, 'UPDATE users SET active_referral_count = ?, mining_power = ?, points = points + ? WHERE id = ?',
            [newAR, newPow, arb, refUser.id]);
          await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
            [crypto.randomUUID(), refUser.id, 'active_referral_bonus', arb, '🔥 @' + user.username + ' started mining!']);
        }
      }
      return json({ success: true, earned });
    }

    if (path === '/api/tasks' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const tasks = await dbAll(env, 'SELECT * FROM tasks WHERE is_active = 1 ORDER BY display_order');
      const done = await dbAll(env, 'SELECT task_id FROM user_tasks WHERE user_id = ?', [user.id]);
      return json({ tasks, done: done.map(d => d.task_id) });
    }

    if (path === '/api/tasks/complete' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id } = await request.json();
      const task = await dbFirst(env, 'SELECT * FROM tasks WHERE id = ? AND is_active = 1', [task_id]);
      if (!task) return err('Task not found');
      const already = await dbFirst(env, 'SELECT id FROM user_tasks WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      if (already) return err('Already completed');
      if (task.task_type === 'quiz') return err('Quiz tasks require answer verification');
      // If task has a verify code, block direct completion — must go through /api/tasks/verify-code
      if (task.verify_code && task.verify_code.trim() !== '') return err('This task requires a secret code to complete');
      await dbRun(env, "INSERT INTO user_tasks (id,user_id,task_id,completed_at) VALUES (?,?,?,datetime('now'))",
        [crypto.randomUUID(), user.id, task_id]);
      await dbRun(env, 'UPDATE users SET points = points + ?, total_tasks_completed = total_tasks_completed + 1 WHERE id = ?',
        [task.points_reward, user.id]);
      await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
        [crypto.randomUUID(), user.id, 'task_complete', task.points_reward, '✅ ' + task.title]);
      return json({ success: true, earned: task.points_reward });
    }

    // VERIFY CODE — user URL/video pe jaake code dhundta hai, yahan submit karta hai
    if (path === '/api/tasks/verify-code' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id, code } = await request.json();
      if (!task_id || !code) return err('Task ID aur code zaroori hain');
      const task = await dbFirst(env, 'SELECT * FROM tasks WHERE id = ? AND is_active = 1', [task_id]);
      if (!task) return err('Task nahi mila');
      const already = await dbFirst(env, 'SELECT id FROM user_tasks WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      if (already) return err('Already completed');
      // Check attempts (reuse quiz_attempts table)
      let attempt = await dbFirst(env, 'SELECT * FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      const maxAttempts = 3;
      const attempts = attempt ? attempt.attempts : 0;
      if (attempt && attempt.failed == 1) return json({ success: false, failed: true, message: 'Aap fail ho chuke hain. Dobara task shuru karen.' });
      const correct = (task.verify_code || '').trim().toLowerCase();
      const given = (code || '').trim().toLowerCase();
      const isCorrect = correct === given;
      if (isCorrect) {
        await dbRun(env, "INSERT INTO user_tasks (id,user_id,task_id,completed_at) VALUES (?,?,?,datetime('now'))",
          [crypto.randomUUID(), user.id, task_id]);
        await dbRun(env, 'UPDATE users SET points = points + ?, total_tasks_completed = total_tasks_completed + 1 WHERE id = ?',
          [task.points_reward, user.id]);
        await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
          [crypto.randomUUID(), user.id, 'task_complete', task.points_reward, '✅ ' + task.title]);
        if (attempt) await dbRun(env, 'DELETE FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
        return json({ success: true, earned: task.points_reward });
      } else {
        const newAttempts = attempts + 1;
        const isFailed = newAttempts >= maxAttempts;
        if (attempt) {
          await dbRun(env, 'UPDATE quiz_attempts SET attempts = ?, failed = ? WHERE user_id = ? AND task_id = ?',
            [newAttempts, isFailed ? 1 : 0, user.id, task_id]);
        } else {
          await dbRun(env, "INSERT INTO quiz_attempts (id,user_id,task_id,attempts,failed,created_at) VALUES (?,?,?,?,?,datetime('now'))",
            [crypto.randomUUID(), user.id, task_id, newAttempts, isFailed ? 1 : 0]);
        }
        const remaining = maxAttempts - newAttempts;
        if (isFailed) return json({ success: false, failed: true, message: 'Galat code! 3 baar fail ho gaye. Dobara task shuru karen.' });
        return json({ success: false, failed: false, remaining, message: 'Galat code! ' + remaining + ' maukay baki hain.' });
      }
    }

    // VERIFY CODE RESET — fail hone k baad dobara shuru
    if (path === '/api/tasks/verify-reset' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id } = await request.json();
      await dbRun(env, 'DELETE FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      return json({ success: true });
    }

    if (path === '/api/tasks/quiz-verify' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id, answer } = await request.json();
      if (!task_id || answer === undefined) return err('Missing fields');
      const task = await dbFirst(env, "SELECT * FROM tasks WHERE id = ? AND is_active = 1 AND task_type = 'quiz'", [task_id]);
      if (!task) return err('Quiz task not found');
      const already = await dbFirst(env, 'SELECT id FROM user_tasks WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      if (already) return err('Already completed');
      let attempt = await dbFirst(env, 'SELECT * FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      const maxAttempts = 3;
      const attempts = attempt ? attempt.attempts : 0;
      if (attempt && attempt.failed == 1) return json({ success: false, failed: true, message: 'Aap fail ho chuke hain. Dobara task shuru karen.' });
      const correct = (task.quiz_answer || '').trim().toLowerCase();
      const given = (answer || '').trim().toLowerCase();
      const isCorrect = correct === given;
      if (isCorrect) {
        await dbRun(env, "INSERT INTO user_tasks (id,user_id,task_id,completed_at) VALUES (?,?,?,datetime('now'))",
          [crypto.randomUUID(), user.id, task_id]);
        await dbRun(env, 'UPDATE users SET points = points + ?, total_tasks_completed = total_tasks_completed + 1 WHERE id = ?',
          [task.points_reward, user.id]);
        await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
          [crypto.randomUUID(), user.id, 'task_complete', task.points_reward, '✅ Quiz: ' + task.title]);
        if (attempt) await dbRun(env, 'DELETE FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
        return json({ success: true, earned: task.points_reward });
      } else {
        const newAttempts = attempts + 1;
        const isFailed = newAttempts >= maxAttempts;
        if (attempt) {
          await dbRun(env, 'UPDATE quiz_attempts SET attempts = ?, failed = ? WHERE user_id = ? AND task_id = ?',
            [newAttempts, isFailed ? 1 : 0, user.id, task_id]);
        } else {
          await dbRun(env, "INSERT INTO quiz_attempts (id,user_id,task_id,attempts,failed,created_at) VALUES (?,?,?,?,?,datetime('now'))",
            [crypto.randomUUID(), user.id, task_id, newAttempts, isFailed ? 1 : 0]);
        }
        const remaining = maxAttempts - newAttempts;
        if (isFailed) return json({ success: false, failed: true, message: 'Galat jawab! 3 baar fail ho gaye. Dobara task shuru karen.' });
        return json({ success: false, failed: false, remaining, message: 'Galat jawab! ' + remaining + ' maukay baki hain.' });
      }
    }

    if (path === '/api/tasks/quiz-reset' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id } = await request.json();
      await dbRun(env, 'DELETE FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      return json({ success: true });
    }

    if (path === '/api/leaderboard' && request.method === 'GET') {
      const results = await dbAll(env, 'SELECT username,wallet_address,wallet_type,total_mined,mining_power,active_referral_count FROM users ORDER BY total_mined DESC LIMIT 25');
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
      const uc = await dbFirst(env, 'SELECT COUNT(*) as c FROM users');
      const tm = await dbFirst(env, 'SELECT SUM(total_mined) as s FROM users');
      return json({ users: parseInt(uc?.c || 0), total_mined: parseInt(tm?.s || 0) });
    }


    // ── ADS ───────────────────────────────────────
    if (path === '/api/ads' && request.method === 'GET') {
      const results = await dbAll(env, 'SELECT * FROM ads WHERE is_active = 1 ORDER BY created_at DESC');
      return json(results.map(a => ({...a, pages: a.pages ? a.pages.split(',') : ['index','blog','policies','vision']})));
    }

    // ── ADMIN ─────────────────────────────────────
    if (path.startsWith('/api/admin/')) {
      const adminPass = request.headers.get('X-Admin-Key');
      if (adminPass !== (env.ADMIN_KEY || "Admin@2026")) return err('Forbidden', 403);
      const body = request.method !== 'GET' ? await request.json().catch(() => ({})) : {};

      if (path === '/api/admin/users' && request.method === 'GET') {
        return json(await dbAll(env, 'SELECT * FROM users ORDER BY created_at DESC LIMIT 100'));
      }
      if (path === '/api/admin/users/update' && request.method === 'POST') {
        await dbRun(env, 'UPDATE users SET username=?,points=?,mining_power=?,is_banned=? WHERE id=?',
          [body.username, body.points, body.mining_power, body.is_banned ? 1 : 0, body.id]);
        return json({ success: true });
      }
      if (path === '/api/admin/tasks' && request.method === 'GET') {
        return json(await dbAll(env, 'SELECT * FROM tasks ORDER BY display_order'));
      }
      if (path === '/api/admin/tasks/save' && request.method === 'POST') {
        const { id, title, description, icon, task_type, url, ad_url, quiz_question, quiz_answer, verify_code, points_reward, timer_seconds, display_order, is_active } = body;
        if (id) {
          await dbRun(env, 'UPDATE tasks SET title=?,description=?,icon=?,task_type=?,url=?,ad_url=?,quiz_question=?,quiz_answer=?,verify_code=?,points_reward=?,timer_seconds=?,display_order=?,is_active=? WHERE id=?',
            [title, description||null, icon||'🎯', task_type, url||null, ad_url||null, quiz_question||null, quiz_answer||null, verify_code||null, points_reward, timer_seconds||0, display_order||99, is_active?1:0, id]);
        } else {
          await dbRun(env, "INSERT INTO tasks (id,title,description,icon,task_type,url,ad_url,quiz_question,quiz_answer,verify_code,points_reward,timer_seconds,display_order,is_active,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))",
            [crypto.randomUUID(), title, description||null, icon||'🎯', task_type, url||null, ad_url||null, quiz_question||null, quiz_answer||null, verify_code||null, points_reward, timer_seconds||0, display_order||99, is_active?1:0]);
        }
        return json({ success: true });
      }
      if (path === '/api/admin/tasks/delete' && request.method === 'POST') {
        await dbRun(env, 'DELETE FROM tasks WHERE id=?', [body.id]);
        return json({ success: true });
      }
      if (path === '/api/admin/settings' && request.method === 'POST') {
        for (const [key, value] of Object.entries(body)) {
          await dbRun(env, 'UPDATE settings SET value=? WHERE key=?', [String(value), key]);
        }
        return json({ success: true });
      }
      if (path === '/api/admin/blog' && request.method === 'GET') {
        return json(await dbAll(env, 'SELECT * FROM blog_posts ORDER BY display_order'));
      }
      if (path === '/api/admin/blog/save' && request.method === 'POST') {
        const { id, title, slug, category, phase, excerpt, content, display_order, status } = body;
        const sl = slug || title.toLowerCase().replace(/[^a-z0-9]+/g, '-');
        if (id) {
          await dbRun(env, 'UPDATE blog_posts SET title=?,slug=?,category=?,phase=?,excerpt=?,content=?,display_order=?,status=? WHERE id=?',
            [title, sl, category||'roadmap', phase||null, excerpt||null, content||null, display_order||99, status||'published', id]);
        } else {
          await dbRun(env, "INSERT INTO blog_posts (id,title,slug,category,phase,excerpt,content,display_order,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,datetime('now'))",
            [crypto.randomUUID(), title, sl, category||'roadmap', phase||null, excerpt||null, content||null, display_order||99, status||'published']);
        }
        return json({ success: true });
      }
      if (path === '/api/admin/blog/delete' && request.method === 'POST') {
        await dbRun(env, 'DELETE FROM blog_posts WHERE id=?', [body.id]);
        return json({ success: true });
      }
      if (path === '/api/admin/dashboard' && request.method === 'GET') {
        const [uc, tm, tc, mc] = await Promise.all([
          dbFirst(env, 'SELECT COUNT(*) as c FROM users'),
          dbFirst(env, 'SELECT SUM(total_mined) as s FROM users'),
          dbFirst(env, 'SELECT COUNT(*) as c FROM tasks WHERE is_active=1'),
          dbFirst(env, 'SELECT COUNT(*) as c FROM mining_sessions'),
        ]);
        const recent = await dbAll(env, 'SELECT username,points,total_mined,mining_power,created_at,login_method FROM users ORDER BY created_at DESC LIMIT 10');
        return json({ users: parseInt(uc?.c||0), total_mined: parseInt(tm?.s||0), tasks: parseInt(tc?.c||0), sessions: parseInt(mc?.c||0), recent });
      }

      if (path === '/api/admin/ads' && request.method === 'GET') {
        return json(await dbAll(env, 'SELECT * FROM ads ORDER BY created_at DESC'));
      }
      if (path === '/api/admin/ads/save' && request.method === 'POST') {
        const { id, name, network, position, code, url, pages, is_active, type } = body;
        const pg = Array.isArray(pages) ? pages.join(',') : (pages || 'index,blog,policies,vision');
        const net = network || type || 'script';
        if (id) {
          await dbRun(env, 'UPDATE ads SET name=?,network=?,position=?,code=?,url=?,pages=?,is_active=? WHERE id=?',
            [name, net, position||'bottom', code||'', url||'', pg, is_active!=null?is_active:1, id]);
        } else {
          await dbRun(env, "INSERT INTO ads (id,name,network,position,code,url,pages,is_active,created_at) VALUES (?,?,?,?,?,?,?,?,datetime('now'))",
            [crypto.randomUUID(), name, net, position||'bottom', code||'', url||'', pg, is_active!=null?is_active:1]);
        }
        return json({ success: true });
      }
      if (path === '/api/admin/ads/delete' && request.method === 'POST') {
        await dbRun(env, 'DELETE FROM ads WHERE id=?', [body.id]);
        return json({ success: true });
      }
      if (path === '/api/admin/transactions' && request.method === 'GET') {
        return json(await dbAll(env, 'SELECT t.*,u.username FROM transactions t LEFT JOIN users u ON t.user_id=u.id ORDER BY t.created_at DESC LIMIT 100'));
      }
    }

    return err('Not found', 404);

  } catch (e) {
    return err('Server error: ' + e.message, 500);
  }
}
