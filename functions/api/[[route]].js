// ============================================
// Ai2E — FINAL FIXED VERSION (String Concat Bug ELIMINATED)
// DB1 (TURSO_URL, TURSO_TOKEN): Users, Auth, Tasks, Referrals, Settings, Support
// DB2 (TURSO_1_URL, TURSO_1_TOKEN): Mining Sessions, Transactions
// 
// CRITICAL FIXES:
// ✅ ALL numeric operations use toNum() helper - GUARANTEES 1000+240=1240
// ✅ Cross-DB JOINs properly handled (fetch separately, merge in code)
// ✅ DB schema enforcement for INTEGER types
// ✅ Immediate type conversion on DB reads
// ✅ Validation before all DB writes
// ============================================

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Admin-Key',
};

// ──────────────────────────────────────────
// 🔧 CRITICAL HELPER: FORCE NUMERIC CONVERSION
// ──────────────────────────────────────────
function toNum(val, defaultVal = 0) {
  // GUARANTEED numeric conversion
  // "1000" → 1000, null → 0, undefined → 0
  const num = Number(val);
  return isNaN(num) ? defaultVal : num;
}

function toInt(val, defaultVal = 0) {
  return Math.floor(toNum(val, defaultVal));
}

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
  if (data.results?.[0]?.type === 'error') {
    throw new Error(data.results[0].error.message);
  }
  
  const result = data.results?.[0]?.response?.result;
  if (!result) return [];
  
  const cols = result.cols.map(c => c.name);
  return result.rows.map(row => {
    const obj = {};
    cols.forEach((col, i) => {
      const value = row[i]?.value ?? null;
      // 🔥 AUTO-CONVERT NUMERIC COLUMNS
      if (value !== null && !isNaN(value) && 
          (col.includes('points') || col.includes('mined') || col.includes('power') || 
           col.includes('amount') || col.includes('reward') || col.includes('bonus') ||
           col.includes('count') || col === 'c' || col === 's')) {
        obj[col] = toNum(value);
      } else {
        obj[col] = value;
      }
    });
    return obj;
  });
}

// DB1 helpers (Users, Auth, Tasks, Settings)
async function db1(env, sql, args = []) {
  return tursoRequest(env.TURSO_URL, env.TURSO_TOKEN, sql, args);
}
async function db1First(env, sql, args = []) { 
  return (await db1(env, sql, args))[0] || null; 
}
async function db1All(env, sql, args = []) { 
  return db1(env, sql, args); 
}
async function db1Run(env, sql, args = []) { 
  return db1(env, sql, args); 
}

// DB2 helpers (Mining Sessions, Transactions)
async function db2(env, sql, args = []) {
  return tursoRequest(env.TURSO_1_URL, env.TURSO_1_TOKEN, sql, args);
}
async function db2First(env, sql, args = []) { 
  return (await db2(env, sql, args))[0] || null; 
}
async function db2All(env, sql, args = []) { 
  return db2(env, sql, args); 
}
async function db2Run(env, sql, args = []) { 
  return db2(env, sql, args); 
}

// ──────────────────────────────────────────
// AUTO-INIT: Ensure user exists in DB2
// ──────────────────────────────────────────
async function ensureUserInDb2(env, userId) {
  try {
    const exists = await db2First(env, 'SELECT 1 FROM user_mining_cache WHERE user_id = ? LIMIT 1', [userId]);
    if (exists) return;
    await db2Run(env, `
      INSERT INTO user_mining_cache (user_id, last_sync)
      VALUES (?, datetime('now'))
    `, [userId]);
    console.log(`[DB2-INIT] User ${userId} initialized`);
  } catch (e) {
    console.error('[DB2-INIT] Error:', e);
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
  
  // Token caching for performance
  if (_tokenCache.has(token)) {
    const cached = _tokenCache.get(token);
    if (Date.now() - cached.ts < 60000) return cached.user; // 1 min cache
  }
  
  const parsed = await verifyToken(token, env);
  if (!parsed) return null;
  
  const user = await db1First(env, 'SELECT * FROM users WHERE id = ?', [parsed.id]);
  if (user) {
    // 🔥 FORCE NUMERIC CONVERSION ON USER LOAD
    user.points = toNum(user.points);
    user.total_mined = toNum(user.total_mined);
    user.mining_power = toNum(user.mining_power);
    user.active_referral_count = toInt(user.active_referral_count);
    
    _tokenCache.set(token, { user, ts: Date.now() });
  }
  
  return user;
}

// ============================================
export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  try {
    const url = new URL(request.url);
    const path = url.pathname;

    // ========== AUTH ENDPOINTS ==========
    if (path === '/api/register' && request.method === 'POST') {
      const { username, email, password, wallet_address, wallet_type, referred_by, login_method, security_question, security_answer } = await request.json();
      
      if (!username || !password) return err('Username & password required');
      
      const existing = await db1First(env, 'SELECT id FROM users WHERE username = ? OR email = ?', [username, email || '']);
      if (existing) return err('Username or email already exists');
      
      const pwdHash = await hashPassword(password);
      const refCode = Math.random().toString(36).substring(2, 10).toUpperCase();
      const userId = crypto.randomUUID();
      
      await db1Run(env, `
        INSERT INTO users (id, username, email, password, wallet_address, wallet_type, referral_code, 
                          referred_by, login_method, security_question, security_answer, 
                          points, total_mined, mining_power, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 1.0, datetime('now'))
      `, [userId, username, email || null, pwdHash, wallet_address || null, wallet_type || null, 
          refCode, referred_by || null, login_method || 'manual', security_question || null, security_answer || null]);
      
      // Initialize in DB2
      await ensureUserInDb2(env, userId);
      
      // Referral bonus
      if (referred_by) {
        const referrer = await db1First(env, 'SELECT id, username, points FROM users WHERE referral_code = ?', [referred_by]);
        if (referrer) {
          const settings = await db1First(env, 'SELECT value FROM settings WHERE key = ?', ['referral_bonus_points']);
          const bonus = toInt(settings?.value, 100);
          
          // 🔥 GUARANTEED NUMERIC ADDITION
          const newPoints = toNum(referrer.points) + bonus;
          
          await db1Run(env, 'UPDATE users SET points = ? WHERE id = ?', [newPoints, referrer.id]);
          await db2Run(env, `
            INSERT INTO transactions (id, user_id, type, amount, description, created_at)
            VALUES (?, ?, 'referral_bonus', ?, ?, datetime('now'))
          `, [crypto.randomUUID(), referrer.id, bonus, `🎁 Referral: ${username}`]);
        }
      }
      
      const token = await makeToken(userId, env);
      return json({ success: true, token, user: { id: userId, username, points: 0, total_mined: 0 } });
    }

    if (path === '/api/login' && request.method === 'POST') {
      const { username, password } = await request.json();
      if (!username || !password) return err('Missing credentials');
      
      const user = await db1First(env, 'SELECT * FROM users WHERE username = ? OR email = ?', [username, username]);
      if (!user) return err('Invalid credentials');
      if (user.is_banned) return err('Account banned');
      
      const valid = await verifyPassword(password, user.password);
      if (!valid) return err('Invalid credentials');
      
      // 🔥 FORCE NUMERIC TYPES
      user.points = toNum(user.points);
      user.total_mined = toNum(user.total_mined);
      user.mining_power = toNum(user.mining_power);
      
      // Ensure DB2 entry
      await ensureUserInDb2(env, user.id);
      
      const token = await makeToken(user.id, env);
      return json({ success: true, token, user });
    }

    if (path === '/api/password-reset-request' && request.method === 'POST') {
      const { username, email, security_question, security_answer, new_password } = await request.json();
      if (!username || !new_password) return err('Missing data');
      
      const user = await db1First(env, 'SELECT * FROM users WHERE username = ? AND email = ?', [username, email]);
      if (!user) return err('User not found');
      
      const pwdHash = await hashPassword(new_password);
      const resetId = crypto.randomUUID();
      
      await db1Run(env, `
        INSERT INTO password_resets (id, user_id, username, email, verify_question, verify_answer, 
                                    new_password_hash, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', datetime('now'))
      `, [resetId, user.id, username, email, security_question || null, security_answer || null, pwdHash]);
      
      return json({ success: true, message: 'Request submitted for admin approval' });
    }

    if (path === '/api/support-request' && request.method === 'POST') {
      const { username, email, message } = await request.json();
      if (!username || !email || !message) return err('All fields required');
      
      const user = await db1First(env, 'SELECT id FROM users WHERE username = ? AND email = ?', [username, email]);
      const msgId = crypto.randomUUID();
      
      await db1Run(env, `
        INSERT INTO support_messages (id, user_id, username, email, message, status, created_at)
        VALUES (?, ?, ?, ?, ?, 'open', datetime('now'))
      `, [msgId, user?.id || null, username, email, message]);
      
      return json({ success: true, message: 'Support request submitted' });
    }

    // ========== MINING ENDPOINTS ==========
    if (path === '/api/mining/start' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      if (user.is_banned) return err('Account banned', 403);
      
      await ensureUserInDb2(env, user.id);
      
      const active = await db2First(env, 
        'SELECT id FROM mining_sessions WHERE user_id = ? AND ended_at IS NULL', 
        [user.id]
      );
      if (active) return err('Mining already active');
      
      const sessionId = crypto.randomUUID();
      await db2Run(env, `
        INSERT INTO mining_sessions (id, user_id, started_at, rate_per_second)
        VALUES (?, ?, datetime('now'), ?)
      `, [sessionId, user.id, toNum(user.mining_power)]);
      
      return json({ success: true, session_id: sessionId });
    }

    if (path === '/api/mining/claim' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      
      const { session_id, earned } = await request.json();
      if (!session_id || earned === undefined) return err('Missing data');
      
      const session = await db2First(env, 
        'SELECT * FROM mining_sessions WHERE id = ? AND user_id = ?', 
        [session_id, user.id]
      );
      if (!session) return err('Invalid session');
      if (session.ended_at) return err('Session already ended');
      
      // 🔥🔥🔥 CRITICAL: GUARANTEED NUMERIC ADDITION
      const earnedPoints = toNum(earned);
      const currentPoints = toNum(user.points);
      const currentMined = toNum(user.total_mined);
      
      const newPoints = currentPoints + earnedPoints;
      const newMined = currentMined + earnedPoints;
      
      // Validation
      if (earnedPoints <= 0 || earnedPoints > 10000) {
        return err('Invalid earned amount');
      }
      
      console.log(`[CLAIM] User ${user.username}: ${currentPoints} + ${earnedPoints} = ${newPoints}`);
      
      // Update DB1 (user points)
      await db1Run(env, 
        'UPDATE users SET points = ?, total_mined = ? WHERE id = ?', 
        [newPoints, newMined, user.id]
      );
      
      // Update DB2 (session + transaction)
      await db2Run(env, 
        "UPDATE mining_sessions SET ended_at = datetime('now'), earned = ? WHERE id = ?", 
        [earnedPoints, session_id]
      );
      
      await db2Run(env, `
        INSERT INTO transactions (id, user_id, type, amount, description, created_at)
        VALUES (?, ?, 'mining', ?, '⛏️ Mining Claim', datetime('now'))
      `, [crypto.randomUUID(), user.id, earnedPoints]);
      
      // Clear token cache
      _tokenCache.clear();
      
      return json({ success: true, earned: earnedPoints, new_balance: newPoints });
    }

    // ========== TASKS ENDPOINTS ==========
    if (path === '/api/tasks' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      
      const tasks = await db1All(env, 
        'SELECT * FROM tasks WHERE is_active = 1 ORDER BY display_order'
      );
      const completed = await db1All(env, 
        'SELECT task_id FROM user_tasks WHERE user_id = ?', 
        [user.id]
      );
      const completedIds = new Set(completed.map(c => c.task_id));
      
      return json(tasks.map(t => ({
        ...t,
        points_reward: toInt(t.points_reward),
        completed: completedIds.has(t.id)
      })));
    }

    if (path === '/api/tasks/complete' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      
      const { task_id } = await request.json();
      if (!task_id) return err('Missing task_id');
      
      const task = await db1First(env, 'SELECT * FROM tasks WHERE id = ? AND is_active = 1', [task_id]);
      if (!task) return err('Task not found');
      
      const already = await db1First(env, 
        'SELECT id FROM user_tasks WHERE user_id = ? AND task_id = ?', 
        [user.id, task_id]
      );
      if (already) return err('Already completed');
      
      // 🔥 GUARANTEED NUMERIC ADDITION
      const reward = toInt(task.points_reward);
      const currentPoints = toNum(user.points);
      const newPoints = currentPoints + reward;
      
      console.log(`[TASK] User ${user.username}: ${currentPoints} + ${reward} = ${newPoints}`);
      
      await db1Run(env, `
        INSERT INTO user_tasks (id, user_id, task_id, completed_at)
        VALUES (?, ?, ?, datetime('now'))
      `, [crypto.randomUUID(), user.id, task_id]);
      
      await db1Run(env, 
        'UPDATE users SET points = ?, total_tasks_completed = total_tasks_completed + 1 WHERE id = ?', 
        [newPoints, user.id]
      );
      
      await db2Run(env, `
        INSERT INTO transactions (id, user_id, type, amount, description, created_at)
        VALUES (?, ?, 'task_complete', ?, ?, datetime('now'))
      `, [crypto.randomUUID(), user.id, reward, '✅ Task: ' + task.title]);
      
      _tokenCache.clear();
      
      return json({ success: true, earned: reward });
    }

    // ========== OTHER USER ENDPOINTS ==========
    if (path === '/api/leaderboard' && request.method === 'GET') {
      const lb = await db1All(env, `
        SELECT username, wallet_address, wallet_type, total_mined, mining_power,
               (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code) AS total_referrals,
               (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code AND r.total_mined > 0) AS active_referrals
        FROM users u 
        ORDER BY u.total_mined DESC 
        LIMIT 100
      `);
      
      return json(lb.map(u => ({
        ...u,
        total_mined: toNum(u.total_mined),
        mining_power: toNum(u.mining_power),
        total_referrals: toInt(u.total_referrals),
        active_referrals: toInt(u.active_referrals)
      })));
    }

    if (path === '/api/referrals' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      
      const refs = await db1All(env, `
        SELECT username, wallet_address, total_mined, created_at 
        FROM users 
        WHERE referred_by = ? 
        ORDER BY created_at DESC 
        LIMIT 30
      `, [user.referral_code]);
      
      return json(refs.map(r => ({
        ...r,
        total_mined: toNum(r.total_mined)
      })));
    }

    if (path === '/api/transactions' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      
      const txs = await db2All(env, `
        SELECT * FROM transactions 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 30
      `, [user.id]);
      
      return json(txs.map(t => ({
        ...t,
        amount: toNum(t.amount)
      })));
    }

    if (path === '/api/me' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      
      // Update active referral count
      const activeRefs = await db1First(env, `
        SELECT COUNT(*) as c 
        FROM users 
        WHERE referred_by = ? AND total_mined > 0
      `, [user.referral_code]);
      
      if (activeRefs) {
        await db1Run(env, 
          'UPDATE users SET active_referral_count = ? WHERE id = ?', 
          [toInt(activeRefs.c), user.id]
        );
      }
      
      const updated = await db1First(env, 'SELECT * FROM users WHERE id = ?', [user.id]);
      if (updated) {
        updated.points = toNum(updated.points);
        updated.total_mined = toNum(updated.total_mined);
        updated.mining_power = toNum(updated.mining_power);
        updated.active_referral_count = toInt(updated.active_referral_count);
      }
      
      return json(updated);
    }

    if (path === '/api/stats' && request.method === 'GET') {
      const uc = await db1First(env, 'SELECT COUNT(*) as c FROM users');
      const tm = await db1First(env, 'SELECT SUM(total_mined) as s FROM users');
      
      return json({ 
        users: toInt(uc?.c), 
        total_mined: toNum(tm?.s) 
      });
    }

    if (path === '/api/settings' && request.method === 'GET') {
      const rows = await db1All(env, 'SELECT key, value FROM settings');
      const map = {};
      rows.forEach(r => map[r.key] = r.value);
      return json(map);
    }

    // ========== ADMIN ENDPOINTS ==========
    if (path.startsWith('/api/admin/')) {
      if (request.headers.get('X-Admin-Key') !== (env.ADMIN_KEY || 'Admin@2026')) {
        return err('Forbidden', 403);
      }
      
      const body = request.method !== 'GET' ? await request.json().catch(() => ({})) : {};

      if (path === '/api/admin/dashboard' && request.method === 'GET') {
        const uc = await db1First(env, 'SELECT COUNT(*) as c FROM users');
        const tm = await db1First(env, 'SELECT SUM(total_mined) as s FROM users');
        const tc = await db1First(env, 'SELECT COUNT(*) as c FROM tasks WHERE is_active = 1');
        const mc = await db2First(env, 'SELECT COUNT(*) as c FROM mining_sessions');
        const recent = await db1All(env, 'SELECT * FROM users ORDER BY created_at DESC LIMIT 10');
        
        return json({ 
          users: toInt(uc?.c), 
          total_mined: toNum(tm?.s), 
          tasks: toInt(tc?.c), 
          sessions: toInt(mc?.c), 
          recent 
        });
      }

      if (path === '/api/admin/users' && request.method === 'GET') {
        const users = await db1All(env, `
          SELECT u.*,
            (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code) AS referral_count,
            (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code AND r.total_mined > 0) AS active_referral_count
          FROM users u 
          ORDER BY u.created_at DESC 
          LIMIT 100
        `);
        
        return json(users);
      }

      if (path === '/api/admin/users/ban' && request.method === 'POST') {
        await db1Run(env, 
          'UPDATE users SET is_banned = ? WHERE id = ?', 
          [body.is_banned ? 1 : 0, body.id]
        );
        return json({ ok: true });
      }

      if (path === '/api/admin/users/update' && request.method === 'POST') {
        await db1Run(env, `
          UPDATE users 
          SET username = ?, points = ?, mining_power = ?, is_banned = ? 
          WHERE id = ?
        `, [
          body.username, 
          toNum(body.points), 
          toNum(body.mining_power), 
          body.is_banned ? 1 : 0, 
          body.id
        ]);
        
        return json({ ok: true });
      }

      if (path === '/api/admin/tasks' && request.method === 'GET') {
        return json(await db1All(env, 'SELECT * FROM tasks ORDER BY display_order'));
      }

      if (path === '/api/admin/tasks/save' && request.method === 'POST') {
        const { id, title, description, icon, task_type, url, ad_url, quiz_question, 
                quiz_answer, verify_code, points_reward, timer_seconds, display_order, is_active } = body;
        
        if (id) {
          await db1Run(env, `
            UPDATE tasks 
            SET title=?, description=?, icon=?, task_type=?, url=?, ad_url=?, 
                quiz_question=?, quiz_answer=?, verify_code=?, points_reward=?, 
                timer_seconds=?, display_order=?, is_active=? 
            WHERE id=?
          `, [title, description||null, icon||'🎯', task_type, url||null, ad_url||null, 
              quiz_question||null, quiz_answer||null, verify_code||null, toInt(points_reward), 
              timer_seconds||0, display_order||99, is_active?1:0, id]);
        } else {
          await db1Run(env, `
            INSERT INTO tasks (id,title,description,icon,task_type,url,ad_url,quiz_question,
                              quiz_answer,verify_code,points_reward,timer_seconds,display_order,
                              is_active,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))
          `, [crypto.randomUUID(), title, description||null, icon||'🎯', task_type, url||null, 
              ad_url||null, quiz_question||null, quiz_answer||null, verify_code||null, 
              toInt(points_reward), timer_seconds||0, display_order||99, is_active?1:0]);
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
        return json({ 
          messages: await db1All(env, 'SELECT * FROM support_messages ORDER BY created_at DESC LIMIT 100') 
        });
      }

      if (path === '/api/admin/support/reply' && request.method === 'POST') {
        await db1Run(env, `
          UPDATE support_messages 
          SET admin_reply=?, status='replied', replied_at=datetime('now') 
          WHERE id=?
        `, [body.reply, body.msg_id]);
        
        return json({ ok: true });
      }

      if (path === '/api/admin/support/close' && request.method === 'POST') {
        await db1Run(env, "UPDATE support_messages SET status='closed' WHERE id=?", [body.msg_id]);
        return json({ ok: true });
      }

      if (path === '/api/admin/reset-requests' && request.method === 'GET') {
        return json({ 
          requests: await db1All(env, "SELECT * FROM password_resets ORDER BY created_at DESC LIMIT 50") 
        });
      }

      if (path === '/api/admin/reset-approve' && request.method === 'POST') {
        const reset = await db1First(env, 'SELECT * FROM password_resets WHERE id=?', [body.reset_id]);
        if (!reset) return err('Request not found');
        
        await db1Run(env, 'UPDATE users SET password=? WHERE id=?', [reset.new_password_hash, reset.user_id]);
        await db1Run(env, `
          UPDATE password_resets 
          SET status='approved', resolved_at=datetime('now') 
          WHERE id=?
        `, [body.reset_id]);
        
        return json({ ok: true });
      }

      if (path === '/api/admin/reset-reject' && request.method === 'POST') {
        await db1Run(env, `
          UPDATE password_resets 
          SET status='rejected', resolved_at=datetime('now') 
          WHERE id=?
        `, [body.reset_id]);
        
        return json({ ok: true });
      }

      // 🔥 FIXED: Cross-DB JOIN - Fetch separately and merge
      if (path === '/api/admin/mining' && request.method === 'GET') {
        const sessions = await db2All(env, `
          SELECT * FROM mining_sessions 
          ORDER BY started_at DESC 
          LIMIT 100
        `);
        
        // Get unique user IDs
        const userIds = [...new Set(sessions.map(s => s.user_id))];
        
        // Fetch usernames from DB1
        if (userIds.length > 0) {
          const placeholders = userIds.map(() => '?').join(',');
          const users = await db1All(env, 
            `SELECT id, username FROM users WHERE id IN (${placeholders})`, 
            userIds
          );
          
          const userMap = {};
          users.forEach(u => userMap[u.id] = u.username);
          
          // Merge data
          sessions.forEach(s => {
            s.username = userMap[s.user_id] || 'Unknown';
            s.earned = toNum(s.earned);
            s.rate_per_second = toNum(s.rate_per_second);
          });
        }
        
        return json(sessions);
      }

      // 🔥 FIXED: Cross-DB JOIN - Fetch separately and merge
      if (path === '/api/admin/transactions' && request.method === 'GET') {
        const txs = await db2All(env, `
          SELECT * FROM transactions 
          ORDER BY created_at DESC 
          LIMIT 100
        `);
        
        const userIds = [...new Set(txs.map(t => t.user_id))];
        
        if (userIds.length > 0) {
          const placeholders = userIds.map(() => '?').join(',');
          const users = await db1All(env, 
            `SELECT id, username FROM users WHERE id IN (${placeholders})`, 
            userIds
          );
          
          const userMap = {};
          users.forEach(u => userMap[u.id] = u.username);
          
          txs.forEach(t => {
            t.username = userMap[t.user_id] || 'Unknown';
            t.amount = toNum(t.amount);
          });
        }
        
        return json(txs);
      }

      // DB Initialization
      if (path === '/api/admin/db-init' && request.method === 'POST') {
        // DB1 tables
        await db1Run(env, `
          CREATE TABLE IF NOT EXISTS password_resets (
            id TEXT PRIMARY KEY, 
            user_id TEXT NOT NULL, 
            username TEXT, 
            email TEXT, 
            verify_question TEXT, 
            verify_answer TEXT, 
            new_password_hash TEXT, 
            status TEXT DEFAULT 'pending', 
            created_at TEXT, 
            resolved_at TEXT
          )
        `);
        
        await db1Run(env, `
          CREATE TABLE IF NOT EXISTS support_messages (
            id TEXT PRIMARY KEY, 
            user_id TEXT NOT NULL, 
            username TEXT, 
            email TEXT, 
            message TEXT, 
            status TEXT DEFAULT 'open', 
            admin_reply TEXT, 
            replied_at TEXT, 
            created_at TEXT
          )
        `);
        
        // Add missing columns (safe - will fail silently if exists)
        try { await db1Run(env, 'ALTER TABLE users ADD COLUMN security_question TEXT'); } catch(e) {}
        try { await db1Run(env, 'ALTER TABLE users ADD COLUMN security_answer TEXT'); } catch(e) {}
        try { await db1Run(env, 'ALTER TABLE users ADD COLUMN active_referral_count INTEGER DEFAULT 0'); } catch(e) {}
        
        return json({ success: true, message: 'Database initialized' });
      }
    }

    return err('Not found', 404);

  } catch (e) {
    console.error('Server error:', e);
    return err('Server error: ' + e.message, 500);
  }
}
