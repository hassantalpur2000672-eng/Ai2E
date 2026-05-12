// ============================================
// Ai2E (Artificial Intelligence to Earn) — Cloudflare Pages Function
// Database: Turso (LibSQL)
// Updated: Secure PBKDF2 password hashing (100k iterations)
// ============================================

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// ── Database helper (Turso via HTTP) ─────
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
      const emailNorm = email.toLowerCase().trim();

      const exists = await dbFirst(env, 'SELECT id FROM users WHERE LOWER(email) = ?', [emailNorm]);
      if (exists) return err('Email already registered');

      const uExists = await dbFirst(env, 'SELECT id FROM users WHERE username = ?', [username.toLowerCase()]);
      if (uExists) return err('Username taken');

      const hashed = await hashPassword(password); // new secure hash (100k iter)
      const myRef = 'AI2E' + Math.random().toString(36).substr(2, 6).toUpperCase();
      const id = crypto.randomUUID();
      const cfg = await dbFirst(env, "SELECT value FROM settings WHERE key = 'welcome_bonus'");
      const bonus = parseInt(cfg?.value || '1000');

      await dbRun(env,
        `INSERT INTO users (id,username,email,password_hash,referral_code,referred_by,points,total_mined,mining_power,login_method,mining_claimed,security_question,security_answer,created_at)
         VALUES (?,?,?,?,?,?,?,0,1.0,'email',1,?,?,datetime('now'))`,
        [id, username.toLowerCase(), emailNorm, hashed, myRef, ref_code || null, bonus, security_question||null, security_answer||null]
      );

      await dbRun(env,
        "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
        [crypto.randomUUID(), id, 'welcome_bonus', bonus, '🎉 Welcome bonus']
      );

      // Refer system: registration pe sirf count badhe — asli faida mining claim par (10% + 1% tree)
      if (ref_code) {
        const refUser = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [ref_code]);
        if (refUser && refUser.id !== id) {
          await dbRun(env, 'UPDATE users SET referral_count = referral_count + 1 WHERE id = ?', [refUser.id]);
        }
      }

            const token = await makeToken(id, env);
      const user = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [id]);
      return json({ token, user });
    }

    if (path === '/api/auth/login' && request.method === 'POST') {
      const { email, password } = await request.json();
      if (!email || !password) return err('Email and password required');
      const emailNorm = email.toLowerCase().trim();

      // Case-insensitive email lookup (handles old accounts with mixed case emails)
      let user = await dbFirst(env, 'SELECT * FROM users WHERE email = ?', [emailNorm]);
      if (!user) user = await dbFirst(env, 'SELECT * FROM users WHERE LOWER(email) = ?', [emailNorm]);
      if (!user) return err('Wrong email or password');
      if (user.is_banned == 1) return err('Account banned');

      // Verify password (handles old/new format + automatic upgrade)
      const valid = await verifyPassword(password, user.password_hash);
      if (!valid) return err('Wrong email or password');

      // If old format, upgrade to new format on-the-fly
      if (!user.password_hash.includes(':')) {
        const newHash = await hashPassword(password);
        await dbRun(env, 'UPDATE users SET password_hash = ? WHERE id = ?', [newHash, user.id]);
      }

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
        const myRef = 'AI2E' + Math.random().toString(36).substr(2, 6).toUpperCase();
        const cfg = await dbFirst(env, "SELECT value FROM settings WHERE key = 'welcome_bonus'");
        const bonus = parseInt(cfg?.value || '1000');

        await dbRun(env,
          `INSERT INTO users (id,username,wallet_address,wallet_type,referral_code,referred_by,points,total_mined,mining_power,login_method,mining_claimed,created_at)
           VALUES (?,?,?,?,?,?,?,0,1.0,?,1,datetime('now'))`,
          [id, username, addr, wallet_type || 'web3', myRef, ref_code || null, bonus, wallet_type || 'wallet']
        );

        await dbRun(env,
          "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))",
          [crypto.randomUUID(), id, 'welcome_bonus', bonus, '🎉 Welcome bonus']
        );

        // Referral: update count only
        if (ref_code) {
          const refUser = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [ref_code]);
          if (refUser) {
            await dbRun(env, 'UPDATE users SET referral_count = referral_count + 1 WHERE id = ?', [refUser.id]);
          }
        }
                user = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [id]);
      }

      if (user.is_banned == 1) return err('Account banned');
      const token = await makeToken(user.id, env);
      return json({ token, user });
    }

    // ── FORGOT PASSWORD CHECK ─────────────────────
    if (path === '/api/auth/forgot-check' && request.method === 'POST') {
      const { email } = await request.json();
      if (!email) return err('Email required');
      const user = await dbFirst(env, 'SELECT id, security_question FROM users WHERE LOWER(email) = ?', [email.toLowerCase().trim()]);
      if (!user) return err('No account found with this email');
      return json({ ok: true, security_question: user.security_question || null });
    }

    // ── FORGOT PASSWORD REQUEST ────────────────────
    if (path === '/api/auth/forgot-password' && request.method === 'POST') {
      const { email, answer, question, new_password } = await request.json();
      if (!email || !answer) return err('Email and answer are required');
      if (!new_password || new_password.length < 6) return err('New password must be at least 6 characters');
      const emailNorm = email.toLowerCase().trim();
      const user = await dbFirst(env, 'SELECT id, username, security_question, security_answer FROM users WHERE LOWER(email) = ?', [emailNorm]);
      if (!user) return err('Account not found');
      const existing = await dbFirst(env, "SELECT id FROM password_resets WHERE user_id = ? AND status = 'pending'", [user.id]);
      if (existing) return err('Password reset request already pending. Admin will review soon.');
      // Hash the new password to store securely
      const hashedNew = await hashPassword(new_password);
      await dbRun(env,
        "INSERT INTO password_resets (id,user_id,username,email,verify_question,verify_answer,new_password_hash,status,created_at) VALUES (?,?,?,?,?,?,?,'pending',datetime('now'))",
        [crypto.randomUUID(), user.id, user.username, emailNorm, question||user.security_question||'', answer, hashedNew]
      );
      return json({ ok: true });
    }

    // ── SUPPORT: USER SEND MESSAGE (1 per 24h) ────
    if (path === '/api/support/send' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { message } = await request.json();
      if (!message || message.trim().length < 5) return err('Message is too short');
      const last = await dbFirst(env, "SELECT id FROM support_messages WHERE user_id = ? AND created_at > datetime('now','-24 hours')", [user.id]);
      if (last) return err('You can only send 1 message per 24 hours');
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
      if (!reset) return err('Request not found');
      // Use the new_password_hash that user submitted (already hashed)
      const pwHash = reset.new_password_hash || await hashPassword(new_password || 'reset123');
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
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      // Live count of active referrals (referred users who have mined)
      const refs = await dbFirst(env, 'SELECT COUNT(*) as c FROM users WHERE referred_by = ? AND total_mined > 0', [user.referral_code]);
      const activeRefs = parseInt(refs?.c || 0);
      // Update active_referral_count in DB (no mining power boost - removed)
      await dbRun(env, 'UPDATE users SET active_referral_count = ? WHERE id = ?', [activeRefs, user.id]);
      const updated = await dbFirst(env, 'SELECT * FROM users WHERE id = ?', [user.id]);
      // Return live active_referral_count even if column missing
      return json({ ...updated, active_referral_count: activeRefs });
    }

    if (path === '/api/mine/start' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      
      // Check if there's an active unclaimed session
      if (user.mining_claimed != 1 && user.last_mining_start) {
        const lastStart = new Date(user.last_mining_start).getTime();
        const durMs = 24 * 3600000; // 24 hours
        const elapsed = Date.now() - lastStart;
        
        // If session is still active (not completed), don't allow starting again
        if (elapsed < durMs) {
          return err('Already mining. Please wait for the session to complete.');
        }
      }
      
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
      const cfgMap = {};
      cfgRows.forEach(r => cfgMap[r.key] = r.value);
      const durMs = parseInt(cfgMap.mining_duration_hours || '24') * 3600000;
      const cpm = parseFloat(cfgMap.mining_coins_per_hour || '10') * parseFloat(user.mining_power) / 3600000;
      const start = new Date(user.last_mining_start).getTime();
      const elapsed = Math.min(Date.now() - start, durMs);
      const earned = Math.floor(cpm * elapsed);

      // Allow claim only after full duration (24 hours) has completed
      if (elapsed < durMs) return err('Mining session not complete yet. Come back when timer ends.');

      const newPts = parseInt(user.points || 0) + earned;
      const newMined = parseInt(user.total_mined || 0) + earned;
      await dbRun(env, 'UPDATE users SET points = ?, total_mined = ?, total_claimed = total_claimed + ?, mining_claimed = 1 WHERE id = ?', [newPts, newMined, earned, user.id]);
      await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, 'mining_claim', earned, '⛏️ Mining claim']);
      await dbRun(env, "UPDATE mining_sessions SET claimed_at = datetime('now'), coins_earned = ?, is_claimed = 1 WHERE user_id = ? AND is_claimed = 0", [earned, user.id]);

      // ── Refer Mining Tree: L1=50%, L2=25%, L3=10% ──────────────────────────────
      if (user.referred_by) {
        // Level 1: Direct referrer — 50% of earned
        const L1 = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [user.referred_by]);
        if (L1) {
          const l1Bonus = Math.floor(earned * 0.50);
          if (l1Bonus > 0) {
            await dbRun(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l1Bonus, L1.id]);
            await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), L1.id, 'refer_mining_l1', l1Bonus, '⛏️ L1 50% refer mining: @' + user.username]);

            // Level 2: L1 ka referrer — 25% of earned
            if (L1.referred_by) {
              const L2 = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [L1.referred_by]);
              if (L2) {
                const l2Bonus = Math.floor(earned * 0.25);
                if (l2Bonus > 0) {
                  await dbRun(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l2Bonus, L2.id]);
                  await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), L2.id, 'refer_mining_l2', l2Bonus, '🌿 L2 25% refer mining: @' + user.username]);

                  // Level 3: L2 ka referrer — 10% of earned
                  if (L2.referred_by) {
                    const L3 = await dbFirst(env, 'SELECT * FROM users WHERE referral_code = ?', [L2.referred_by]);
                    if (L3) {
                      const l3Bonus = Math.floor(earned * 0.10);
                      if (l3Bonus > 0) {
                        await dbRun(env, 'UPDATE users SET points = points + ? WHERE id = ?', [l3Bonus, L3.id]);
                        await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), L3.id, 'refer_mining_l3', l3Bonus, '🔥 L3 10% refer mining: @' + user.username]);
                      }
                    }
                  }
                }
              }
            }
          }
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
      if (task.verify_code && task.verify_code.trim() !== '') return err('This task requires a secret code to complete');
      await dbRun(env, "INSERT INTO user_tasks (id,user_id,task_id,completed_at) VALUES (?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, task_id]);
      await dbRun(env, 'UPDATE users SET points = points + ?, total_tasks_completed = total_tasks_completed + 1 WHERE id = ?', [task.points_reward, user.id]);
      await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, 'task_complete', task.points_reward, '✅ ' + task.title]);
      return json({ success: true, earned: task.points_reward });
    }

    // VERIFY CODE — user visits URL/video to find code, submits here
    if (path === '/api/tasks/verify-code' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id, code } = await request.json();
      if (!task_id || !code) return err('Task ID and code are required');
      const task = await dbFirst(env, 'SELECT * FROM tasks WHERE id = ? AND is_active = 1', [task_id]);
      if (!task) return err('Task not found');
      const already = await dbFirst(env, 'SELECT id FROM user_tasks WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      if (already) return err('Already completed');
      let attempt = await dbFirst(env, 'SELECT * FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
      const maxAttempts = 3;
      const attempts = attempt ? attempt.attempts : 0;
      if (attempt && attempt.failed == 1) return json({ success: false, failed: true, message: 'You have failed. Please restart the task.' });
      const correct = (task.verify_code || '').trim().toLowerCase();
      const given = (code || '').trim().toLowerCase();
      const isCorrect = correct === given;
      if (isCorrect) {
        await dbRun(env, "INSERT INTO user_tasks (id,user_id,task_id,completed_at) VALUES (?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, task_id]);
        await dbRun(env, 'UPDATE users SET points = points + ?, total_tasks_completed = total_tasks_completed + 1 WHERE id = ?', [task.points_reward, user.id]);
        await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, 'task_complete', task.points_reward, '✅ ' + task.title]);
        if (attempt) await dbRun(env, 'DELETE FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
        return json({ success: true, earned: task.points_reward });
      } else {
        const newAttempts = attempts + 1;
        const isFailed = newAttempts >= maxAttempts;
        if (attempt) {
          await dbRun(env, 'UPDATE quiz_attempts SET attempts = ?, failed = ? WHERE user_id = ? AND task_id = ?', [newAttempts, isFailed ? 1 : 0, user.id, task_id]);
        } else {
          await dbRun(env, "INSERT INTO quiz_attempts (id,user_id,task_id,attempts,failed,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, task_id, newAttempts, isFailed ? 1 : 0]);
        }
        const remaining = maxAttempts - newAttempts;
        if (isFailed) return json({ success: false, failed: true, message: 'Wrong code! Failed 3 times. Please restart the task.' });
        return json({ success: false, failed: false, remaining, message: 'Wrong code! ' + remaining + ' attempts remaining.' });
      }
    }

    // VERIFY CODE RESET — restart after failure
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
      if (attempt && attempt.failed == 1) return json({ success: false, failed: true, message: 'You have failed. Please restart the task.' });
      const correct = (task.quiz_answer || '').trim().toLowerCase();
      const given = (answer || '').trim().toLowerCase();
      const isCorrect = correct === given;
      if (isCorrect) {
        await dbRun(env, "INSERT INTO user_tasks (id,user_id,task_id,completed_at) VALUES (?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, task_id]);
        await dbRun(env, 'UPDATE users SET points = points + ?, total_tasks_completed = total_tasks_completed + 1 WHERE id = ?', [task.points_reward, user.id]);
        await dbRun(env, "INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, 'task_complete', task.points_reward, '✅ Quiz: ' + task.title]);
        if (attempt) await dbRun(env, 'DELETE FROM quiz_attempts WHERE user_id = ? AND task_id = ?', [user.id, task_id]);
        return json({ success: true, earned: task.points_reward });
      } else {
        const newAttempts = attempts + 1;
        const isFailed = newAttempts >= maxAttempts;
        if (attempt) {
          await dbRun(env, 'UPDATE quiz_attempts SET attempts = ?, failed = ? WHERE user_id = ? AND task_id = ?', [newAttempts, isFailed ? 1 : 0, user.id, task_id]);
        } else {
          await dbRun(env, "INSERT INTO quiz_attempts (id,user_id,task_id,attempts,failed,created_at) VALUES (?,?,?,?,?,datetime('now'))", [crypto.randomUUID(), user.id, task_id, newAttempts, isFailed ? 1 : 0]);
        }
        const remaining = maxAttempts - newAttempts;
        if (isFailed) return json({ success: false, failed: true, message: 'Wrong answer! Failed 3 times. Please restart the task.' });
        return json({ success: false, failed: false, remaining, message: 'Wrong answer! ' + remaining + ' attempts remaining.' });
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
      const results = await dbAll(env,
        `SELECT u.username, u.wallet_address, u.wallet_type, u.total_mined, u.mining_power,
                (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code) AS total_referrals,
                (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code AND r.total_mined > 0) AS active_referrals
         FROM users u ORDER BY u.total_mined DESC LIMIT 25`
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
      const uc = await dbFirst(env, 'SELECT COUNT(*) as c FROM users');
      const tm = await dbFirst(env, 'SELECT SUM(total_mined) as s FROM users');
      return json({ users: parseInt(uc?.c || 0), total_mined: parseInt(tm?.s || 0) });
    }

    // ── ADS ── Now ads are manual in ads.js, not from DB
    // /api/ads removed — ads directly hardcoded in ads.js

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
        const [uc, tm, tc, mc] = await Promise.all([
          dbFirst(env, 'SELECT COUNT(*) as c FROM users'),
          dbFirst(env, 'SELECT SUM(total_mined) as s FROM users'),
          dbFirst(env, 'SELECT COUNT(*) as c FROM tasks WHERE is_active=1'),
          dbFirst(env, 'SELECT COUNT(*) as c FROM mining_sessions'),
        ]);
        const recent = await dbAll(env, 'SELECT id,username,email,wallet_address,points,total_mined,mining_power,created_at,login_method,is_banned,(SELECT COUNT(*) FROM users r WHERE r.referred_by = u.referral_code AND r.total_mined > 0) AS active_referral_count FROM users u ORDER BY created_at DESC LIMIT 10');
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
        // Create tables that were added in v5 update (run once after deploy)
        await dbRun(env, `CREATE TABLE IF NOT EXISTS password_resets (
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
        )`);
        // Add new columns to existing tables if they don't exist (safe to run multiple times)
        try { await dbRun(env, 'ALTER TABLE users ADD COLUMN security_question TEXT'); } catch(e) {}
        try { await dbRun(env, 'ALTER TABLE users ADD COLUMN security_answer TEXT'); } catch(e) {}
        try { await dbRun(env, 'ALTER TABLE password_resets ADD COLUMN new_password_hash TEXT'); } catch(e) {}
        try { await dbRun(env, 'ALTER TABLE users ADD COLUMN active_referral_count INTEGER DEFAULT 0'); } catch(e) {}
        try { await dbRun(env, 'ALTER TABLE users ADD COLUMN referral_count INTEGER DEFAULT 0'); } catch(e) {}
        await dbRun(env, `CREATE TABLE IF NOT EXISTS support_messages (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          username TEXT,
          email TEXT,
          message TEXT,
          status TEXT DEFAULT 'open',
          admin_reply TEXT,
          replied_at TEXT,
          created_at TEXT
        )`);
        return json({ success: true, message: 'Tables created (or already existed)' });
      }

        return err('Not found', 404);

  } catch (e) {
    return err('Server error: ' + e.message, 500);
  }
}
