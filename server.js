// ReDeform 远程授权验证服务 - Express.js 版
// 部署目标: Railway / Render / Vercel

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// ========== 配置（通过环境变量设置） ==========
// 环境变量（ Railway 部署时在 Variables 中配置，禁止硬编码）
const CF_ACCOUNT_ID = process.env.CF_ACCOUNT_ID;
const CF_API_TOKEN  = process.env.CF_API_TOKEN;
const KV_NS_ID      = process.env.KV_NS_ID;
const SECRET_KEY    = process.env.SECRET_KEY;

// 启动时校验必要变量
if (!CF_ACCOUNT_ID || !CF_API_TOKEN || !KV_NS_ID || !SECRET_KEY) {
  console.error('缺少必要环境变量: CF_ACCOUNT_ID, CF_API_TOKEN, KV_NS_ID, SECRET_KEY');
  process.exit(1);
}

const KV_BASE = `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/storage/kv/namespaces/${KV_NS_ID}`;

// ========== KV REST API 封装 ==========
async function kvGet(key) {
  const res = await fetch(`${KV_BASE}/values/${encodeURIComponent(key)}`, {
    headers: { 'Authorization': `Bearer ${CF_API_TOKEN}` }
  });
  if (!res.ok) return null;
  const text = await res.text();
  try { return JSON.parse(text); } catch { return text; }
}

async function kvPut(key, value, ttlSeconds) {
  const url = `${KV_BASE}/values/${encodeURIComponent(key)}`;
  const headers = {
    'Authorization': `Bearer ${CF_API_TOKEN}`,
    'Content-Type': 'application/json'
  };
  // Cloudflare KV REST API 用 expiration 参数（Unix 秒）
  if (ttlSeconds) {
    const expiration = Math.floor(Date.now() / 1000) + ttlSeconds;
    // PUT 时通过 query string 传 expiration
    const urlWithExp = `${url}?expiration=${expiration}`;
    const res = await fetch(urlWithExp, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${CF_API_TOKEN}`, 'Content-Type': 'application/json' },
      body: typeof value === 'string' ? value : JSON.stringify(value)
    });
    if (!res.ok) throw new Error(`KV PUT failed: ${await res.text()}`);
  } else {
    const res = await fetch(url, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${CF_API_TOKEN}`, 'Content-Type': 'application/json' },
      body: typeof value === 'string' ? value : JSON.stringify(value)
    });
    if (!res.ok) throw new Error(`KV PUT failed: ${await res.text()}`);
  }
}

async function kvDelete(key) {
  await fetch(`${KV_BASE}/values/${encodeURIComponent(key)}`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${CF_API_TOKEN}` }
  });
}

async function kvList(prefix) {
  const url = `${KV_BASE}/keys?prefix=${encodeURIComponent(prefix)}`;
  const res = await fetch(url, {
    headers: { 'Authorization': `Bearer ${CF_API_TOKEN}` }
  });
  if (!res.ok) return [];
  const data = await res.json();
  return data.result || [];
}

// ========== 工具函数 ==========
function jsonRes(res, data, status = 200) {
  return res.status(status).json(data);
}

async function hashPassword(password) {
  const h = crypto.createHash('sha256');
  h.update(password + SECRET_KEY);
  return h.digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function verifyAdmin(req) {
  const auth = req.headers['authorization'];
  return auth === 'Bearer ' + SECRET_KEY;
}

// ========== 路由 ==========

// 健康检查
app.post('/api/health', (req, res) => {
  jsonRes(res, { ok: true, ts: Date.now() });
});

// 登录
app.post('/api/login', async (req, res) => {
  try {
    const { username, password, device_id, device_name } = req.body;
    if (!username || !password || !device_id) {
      return jsonRes(res, { success: false, error: '参数缺失' }, 400);
    }

    const userData = await kvGet(`users:${username}`);
    if (!userData) return jsonRes(res, { success: false, error: '用户不存在' }, 401);
    if (userData.enabled === false) return jsonRes(res, { success: false, error: '账号已被禁用' }, 403);
    if (userData.expiry && Date.now() > userData.expiry) return jsonRes(res, { success: false, error: '账号已过期' }, 403);

    const passwordHash = await hashPassword(password);
    if (passwordHash !== userData.password_hash) return jsonRes(res, { success: false, error: '密码错误' }, 401);

    // 设备绑定
    if (!userData.devices.includes(device_id)) {
      if (userData.devices.length >= (userData.max_devices || 3)) {
        return jsonRes(res, { success: false, error: `设备数量已达上限 (${userData.max_devices})` }, 403);
      }
      userData.devices.push(device_id);
      await kvPut(`users:${username}`, userData);
    }

    // 设备记录
    let deviceData = await kvGet(`devices:${device_id}`) || {
      username, device_name: device_name || '未知设备',
      total_hours: 0, last_login: Date.now()
    };
    if (userData.max_hours && deviceData.total_hours >= userData.max_hours) {
      return jsonRes(res, { success: false, error: `使用时长已达上限 (${userData.max_hours}小时)` }, 403);
    }
    deviceData.last_login = Date.now();
    await kvPut(`devices:${device_id}`, deviceData);

    // 会话 (24h TTL)
    const sessionToken = generateToken();
    const sessionData = { username, device_id, start_time: Date.now(), last_heartbeat: Date.now() };
    await kvPut(`sessions:${sessionToken}`, sessionData, 86400);

    jsonRes(res, {
      success: true,
      token: sessionToken,
      expiry: userData.expiry,
      max_hours: userData.max_hours,
      used_hours: Math.floor(deviceData.total_hours * 10) / 10
    });
  } catch (e) {
    console.error('/api/login error:', e);
    jsonRes(res, { success: false, error: e.message }, 500);
  }
});

// 心跳
app.post('/api/heartbeat', async (req, res) => {
  try {
    const { token, device_id } = req.body;
    const sessionData = await kvGet(`sessions:${token}`);
    if (!sessionData) return jsonRes(res, { success: false, error: '会话已过期' }, 401);
    if (sessionData.device_id !== device_id) return jsonRes(res, { success: false, error: '设备不匹配' }, 403);

    const userData = await kvGet(`users:${sessionData.username}`);
    if (userData.enabled === false) { await kvDelete(`sessions:${token}`); return jsonRes(res, { success: false, error: '账号已被禁用' }, 403); }
    if (userData.expiry && Date.now() > userData.expiry) { await kvDelete(`sessions:${token}`); return jsonRes(res, { success: false, error: '账号已过期' }, 403); }

    // 累加时长
    const now = Date.now();
    const elapsed = (now - sessionData.last_heartbeat) / 3600000;
    const deviceData = await kvGet(`devices:${device_id}`);
    deviceData.total_hours += elapsed;
    if (userData.max_hours && deviceData.total_hours >= userData.max_hours) {
      await kvDelete(`sessions:${token}`);
      return jsonRes(res, { success: false, error: '使用时长已达上限' }, 403);
    }
    await kvPut(`devices:${device_id}`, deviceData);

    sessionData.last_heartbeat = now;
    await kvPut(`sessions:${token}`, sessionData, 86400);

    jsonRes(res, {
      success: true,
      remaining_hours: userData.max_hours ? Math.floor((userData.max_hours - deviceData.total_hours) * 10) / 10 : null,
      expiry: userData.expiry
    });
  } catch (e) {
    console.error('/api/heartbeat error:', e);
    jsonRes(res, { success: false, error: e.message }, 500);
  }
});

// 登出
app.post('/api/logout', async (req, res) => {
  try {
    const { token } = req.body;
    await kvDelete(`sessions:${token}`);
    jsonRes(res, { success: true });
  } catch (e) {
    jsonRes(res, { success: false, error: e.message }, 500);
  }
});

// 管理：创建用户
app.post('/api/admin/create_user', async (req, res) => {
  if (!verifyAdmin(req)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  try {
    const { username, password, max_devices, max_hours, expiry_days } = req.body;
    const userData = {
      password_hash: await hashPassword(password),
      devices: [],
      max_devices: max_devices || 3,
      max_hours: max_hours || null,
      expiry: expiry_days ? Date.now() + expiry_days * 86400000 : null,
      enabled: true
    };
    await kvPut(`users:${username}`, userData);
    jsonRes(res, { success: true, username });
  } catch (e) {
    jsonRes(res, { error: e.message }, 500);
  }
});

// 管理：列出用户
app.post('/api/admin/list_users', async (req, res) => {
  if (!verifyAdmin(req)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  try {
    const keys = await kvList('users:');
    const users = [];
    for (const k of keys) {
      const data = await kvGet(k.name);
      users.push({
        username: k.name.replace('users:', ''),
        devices: data ? data.devices.length : 0,
        max_devices: data ? data.max_devices : 0,
        max_hours: data ? data.max_hours : null,
        expiry: data ? data.expiry : null,
        enabled: data ? data.enabled : false
      });
    }
    jsonRes(res, { users });
  } catch (e) {
    jsonRes(res, { error: e.message }, 500);
  }
});

// 管理：启用/禁用用户
app.post('/api/admin/toggle_user', async (req, res) => {
  if (!verifyAdmin(req)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  try {
    const { username, enabled } = req.body;
    const userData = await kvGet(`users:${username}`);
    if (!userData) return jsonRes(res, { error: 'User not found' }, 404);
    userData.enabled = enabled;
    await kvPut(`users:${username}`, userData);

    if (!enabled) {
      // 踢掉该用户的所有会话
      const sessions = await kvList('sessions:');
      for (const s of sessions) {
        const sess = await kvGet(s.name);
        if (sess && sess.username === username) await kvDelete(s.name);
      }
    }
    jsonRes(res, { success: true });
  } catch (e) {
    jsonRes(res, { error: e.message }, 500);
  }
});

// 启动
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ReDeform Auth Server running on port ${PORT}`);
});
