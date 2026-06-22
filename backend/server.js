const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3003;
const DB_PATH = path.join(__dirname, 'teahouse.db');

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, '../')));

// ==================== Database Setup ====================
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    phone TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nickname TEXT NOT NULL,
    avatar TEXT DEFAULT '',
    bio TEXT DEFAULT '',
    role TEXT DEFAULT 'user' CHECK(role IN ('user','admin')),
    status TEXT DEFAULT 'active' CHECK(status IN ('active','banned','deactivated')),
    join_time INTEGER NOT NULL,
    last_active INTEGER NOT NULL,
    posts_count INTEGER DEFAULT 0,
    followers TEXT DEFAULT '[]',
    following TEXT DEFAULT '[]',
    liked_posts TEXT DEFAULT '[]',
    favorited_posts TEXT DEFAULT '[]',
    registered_phones TEXT DEFAULT '[]'
  );

  CREATE TABLE IF NOT EXISTS posts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT DEFAULT '',
    content TEXT NOT NULL,
    topic TEXT DEFAULT 'acg',
    media TEXT DEFAULT '[]',
    likes TEXT DEFAULT '[]',
    favorites TEXT DEFAULT '[]',
    pinned INTEGER DEFAULT 0,
    pinned_by TEXT,
    created_at INTEGER NOT NULL,
    views INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY,
    post_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    content TEXT NOT NULL,
    time INTEGER NOT NULL,
    FOREIGN KEY (post_id) REFERENCES posts(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS group_messages (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    content TEXT NOT NULL,
    time INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS private_messages (
    id TEXT PRIMARY KEY,
    sender_id TEXT NOT NULL,
    receiver_id TEXT NOT NULL,
    content TEXT NOT NULL,
    time INTEGER NOT NULL,
    is_read INTEGER DEFAULT 0,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

// Ensure default admin key
const adminKey = db.prepare('SELECT value FROM settings WHERE key = ?').get('admin_key');
if (!adminKey) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run('admin_key', 'admin888');
}

// Seed default admin user
const existingAdmin = db.prepare('SELECT id FROM users WHERE role = ?').get('admin');
if (!existingAdmin) {
  db.prepare(`INSERT INTO users (id, phone, password, nickname, bio, role, join_time, last_active)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
    'admin_001', 'admin', 'Hty070818', '管理员', '二次元茶话会管理员 🛡️', 'admin', Date.now(), Date.now()
  );
}

// ==================== Helpers ====================
function genId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 6);
}

function genToken() {
  return crypto.randomBytes(32).toString('hex');
}

function parseJSON(str, def) {
  try { return JSON.parse(str); } catch(e) { return def || []; }
}

function authenticate(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token) return res.status(401).json({ error: '未登录' });
  
  const session = db.prepare('SELECT user_id FROM sessions WHERE token = ?').get(token);
  if (!session) return res.status(401).json({ error: '登录已过期' });
  
  req.userId = session.user_id;
  next();
}

function adminAuth(req, res, next) {
  authenticate(req, res, () => {
    const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.userId);
    if (!user || user.role !== 'admin') return res.status(403).json({ error: '需要管理员权限' });
    next();
  });
}

function sanitizeUser(user) {
  if (!user) return null;
  const { password, ...safe } = user;
  return safe;
}

// ==================== Auth Routes ====================
app.post('/api/register', (req, res) => {
  const { phone, password, nickname } = req.body;
  if (!phone || !password || !nickname) return res.status(400).json({ error: '请填写所有必填字段' });
  if (password.length < 6) return res.status(400).json({ error: '密码至少6位' });
  
  const existing = db.prepare('SELECT id FROM users WHERE phone = ?').get(phone);
  if (existing) return res.status(400).json({ error: '该手机号已被注册' });
  
  const id = genId();
  const now = Date.now();
  db.prepare(`INSERT INTO users (id, phone, password, nickname, bio, role, status, join_time, last_active)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, phone, password, nickname, '', 'user', 'active', now, now);
  
  const token = genToken();
  db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)').run(token, id, now);
  
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  res.json({ token, user: sanitizeUser(user) });
});

app.post('/api/login', (req, res) => {
  const { phone, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE phone = ? AND password = ?').get(phone, password);
  if (!user) return res.status(401).json({ error: '手机号或密码错误' });
  if (user.status === 'banned') return res.status(403).json({ error: '账号已被封禁' });
  if (user.status === 'deactivated') return res.status(403).json({ error: '账号已注销' });
  
  db.prepare('UPDATE users SET last_active = ? WHERE id = ?').run(Date.now(), user.id);
  const token = genToken();
  db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)').run(token, user.id, Date.now());
  
  res.json({ token, user: sanitizeUser(user) });
});

app.post('/api/admin/login', (req, res) => {
  const { key, phone } = req.body;
  const storedKey = db.prepare('SELECT value FROM settings WHERE key = ?').get('admin_key');
  if (!storedKey || storedKey.value !== key) return res.status(401).json({ error: '管理员密钥错误' });
  
  let admin;
  if (phone) {
    admin = db.prepare('SELECT * FROM users WHERE phone = ? AND role = ?').get(phone, 'admin');
  }
  if (!admin) {
    admin = db.prepare('SELECT * FROM users WHERE role = ?').get('admin');
  }
  if (!admin) return res.status(404).json({ error: '未找到管理员账号' });
  
  db.prepare('UPDATE users SET last_active = ? WHERE id = ?').run(Date.now(), admin.id);
  const token = genToken();
  db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)').run(token, admin.id, Date.now());
  
  res.json({ token, user: sanitizeUser(admin) });
});

// ==================== Data Load Routes ====================
app.get('/api/load', authenticate, (req, res) => {
  const users = db.prepare('SELECT * FROM users').all().map(sanitizeUser);
  const posts = db.prepare('SELECT * FROM posts').all().map(p => ({
    ...p, media: parseJSON(p.media), likes: parseJSON(p.likes), favorites: parseJSON(p.favorites),
    pinned: !!p.pinned
  }));
  const comments = db.prepare('SELECT * FROM comments').all();
  const groupMessages = db.prepare('SELECT * FROM group_messages ORDER BY time ASC').all();
  const privateMessages = db.prepare('SELECT * FROM private_messages ORDER BY time ASC').all();
  
  // Attach comments to posts
  posts.forEach(p => {
    p.comments = comments.filter(c => c.post_id === p.id);
  });
  
  const adminKey = db.prepare('SELECT value FROM settings WHERE key = ?').get('admin_key');
  
  res.json({
    users,
    posts,
    groupMessages,
    privateMessages,
    adminKey: adminKey?.value || 'admin888',
    registeredPhones: users.map(u => u.phone)
  });
});

app.post('/api/save', authenticate, (req, res) => {
  const { posts: incomingPosts, groupMessages, privateMessages, adminKey: newAdminKey } = req.body;
  
  const txn = db.transaction(() => {
    // Save posts
    if (incomingPosts) {
      const existingIds = new Set(db.prepare('SELECT id FROM posts').all().map(r => r.id));
      const insertPost = db.prepare(`INSERT OR REPLACE INTO posts (id, user_id, title, content, topic, media, likes, favorites, pinned, pinned_by, created_at, views)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      
      incomingPosts.forEach(p => {
        insertPost.run(
          p.id, p.userId, p.title || '', p.content, p.topic || 'acg',
          JSON.stringify(p.media || []), JSON.stringify(p.likes || []), JSON.stringify(p.favorites || []),
          p.pinned ? 1 : 0, p.pinnedBy || null, p.createdAt || Date.now(), p.views || 0
        );
        
        // Update users post count
        db.prepare('UPDATE users SET posts_count = (SELECT COUNT(*) FROM posts WHERE user_id = ?) WHERE id = ?')
          .run(p.userId, p.userId);
      });
      
      // Save comments
      const commentStmt = db.prepare('INSERT OR REPLACE INTO comments (id, post_id, user_id, content, time) VALUES (?, ?, ?, ?, ?)');
      incomingPosts.forEach(p => {
        if (p.comments) {
          p.comments.forEach(c => {
            commentStmt.run(c.id || genId(), p.id, c.userId, c.content, c.time || Date.now());
          });
        }
      });
    }
    
    // Save group messages
    if (groupMessages) {
      const gmStmt = db.prepare('INSERT OR REPLACE INTO group_messages (id, user_id, content, time) VALUES (?, ?, ?, ?)');
      groupMessages.forEach(m => {
        gmStmt.run(m.id, m.userId, m.content, m.time || Date.now());
      });
    }
    
    // Save private messages
    if (privateMessages) {
      const pmStmt = db.prepare('INSERT OR REPLACE INTO private_messages (id, sender_id, receiver_id, content, time, is_read) VALUES (?, ?, ?, ?, ?, ?)');
      privateMessages.forEach(m => {
        pmStmt.run(m.id, m.from, m.to, m.content, m.time || Date.now(), m.read ? 1 : 0);
      });
    }
    
    // Save admin key
    if (newAdminKey) {
      db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run('admin_key', newAdminKey);
    }
  });
  
  try {
    txn();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: '保存失败: ' + e.message });
  }
});

// ==================== Individual API Routes ====================

// Create post
app.post('/api/posts', authenticate, (req, res) => {
  const { title, content, topic, media } = req.body;
  const post = {
    id: genId(), userId: req.userId, title: title || '', content,
    topic: topic || 'acg', media: media || [],
    likes: [], favorites: [], pinned: false, pinnedBy: null,
    createdAt: Date.now(), views: 0
  };
  
  db.prepare('INSERT INTO posts (id, user_id, title, content, topic, media, created_at) VALUES (?,?,?,?,?,?,?)')
    .run(post.id, post.userId, post.title, post.content, post.topic, JSON.stringify(post.media), post.createdAt);
  db.prepare('UPDATE users SET posts_count = posts_count + 1 WHERE id = ?').run(req.userId);
  
  res.json({ success: true, post });
  broadcastData();
});

// Toggle like
app.post('/api/posts/:id/like', authenticate, (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).json({ error: '帖子不存在' });
  let likes = parseJSON(post.likes);
  const idx = likes.indexOf(req.userId);
  if (idx > -1) likes.splice(idx, 1);
  else likes.push(req.userId);
  db.prepare('UPDATE posts SET likes = ? WHERE id = ?').run(JSON.stringify(likes), req.params.id);
  res.json({ success: true });
});

// Toggle favorite
app.post('/api/posts/:id/favorite', authenticate, (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).json({ error: '帖子不存在' });
  let favorites = parseJSON(post.favorites);
  const idx = favorites.indexOf(req.userId);
  if (idx > -1) favorites.splice(idx, 1);
  else favorites.push(req.userId);
  db.prepare('UPDATE posts SET favorites = ? WHERE id = ?').run(JSON.stringify(favorites), req.params.id);
  res.json({ success: true });
});

// Add comment
app.post('/api/posts/:id/comment', authenticate, (req, res) => {
  const { content } = req.body;
  const comment = { id: genId(), postId: req.params.id, userId: req.userId, content, time: Date.now() };
  db.prepare('INSERT INTO comments (id, post_id, user_id, content, time) VALUES (?,?,?,?,?)')
    .run(comment.id, comment.postId, comment.userId, comment.content, comment.time);
  db.prepare('UPDATE posts SET views = views + 1 WHERE id = ?').run(req.params.id);
  res.json({ success: true, comment });
});

// Get user by ID
app.get('/api/users/:id', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: '用户不存在' });
  res.json(sanitizeUser(user));
});

// Toggle follow
app.post('/api/users/:id/follow', authenticate, (req, res) => {
  if (req.userId === req.params.id) return res.status(400).json({ error: '不能关注自己' });
  
  const me = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: '用户不存在' });
  
  let following = parseJSON(me.following);
  let followers = parseJSON(target.followers);
  
  const idx = following.indexOf(req.params.id);
  if (idx > -1) {
    following.splice(idx, 1);
    followers = followers.filter(id => id !== req.userId);
  } else {
    following.push(req.params.id);
    if (!followers.includes(req.userId)) followers.push(req.userId);
  }
  
  db.prepare('UPDATE users SET following = ? WHERE id = ?').run(JSON.stringify(following), req.userId);
  db.prepare('UPDATE users SET followers = ? WHERE id = ?').run(JSON.stringify(followers), req.params.id);
  
  res.json({ success: true, isFollowing: idx === -1 });
});

// Update own profile
app.put('/api/users/me', authenticate, (req, res) => {
  const { nickname, bio, avatar } = req.body;
  if (nickname) db.prepare('UPDATE users SET nickname = ?, bio = ?, avatar = ? WHERE id = ?').run(nickname, bio || '', avatar || '', req.userId);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  res.json({ success: true, user: sanitizeUser(user) });
});

// Group chat
app.get('/api/chat/group', (req, res) => {
  const msgs = db.prepare('SELECT * FROM group_messages ORDER BY time ASC LIMIT 200').all();
  res.json(msgs);
});

app.post('/api/chat/group', authenticate, (req, res) => {
  const { content } = req.body;
  const msg = { id: genId(), userId: req.userId, content, time: Date.now() };
  db.prepare('INSERT INTO group_messages (id, user_id, content, time) VALUES (?,?,?,?)')
    .run(msg.id, msg.userId, msg.content, msg.time);
  res.json({ success: true, message: msg });
});

// Private chat
app.get('/api/chat/private/:userId', authenticate, (req, res) => {
  const msgs = db.prepare(`SELECT * FROM private_messages 
    WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
    ORDER BY time ASC LIMIT 200`).all(req.userId, req.params.userId, req.params.userId, req.userId);
  
  // Mark as read
  db.prepare('UPDATE private_messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ?')
    .run(req.params.userId, req.userId);
  
  res.json(msgs.map(m => ({ ...m, from: m.sender_id, to: m.receiver_id, read: !!m.is_read })));
});

app.post('/api/chat/private', authenticate, (req, res) => {
  const { to, content } = req.body;
  const msg = { id: genId(), from: req.userId, to, content, time: Date.now(), read: false };
  db.prepare('INSERT INTO private_messages (id, sender_id, receiver_id, content, time) VALUES (?,?,?,?,?)')
    .run(msg.id, msg.from, msg.to, msg.content, msg.time);
  res.json({ success: true, message: msg });
});

// ==================== Admin Routes ====================
app.get('/api/admin/users', adminAuth, (req, res) => {
  const users = db.prepare('SELECT * FROM users').all().map(sanitizeUser);
  res.json(users);
});

app.post('/api/admin/users/:id/ban', adminAuth, (req, res) => {
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run('banned', req.params.id);
  res.json({ success: true });
});

app.post('/api/admin/users/:id/unban', adminAuth, (req, res) => {
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run('active', req.params.id);
  res.json({ success: true });
});

app.post('/api/admin/users/:id/delete', adminAuth, (req, res) => {
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run('deactivated', req.params.id);
  res.json({ success: true });
});

app.put('/api/admin/users/:id', adminAuth, (req, res) => {
  const { nickname, password } = req.body;
  if (nickname) db.prepare('UPDATE users SET nickname = ? WHERE id = ?').run(nickname, req.params.id);
  if (password) db.prepare('UPDATE users SET password = ? WHERE id = ?').run(password, req.params.id);
  res.json({ success: true });
});

app.get('/api/admin/posts', adminAuth, (req, res) => {
  const posts = db.prepare('SELECT * FROM posts ORDER BY created_at DESC').all().map(p => ({
    ...p, media: parseJSON(p.media), likes: parseJSON(p.likes), favorites: parseJSON(p.favorites),
    pinned: !!p.pinned
  }));
  res.json(posts);
});

app.delete('/api/admin/posts/:id', adminAuth, (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (post) {
    db.prepare('DELETE FROM comments WHERE post_id = ?').run(req.params.id);
    db.prepare('DELETE FROM posts WHERE id = ?').run(req.params.id);
    if (post.user_id) db.prepare('UPDATE users SET posts_count = MAX(0, posts_count - 1) WHERE id = ?').run(post.user_id);
  }
  res.json({ success: true });
});

app.post('/api/admin/posts/:id/pin', adminAuth, (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).json({ error: '帖子不存在' });
  const pinned = !post.pinned;
  db.prepare('UPDATE posts SET pinned = ?, pinned_by = ? WHERE id = ?').run(pinned ? 1 : 0, pinned ? req.userId : null, req.params.id);
  res.json({ success: true, pinned });
});

// ==================== SSE for real-time updates ====================
const clients = [];

app.get('/api/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });
  
  const clientId = Date.now();
  const client = { id: clientId, res };
  clients.push(client);
  
  req.on('close', () => {
    const idx = clients.indexOf(client);
    if (idx > -1) clients.splice(idx, 1);
  });
});

function broadcastData() {
  const data = JSON.stringify({ refresh: true });
  clients.forEach(c => {
    c.res.write(`data: ${data}\n\n`);
  });
}

// ==================== Start Server ====================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🍵 二次元茶话会 后端服务已启动!`);
  console.log(`   API: http://localhost:${PORT}/api`);
  console.log(`   前端: http://localhost:${PORT}/`);
});
