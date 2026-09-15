const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'users.json');

app.use(cors({ origin: true, methods: ['GET', 'POST', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type'] }));
app.use(express.json());

function readDB() {
  try {
    if (!fs.existsSync(DB_FILE)) return {};
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    return data && typeof data === 'object' ? data : {};
  } catch (err) {
    console.error('Database read error:', err.message);
    return {};
  }
}

function writeDB(data) {
  const tmp = `${DB_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

function makeSessionId() {
  return `sess_${Math.random().toString(36).slice(2)}_${Date.now()}`;
}

async function seedDefaultUsers() {
  const db = readDB();
  let changed = false;

  const defaults = {
    uk0wme: { password: 'ilobyou', days: 300, role: 'admin' },
    ankit: { password: 'gupta', days: 30, role: 'user' },
    rajj: { password: 'rajj', days: 28, role: 'user' },
    john: { password: 'john7698', days: 28, role: 'user' }
  };

  for (const [username, cfg] of Object.entries(defaults)) {
    if (!db[username]) {
      db[username] = {
        password: await bcrypt.hash(cfg.password, 10),
        expiresAt: Date.now() + cfg.days * 24 * 60 * 60 * 1000,
        activeSession: '',
        role: cfg.role
      };
      changed = true;
    } else if (!db[username].role) {
      db[username].role = cfg.role;
      changed = true;
    }
  }

  if (changed) writeDB(db);
}

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'my-json-auth-server', endpoints: ['/login', '/verify-session', '/register', '/users'] });
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.get('/users', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json(readDB());
});

app.post('/register', async (req, res) => {
  try {
    const { username, password, duration, unit } = req.body || {};
    const cleanUsername = String(username || '').trim();
    if (!cleanUsername || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    if (cleanUsername.toLowerCase() === 'uk0wme') {
      return res.status(409).json({ error: 'Username already exists' });
    }

    const db = readDB();
    if (db[cleanUsername]) return res.status(409).json({ error: 'Username already exists' });

    const dur = Number(duration);
    let ms = 24 * 60 * 60 * 1000;
    if (Number.isFinite(dur) && dur > 0) {
      if (unit === 'minutes') ms = dur * 60 * 1000;
      else if (unit === 'hours') ms = dur * 60 * 60 * 1000;
      else ms = dur * 24 * 60 * 60 * 1000;
    }

    db[cleanUsername] = {
      password: await bcrypt.hash(String(password), 10),
      expiresAt: Date.now() + ms,
      activeSession: '',
      role: 'user'
    };
    writeDB(db);
    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/users/:username', (req, res) => {
  const username = decodeURIComponent(req.params.username);
  if (username.toLowerCase() === 'uk0wme') {
    return res.status(400).json({ error: 'Admin account cannot be deleted' });
  }
  const db = readDB();
  if (!db[username]) return res.status(404).json({ error: 'User not found' });
  delete db[username];
  writeDB(db);
  res.json({ message: 'User deleted successfully' });
});

app.post('/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    const db = readDB();
    const user = db[username];

    if (!user) return res.status(400).json({ error: 'Invalid username or password' });

    const valid = user.password && user.password.startsWith('$2')
      ? await bcrypt.compare(password, user.password)
      : password === user.password;
    if (!valid) return res.status(400).json({ error: 'Invalid username or password' });

    if (Number(user.expiresAt) <= Date.now()) {
      return res.status(400).json({ error: 'This account has expired. Contact administrator.' });
    }

    const sessionId = makeSessionId();
    user.activeSession = sessionId;
    writeDB(db);

    res.json({ message: 'Login successful', sessionId, expiresAt: user.expiresAt });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/verify-session', (req, res) => {
  const username = String(req.body?.username || '').trim();
  const sessionId = String(req.body?.sessionId || '');
  const db = readDB();
  const user = db[username];

  if (!user || !sessionId || user.activeSession !== sessionId) {
    return res.status(401).json({ error: 'Logged out: Account logged in on another device.' });
  }
  if (Number(user.expiresAt) <= Date.now()) {
    return res.status(401).json({ error: 'Access expired.' });
  }
  res.json({ status: 'active' });
});

app.post('/logout', (req, res) => {
  const username = String(req.body?.username || '').trim();
  const sessionId = String(req.body?.sessionId || '');
  const db = readDB();
  if (db[username] && db[username].activeSession === sessionId) {
    db[username].activeSession = '';
    writeDB(db);
  }
  res.json({ message: 'Logged out' });
});

seedDefaultUsers().catch(err => console.error('Seed error:', err));

app.listen(PORT, () => console.log(`Auth server running on port ${PORT}`));
