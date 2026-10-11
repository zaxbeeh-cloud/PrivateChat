
const express = require('express');
const http = require('http');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json({ limit: '16kb' }));

const dataDir = __dirname;
const usersFile = path.join(dataDir, 'users.json');
const messagesFile = path.join(dataDir, 'messages.json');
const SECRET = process.env.JWT_SECRET;

if (!SECRET || SECRET.length < 32) {
  console.error('Set JWT_SECRET to a secure random value.');
  process.exit(1);
}

function readJSON(file) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, '[]');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), {
    mode: 0o600
  });
}

function tokenFor(user) {
  return jwt.sign({ id: user.id }, SECRET, { expiresIn: '7d' });
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    req.user = jwt.verify(header.replace(/^Bearer /, ''), SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Please sign in' });
  }
}

function publicUser(user) {
  return { id: user.id, email: user.email };
}

function roomFor(a, b) {
  return 'private:' + [a, b].sort().join(':');
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/register', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email' });
  }

  if (password.length < 10 || password.length > 128) {
    return res.status(400).json({
      error: 'Password must be 10 to 128 characters'
    });
  }

  const list = readJSON(usersFile);

  if (list.some(u => u.email === email)) {
    return res.status(409).json({ error: 'Email already registered' });
  }

  const user = {
    id: crypto.randomUUID(),
    email,
    password: await bcrypt.hash(password, 12)
  };

  list.push(user);
  saveJSON(usersFile, list);

  res.status(201).json({
    token: tokenFor(user),
    user: publicUser(user)
  });
});

app.post('/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = readJSON(usersFile).find(u => u.email === email);

  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  res.json({ token: tokenFor(user), user: publicUser(user) });
});

app.get('/me', auth, (req, res) => {
  const user = readJSON(usersFile).find(u => u.id === req.user.id);

  if (!user) return res.status(401).json({ error: 'Account not found' });

  res.json(publicUser(user));
});

app.get('/users', auth, (req, res) => {
  const list = readJSON(usersFile)
    .filter(u => u.id !== req.user.id)
    .map(publicUser);

  res.json(list);
});

app.get('/messages/:userId', auth, (req, res) => {
  const otherId = req.params.userId;
  const list = readJSON(usersFile);

  if (otherId === req.user.id || !list.some(u => u.id === otherId)) {
    return res.status(404).json({ error: 'User not found' });
  }

  const messages = readJSON(messagesFile)
    .filter(m =>
      (m.from === req.user.id && m.to === otherId) ||
      (m.from === otherId && m.to === req.user.id)
    )
    .slice(-200);

  res.json(messages);
});

io.use((socket, next) => {
  try {
    const payload = jwt.verify(socket.handshake.auth?.token, SECRET);
    const exists = readJSON(usersFile).some(u => u.id === payload.id);

    if (!exists) return next(new Error('Unauthorized'));

    socket.userId = payload.id;
    next();
  } catch {
    next(new Error('Unauthorized'));
  }
});

io.on('connection', socket => {
  socket.on('join-private', otherId => {
    if (typeof otherId !== 'string' || otherId === socket.userId) return;

    const exists = readJSON(usersFile).some(u => u.id === otherId);
    if (!exists) return;

    socket.join(roomFor(socket.userId, otherId));
  });

  socket.on('private-message', data => {
    if (!data || typeof data.to !== 'string' ||
        typeof data.text !== 'string') return;

    const text = data.text.trim();
    if (!text || text.length > 2000 || data.to === socket.userId) return;

    const list = readJSON(usersFile);
    if (!list.some(u => u.id === data.to)) return;

    const message = {
      id: crypto.randomUUID(),
      from: socket.userId,
      to: data.to,
      text,
      time: new Date().toISOString()
    };

    const messages = readJSON(messagesFile);
    messages.push(message);
    saveJSON(messagesFile, messages.slice(-10000));

    socket.to(roomFor(socket.userId, data.to))
      .emit('private-message', message);

    socket.emit('message-sent', message);
  });
});

const port = Number(process.env.PORT) || 3000;

server.listen(port, '0.0.0.0', () => {
  console.log(`PrivateChat ready on port ${port}`);
});

