const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// In-memory storage (use database like MongoDB in production)
const users = new Map(); // userId -> { id, username, passwordHash, friends, online, socketId }
const messages = new Map(); // chatKey -> array of messages
const refreshTokens = new Set();

// Secret keys (store in .env in production)
const JWT_SECRET = 'your-secret-key-change-this';
const JWT_REFRESH_SECRET = 'your-refresh-secret-key-change-this';

// Helper functions
function getChatKey(userId1, userId2) {
  return [userId1, userId2].sort().join('_');
}

// Generate tokens
function generateTokens(userId, username) {
  const accessToken = jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ userId, username }, JWT_REFRESH_SECRET, { expiresIn: '7d' });
  refreshTokens.add(refreshToken);
  return { accessToken, refreshToken };
}

// Middleware to verify token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Routes
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  // Check if username exists
  let usernameExists = false;
  for (let user of users.values()) {
    if (user.username.toLowerCase() === username.toLowerCase()) {
      usernameExists = true;
      break;
    }
  }

  if (usernameExists) {
    return res.status(400).json({ error: 'Username already taken' });
  }

  // Hash password and create user
  const hashedPassword = await bcrypt.hash(password, 10);
  const userId = Date.now().toString();
  const newUser = {
    id: userId,
    username,
    passwordHash: hashedPassword,
    friends: [],
    online: false,
    socketId: null,
    createdAt: new Date().toISOString()
  };

  users.set(userId, newUser);
  const { accessToken, refreshToken } = generateTokens(userId, username);

  res.status(201).json({
    message: 'User created successfully',
    user: { id: userId, username, friends: [] },
    accessToken,
    refreshToken
  });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  // Find user
  let foundUser = null;
  for (let user of users.values()) {
    if (user.username.toLowerCase() === username.toLowerCase()) {
      foundUser = user;
      break;
    }
  }

  if (!foundUser) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const validPassword = await bcrypt.compare(password, foundUser.passwordHash);
  if (!validPassword) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const { accessToken, refreshToken } = generateTokens(foundUser.id, foundUser.username);

  res.json({
    message: 'Logged in successfully',
    user: { id: foundUser.id, username: foundUser.username, friends: foundUser.friends },
    accessToken,
    refreshToken
  });
});

app.post('/api/refresh-token', (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken || !refreshTokens.has(refreshToken)) {
    return res.status(403).json({ error: 'Invalid refresh token' });
  }

  jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }

    const newAccessToken = jwt.sign({ userId: user.userId, username: user.username }, JWT_SECRET, { expiresIn: '15m' });
    res.json({ accessToken: newAccessToken });
  });
});

app.post('/api/logout', authenticateToken, (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token) {
    // In a real app, add token to blacklist
  }
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/users/search', authenticateToken, (req, res) => {
  const { q } = req.query;
  if (!q) {
    return res.json([]);
  }

  const results = [];
  for (let user of users.values()) {
    if (user.username.toLowerCase().includes(q.toLowerCase()) && user.id !== req.user.userId) {
      results.push({ id: user.id, username: user.username });
      if (results.length >= 10) break;
    }
  }
  res.json(results);
});

app.post('/api/friends/add', authenticateToken, (req, res) => {
  const { friendId } = req.body;
  const userId = req.user.userId;

  const user = users.get(userId);
  const friend = users.get(friendId);

  if (!friend) {
    return res.status(404).json({ error: 'User not found' });
  }

  if (user.friends.includes(friendId)) {
    return res.status(400).json({ error: 'Already friends' });
  }

  user.friends.push(friendId);
  friend.friends.push(userId);

  users.set(userId, user);
  users.set(friendId, friend);

  // Notify friend if online
  if (friend.socketId) {
    io.to(friend.socketId).emit('friend-added', { friendId: userId, friendName: user.username });
  }

  res.json({ message: 'Friend added successfully', friends: user.friends });
});

app.get('/api/friends/list', authenticateToken, (req, res) => {
  const user = users.get(req.user.userId);
  const friendsList = user.friends.map(friendId => {
    const friend = users.get(friendId);
    return {
      id: friend.id,
      username: friend.username,
      online: friend.online
    };
  });
  res.json(friendsList);
});

app.get('/api/messages/:friendId', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const { friendId } = req.params;
  const chatKey = getChatKey(userId, friendId);
  const chatMessages = messages.get(chatKey) || [];
  res.json(chatMessages);
});

// Socket.IO for real-time messaging
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('user-online', async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = users.get(decoded.userId);
      
      if (user) {
        user.online = true;
        user.socketId = socket.id;
        users.set(decoded.userId, user);
        socket.userId = decoded.userId;

        // Notify friends that user is online
        user.friends.forEach(friendId => {
          const friend = users.get(friendId);
          if (friend && friend.socketId) {
            io.to(friend.socketId).emit('friend-status-change', {
              friendId: user.id,
              online: true
            });
          }
        });

        socket.emit('online-status', { online: true });
      }
    } catch (err) {
      console.error('Invalid token:', err);
    }
  });

  socket.on('send-message', async (data) => {
    const { receiverId, text, tempId } = data;
    const senderId = socket.userId;

    if (!senderId || !receiverId || !text) return;

    const message = {
      id: Date.now().toString(),
      senderId,
      receiverId,
      text,
      timestamp: new Date().toISOString(),
      tempId
    };

    const chatKey = getChatKey(senderId, receiverId);
    if (!messages.has(chatKey)) {
      messages.set(chatKey, []);
    }
    messages.get(chatKey).push(message);

    // Send to receiver if online
    const receiver = users.get(receiverId);
    if (receiver && receiver.socketId) {
      io.to(receiver.socketId).emit('new-message', message);
    }

    // Confirm to sender
    socket.emit('message-sent', message);
  });

  socket.on('typing', (data) => {
    const { receiverId, isTyping } = data;
    const senderId = socket.userId;
    
    const receiver = users.get(receiverId);
    if (receiver && receiver.socketId) {
      io.to(receiver.socketId).emit('user-typing', {
        userId: senderId,
        isTyping
      });
    }
  });

  socket.on('disconnect', () => {
    if (socket.userId) {
      const user = users.get(socket.userId);
      if (user) {
        user.online = false;
        user.socketId = null;
        users.set(socket.userId, user);

        // Notify friends
        user.friends.forEach(friendId => {
          const friend = users.get(friendId);
          if (friend && friend.socketId) {
            io.to(friend.socketId).emit('friend-status-change', {
              friendId: user.id,
              online: false
            });
          }
        });
      }
    }
    console.log('User disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
