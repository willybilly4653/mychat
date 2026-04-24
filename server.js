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

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const users = new Map();
const messages = new Map();
const refreshTokens = new Set();
const friendRequests = new Map();

const JWT_SECRET = 'your-secret-key-change-this-make-it-very-long-and-random';
const JWT_REFRESH_SECRET = 'your-refresh-secret-key-change-this-too';
const ADMIN_SECRET_KEY = 'your-super-secret-admin-key-only-you-know'; // Change this!

function getChatKey(userId1, userId2) {
  return [userId1, userId2].sort().join('_');
}

function generateTokens(userId, username, role = 'user') {
  const accessToken = jwt.sign({ userId, username, role }, JWT_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ userId, username, role }, JWT_REFRESH_SECRET, { expiresIn: '7d' });
  refreshTokens.add(refreshToken);
  return { accessToken, refreshToken };
}

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

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

function containsProfanity(text) {
  const badWords = ['fuck', 'shit', 'ass', 'bitch', 'damn', 'crap', 'hell', 'dick', 'pussy', 'cock', 'whore', 'slut', 'cunt', 'nigger', 'fag', 'retard'];
  const lowerText = text.toLowerCase();
  return badWords.some(word => lowerText.includes(word));
}

function containsEmoji(text) {
  const emojiRegex = /[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{1F900}-\u{1F9FF}]/u;
  return emojiRegex.test(text);
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/register', async (req, res) => {
  const { username, password, adminKey } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  if (username.length > 20) {
    return res.status(400).json({ error: 'Username must be 20 characters or less' });
  }

  if (username.length < 3) {
    return res.status(400).json({ error: 'Username must be at least 3 characters' });
  }

  if (containsProfanity(username)) {
    return res.status(400).json({ error: 'Username contains inappropriate language' });
  }

  if (containsEmoji(username)) {
    return res.status(400).json({ error: 'Username cannot contain emojis' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

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

  const hashedPassword = await bcrypt.hash(password, 10);
  const userId = Date.now().toString();
  
  let role = 'user';
  if (adminKey && adminKey === ADMIN_SECRET_KEY) {
    role = 'admin';
  }
  
  const newUser = {
    id: userId,
    username,
    passwordHash: hashedPassword,
    friends: [],
    online: false,
    socketId: null,
    role: role,
    createdAt: new Date().toISOString()
  };

  users.set(userId, newUser);
  const { accessToken, refreshToken } = generateTokens(userId, username, role);

  res.status(201).json({
    message: 'User created successfully',
    user: { id: userId, username, friends: [], role: role },
    accessToken,
    refreshToken
  });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

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

  const { accessToken, refreshToken } = generateTokens(foundUser.id, foundUser.username, foundUser.role);

  res.json({
    message: 'Logged in successfully',
    user: { id: foundUser.id, username: foundUser.username, friends: foundUser.friends, role: foundUser.role },
    accessToken,
    refreshToken
  });
});

app.get('/api/user', authenticateToken, (req, res) => {
  const user = users.get(req.user.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({ id: user.id, username: user.username, friends: user.friends, role: user.role });
});

app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
  const allUsers = [];
  for (let user of users.values()) {
    allUsers.push({
      id: user.id,
      username: user.username,
      role: user.role,
      online: user.online,
      friendsCount: user.friends.length,
      createdAt: user.createdAt
    });
  }
  res.json(allUsers);
});

app.delete('/api/admin/users/:userId', authenticateToken, requireAdmin, (req, res) => {
  const { userId } = req.params;
  const userToDelete = users.get(userId);
  
  if (!userToDelete) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  users.delete(userId);
  res.json({ message: `User ${userToDelete.username} has been deleted` });
});

app.post('/api/admin/make-admin/:userId', authenticateToken, requireAdmin, (req, res) => {
  const { userId } = req.params;
  const user = users.get(userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  user.role = 'admin';
  users.set(userId, user);
  res.json({ message: `${user.username} is now an admin` });
});

app.get('/api/admin/stats', authenticateToken, requireAdmin, (req, res) => {
  let totalMessages = 0;
  for (let chatMessages of messages.values()) {
    totalMessages += chatMessages.length;
  }
  
  res.json({
    totalUsers: users.size,
    totalMessages: totalMessages,
    onlineUsers: Array.from(users.values()).filter(u => u.online).length,
    totalFriendRequests: friendRequests.size
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

    const newAccessToken = jwt.sign({ userId: user.userId, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '15m' });
    res.json({ accessToken: newAccessToken });
  });
});

app.post('/api/logout', authenticateToken, (req, res) => {
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
      if (!user.friends.includes(req.user.userId)) {
        const existingRequest = friendRequests.get(user.id);
        const hasPending = existingRequest && existingRequest.some(r => r.fromId === req.user.userId || r.toId === req.user.userId);
        if (!hasPending) {
          results.push({ id: user.id, username: user.username });
        }
      }
      if (results.length >= 10) break;
    }
  }
  res.json(results);
});

app.post('/api/friends/request', authenticateToken, (req, res) => {
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

  if (!friendRequests.has(friendId)) {
    friendRequests.set(friendId, []);
  }

  const existingRequests = friendRequests.get(friendId);
  const requestExists = existingRequests.some(r => r.fromId === userId);
  
  if (requestExists) {
    return res.status(400).json({ error: 'Friend request already sent' });
  }

  existingRequests.push({
    fromId: userId,
    fromUsername: user.username,
    toId: friendId,
    timestamp: new Date().toISOString()
  });

  friendRequests.set(friendId, existingRequests);

  if (friend.socketId) {
    io.to(friend.socketId).emit('friend-request', {
      fromId: userId,
      fromUsername: user.username
    });
  }

  res.json({ message: 'Friend request sent' });
});

app.get('/api/friends/requests', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const requests = friendRequests.get(userId) || [];
  res.json(requests.map(r => ({
    fromId: r.fromId,
    fromUsername: r.fromUsername
  })));
});

app.post('/api/friends/accept', authenticateToken, (req, res) => {
  const { friendId } = req.body;
  const userId = req.user.userId;

  const user = users.get(userId);
  const friend = users.get(friendId);

  if (!friend) {
    return res.status(404).json({ error: 'User not found' });
  }

  const requests = friendRequests.get(userId) || [];
  const requestIndex = requests.findIndex(r => r.fromId === friendId);
  
  if (requestIndex === -1) {
    return res.status(400).json({ error: 'No friend request found' });
  }

  requests.splice(requestIndex, 1);
  friendRequests.set(userId, requests);

  if (!user.friends.includes(friendId)) {
    user.friends.push(friendId);
  }
  if (!friend.friends.includes(userId)) {
    friend.friends.push(userId);
  }

  users.set(userId, user);
  users.set(friendId, friend);

  if (friend.socketId) {
    io.to(friend.socketId).emit('friend-request-accepted', {
      fromId: userId,
      fromUsername: user.username
    });
  }

  res.json({ message: 'Friend request accepted' });
});

app.post('/api/friends/decline', authenticateToken, (req, res) => {
  const { friendId } = req.body;
  const userId = req.user.userId;

  const requests = friendRequests.get(userId) || [];
  const requestIndex = requests.findIndex(r => r.fromId === friendId);
  
  if (requestIndex !== -1) {
    requests.splice(requestIndex, 1);
    friendRequests.set(userId, requests);
  }

  res.json({ message: 'Friend request declined' });
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

    if (containsEmoji(text)) {
      socket.emit('message-blocked', { message: 'Emojis are not allowed in messages' });
      return;
    }

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

    const receiver = users.get(receiverId);
    if (receiver && receiver.socketId) {
      io.to(receiver.socketId).emit('new-message', message);
    }

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

  socket.on('friend-request-accepted', (data) => {
    const { friendId } = data;
    const userId = socket.userId;
    const user = users.get(userId);
    const friend = users.get(friendId);
    
    if (friend && friend.socketId) {
      io.to(friend.socketId).emit('friend-request-accepted', {
        fromId: userId,
        fromUsername: user.username
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
  console.log(`Admin secret key is: ${ADMIN_SECRET_KEY}`);
  console.log(`To create an admin account, register with adminKey: ${ADMIN_SECRET_KEY}`);
});
