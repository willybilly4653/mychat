// API Configuration
const API_URL = window.location.origin;
let socket = null;
let currentUser = null;
let currentChatFriend = null;
let accessToken = null;
let refreshToken = null;
let typingTimeout = null;

// Helper functions
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        left: 50%;
        transform: translateX(-50%);
        background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#f59e0b'};
        color: white;
        padding: 12px 24px;
        border-radius: 12px;
        font-size: 14px;
        z-index: 3000;
        animation: slideUp 0.3s ease;
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2000);
}

async function fetchWithAuth(url, options = {}) {
    if (!accessToken) {
        throw new Error('No access token');
    }

    options.headers = {
        ...options.headers,
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
    };

    let response = await fetch(url, options);
    
    if (response.status === 403) {
        // Try to refresh token
        const refreshed = await refreshAccessToken();
        if (refreshed) {
            options.headers['Authorization'] = `Bearer ${accessToken}`;
            response = await fetch(url, options);
        } else {
            logout();
            throw new Error('Session expired');
        }
    }
    
    return response;
}

async function refreshAccessToken() {
    try {
        const response = await fetch(`${API_URL}/api/refresh-token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken })
        });
        
        if (response.ok) {
            const data = await response.json();
            accessToken = data.accessToken;
            localStorage.setItem('accessToken', accessToken);
            return true;
        }
    } catch (error) {
        console.error('Token refresh failed:', error);
    }
    return false;
}

// Auth functions
async function handleRegister() {
    const username = document.getElementById('regUsername').value.trim();
    const password = document.getElementById('regPassword').value;
    const confirm = document.getElementById('regConfirm').value;
    const errorEl = document.getElementById('regError');

    if (!username || !password) {
        errorEl.textContent = 'Please fill all fields';
        errorEl.classList.add('show');
        return;
    }

    if (password !== confirm) {
        errorEl.textContent = 'Passwords do not match';
        errorEl.classList.add('show');
        return;
    }

    if (password.length < 8) {
        errorEl.textContent = 'Password must be at least 8 characters';
        errorEl.classList.add('show');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/api/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();
        
        if (response.ok) {
            accessToken = data.accessToken;
            refreshToken = data.refreshToken;
            localStorage.setItem('accessToken', accessToken);
            localStorage.setItem('refreshToken', refreshToken);
            currentUser = data.user;
            showToast('Account created successfully!', 'success');
            showApp();
        } else {
            errorEl.textContent = data.error;
            errorEl.classList.add('show');
        }
    } catch (error) {
        errorEl.textContent = 'Server error. Please try again.';
        errorEl.classList.add('show');
    }
}

async function handleLogin() {
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    const errorEl = document.getElementById('loginError');

    if (!username || !password) {
        errorEl.textContent = 'Please enter username and password';
        errorEl.classList.add('show');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();
        
        if (response.ok) {
            accessToken = data.accessToken;
            refreshToken = data.refreshToken;
            localStorage.setItem('accessToken', accessToken);
            localStorage.setItem('refreshToken', refreshToken);
            currentUser = data.user;
            showToast('Logged in successfully!', 'success');
            showApp();
        } else {
            errorEl.textContent = data.error;
            errorEl.classList.add('show');
        }
    } catch (error) {
        errorEl.textContent = 'Server error. Please try again.';
        errorEl.classList.add('show');
    }
}

function showRegister() {
    document.getElementById('authTitle').textContent = 'Create Account';
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('registerForm').style.display = 'block';
}

function showLogin() {
    document.getElementById('authTitle').textContent = 'Welcome Back';
    document.getElementById('registerForm').style.display = 'none';
    document.getElementById('loginForm').style.display = 'block';
}

async function logout() {
    if (accessToken) {
        await fetch(`${API_URL}/api/logout`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${accessToken}` }
        }).catch(() => {});
    }
    
    if (socket) {
        socket.disconnect();
    }
    
    currentUser = null;
    currentChatFriend = null;
    accessToken = null;
    refreshToken = null;
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    
    document.getElementById('authContainer').classList.remove('hidden');
    document.getElementById('appContainer').classList.remove('visible');
    showLogin();
    showToast('Logged out', 'info');
}

// Socket and real-time functions
function initSocket() {
    socket = io(API_URL, {
        transports: ['websocket', 'polling']
    });
    
    socket.on('connect', () => {
        console.log('Socket connected');
        socket.emit('user-online', accessToken);
    });
    
    socket.on('new-message', (message) => {
        if (currentChatFriend && (message.senderId === currentChatFriend.id || message.receiverId === currentChatFriend.id)) {
            loadMessages();
        }
        loadFriends(); // Update unread indicator if needed
    });
    
    socket.on('message-sent', (message) => {
        loadMessages();
    });
    
    socket.on('user-typing', (data) => {
        if (currentChatFriend && data.userId === currentChatFriend.id) {
            const typingStatus = document.getElementById('typingStatus');
            if (data.isTyping) {
                typingStatus.textContent = `${currentChatFriend.username} is typing...`;
            } else {
                typingStatus.textContent = '';
            }
        }
    });
    
    socket.on('friend-added', (data) => {
        showToast(`${data.friendName} added you as a friend!`, 'success');
        loadFriends();
    });
    
    socket.on('friend-status-change', (data) => {
        loadFriends();
        if (currentChatFriend && currentChatFriend.id === data.friendId) {
            const statusEl = document.querySelector('.friend-status');
            if (statusEl) {
                statusEl.textContent = data.online ? 'Online' : 'Offline';
                statusEl.className = `friend-status ${data.online ? 'online' : ''}`;
            }
        }
    });
    
    socket.on('disconnect', () => {
        console.log('Socket disconnected');
    });
}

function handleTyping() {
    if (!socket || !currentChatFriend) return;
    
    socket.emit('typing', {
        receiverId: currentChatFriend.id,
        isTyping: true
    });
    
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => {
        socket.emit('typing', {
            receiverId: currentChatFriend.id,
            isTyping: false
        });
    }, 1000);
}

// Friend functions
let searchTimeout = null;

async function searchUsers() {
    const query = document.getElementById('searchInput').value.trim();
    const resultsDiv = document.getElementById('searchResults');
    
    if (!query) {
        resultsDiv.innerHTML = '';
        return;
    }
    
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(async () => {
        try {
            const response = await fetchWithAuth(`${API_URL}/api/users/search?q=${encodeURIComponent(query)}`);
            const users = await response.json();
            
            resultsDiv.innerHTML = users.map(user => `
                <div class="search-result-item" onclick="addFriendById('${user.id}')">
                    ${escapeHtml(user.username)}
                </div>
            `).join('');
        } catch (error) {
            console.error('Search failed:', error);
        }
    }, 300);
}

async function addFriendById(friendId) {
    try {
        const response = await fetchWithAuth(`${API_URL}/api/friends/add`, {
            method: 'POST',
            body: JSON.stringify({ friendId })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast('Friend added!', 'success');
            document.getElementById('searchInput').value = '';
            document.getElementById('searchResults').innerHTML = '';
            document.getElementById('searchSection').style.display = 'none';
            loadFriends();
        } else {
            showToast(data.error, 'error');
        }
    } catch (error) {
        showToast('Failed to add friend', 'error');
    }
}

async function loadFriends() {
    try {
        const response = await fetchWithAuth(`${API_URL}/api/friends/list`);
        const friends = await response.json();
        
        const friendsList = document.getElementById('friendsList');
        
        if (friends.length === 0) {
            friendsList.innerHTML = '<div style="text-align: center; color: #888; padding: 20px;">No friends yet<br>Add friends to start chatting!</div>';
            return;
        }
        
        friendsList.innerHTML = friends.map(friend => `
            <div class="friend-item ${currentChatFriend && currentChatFriend.id === friend.id ? 'active' : ''}" onclick="selectFriend('${friend.id}', '${escapeHtml(friend.username)}')">
                <div class="friend-avatar">${friend.username.charAt(0).toUpperCase()}</div>
                <div class="friend-info">
                    <div class="friend-name">${escapeHtml(friend.username)}</div>
                    <div class="friend-status ${friend.online ? 'online' : ''}">${friend.online ? 'Online' : 'Offline'}</div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load friends:', error);
    }
}

function toggleSearch() {
    const searchSection = document.getElementById('searchSection');
    searchSection.style.display = searchSection.style.display === 'none' ? 'block' : 'none';
    if (searchSection.style.display === 'block') {
        document.getElementById('searchInput').focus();
    }
}

// Chat functions
async function selectFriend(friendId, friendName) {
    currentChatFriend = { id: friendId, username: friendName };
    document.getElementById('chatWith').textContent = `Chat with ${friendName}`;
    document.getElementById('typingStatus').textContent = '';
    await loadMessages();
    loadFriends();
    document.getElementById('messageInput').focus();
}

async function loadMessages() {
    if (!currentChatFriend) return;
    
    try {
        const response = await fetchWithAuth(`${API_URL}/api/messages/${currentChatFriend.id}`);
        const messages = await response.json();
        
        const container = document.getElementById('messagesContainer');
        
        if (messages.length === 0) {
            container.innerHTML = '<div class="empty-chat">💬 No messages yet<br>Send a message to start the conversation!</div>';
            return;
        }
        
        container.innerHTML = messages.map(msg => `
            <div class="message ${msg.senderId === currentUser.id ? 'sent' : 'received'}">
                <div class="message-bubble">${escapeHtml(msg.text)}</div>
                <div class="message-time">${new Date(msg.timestamp).toLocaleTimeString()}</div>
            </div>
        `).join('');
        
        container.scrollTop = container.scrollHeight;
    } catch (error) {
        console.error('Failed to load messages:', error);
    }
}

function sendMessage() {
    const input = document.getElementById('messageInput');
    const text = input.value.trim();
    
    if (!text || !currentChatFriend || !socket) {
        if (!currentChatFriend) showToast('Select a friend first', 'warning');
        return;
    }
    
    socket.emit('send-message', {
        receiverId: currentChatFriend.id,
        text: text,
        tempId: Date.now().toString()
    });
    
    input.value = '';
    input.style.height = 'auto';
    
    // Clear typing indicator
    clearTimeout(typingTimeout);
    if (typingTimeout) {
        socket.emit('typing', {
            receiverId: currentChatFriend.id,
            isTyping: false
        });
    }
}

function handleKeyPress(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Auto-resize textarea
document.getElementById('messageInput')?.addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 100) + 'px';
});

// App initialization
async function showApp() {
    document.getElementById('authContainer').classList.add('hidden');
    document.getElementById('appContainer').classList.add('visible');
    document.getElementById('currentUsername').textContent = currentUser.username;
    document.getElementById('userAvatar').textContent = currentUser.username.charAt(0).toUpperCase();
    
    await loadFriends();
    initSocket();
}

// Check for existing session
const savedAccessToken = localStorage.getItem('accessToken');
if (savedAccessToken) {
    accessToken = savedAccessToken;
    refreshToken = localStorage.getItem('refreshToken');
    // Verify token by loading friends
    loadFriends().then(() => {
        // If successful, we need to get user info
        currentUser = { id: 'temp', username: 'Loading...' };
        showApp();
        // Actually fetch user info from token or stored data
        setTimeout(() => {
            if (currentUser.id === 'temp') {
                // Couldn't restore session
                logout();
            }
        }, 2000);
    }).catch(() => {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        showLogin();
    });
} else {
    showLogin();
}

// Add CSS animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideUp {
        from {
            opacity: 0;
            transform: translateX(-50%) translateY(20px);
        }
        to {
            opacity: 1;
            transform: translateX(-50%) translateY(0);
        }
    }
`;
document.head.appendChild(style);
