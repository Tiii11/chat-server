// chat-server/server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors'); // Ensure 'cors' is installed (npm install cors)
const http = require('http');
const { Server } = require("socket.io");
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models/User'); // Ensure models/User.js exists

const app = express();
const server = http.createServer(app);

// --- Socket.IO Server Initialization ---
// CORS config specifically for Socket.IO connections
const io = new Server(server, {
    cors: {
        origin: "*", // Allow all origins for WebSocket connections
        methods: ["GET", "POST"]
        // You might add 'credentials: true' if needed later for socket auth with cookies
    }
});

// --- Environment Variables & Config ---
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGODB_URI || !JWT_SECRET) {
    console.error("FATAL ERROR: MONGODB_URI or JWT_SECRET is missing.");
    process.exit(1);
}

// --- Database Connection ---
mongoose.connect(MONGODB_URI)
    .then(() => console.log('SERVER LOG: MongoDB Connected Successfully.'))
    .catch(err => {
        console.error('SERVER LOG: MongoDB connection error:', err);
        process.exit(1);
    });

// --- Express Middleware ---

// ** Configure CORS Options for API Routes **
const corsOptions = {
  origin: '*', // Allow all origins (Consider restricting in production to your client's URL)
  methods: ['GET', 'POST', 'OPTIONS'], // Explicitly allow OPTIONS, GET, POST
  allowedHeaders: ['Content-Type', 'Authorization'], // Allow necessary headers
  // credentials: true // Uncomment if dealing with cookies/sessions across origins
};

// ** Use CORS Middleware **
// 1. Handle preflight OPTIONS requests globally using the options
app.options('*', cors(corsOptions));
// 2. Apply CORS headers with options to all other requests
app.use(cors(corsOptions));

// 3. Body Parser (comes AFTER basic CORS handling)
app.use(express.json());

// --- User Tracking (In-memory map) ---
const onlineUsers = {}; // { userId: { username: "...", socketId: "..." } }
function getOnlineUsernames() {
    const usernames = new Set();
    for (const userId in onlineUsers) {
        if (onlineUsers[userId]) { usernames.add(onlineUsers[userId].username); }
    }
    return Array.from(usernames);
}

// --- API Routes ---
app.get('/', (req, res) => {
     res.send(`Chat server alive. Port: ${PORT}. Users online: ${getOnlineUsernames().length}`);
});

// Registration Route
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    console.log(`SERVER LOG: Registration attempt: "${username}"`);
    // Validation
    if (!username || !password || password.length < 6) { return res.status(400).json({ message: 'Username & password (min 6 chars) required.' }); }
    if (!/^[a-zA-Z0-9_]+$/.test(username) || username.length < 3 || username.length > 15) { return res.status(400).json({ message: 'Username invalid (3-15 chars, A-Z, 0-9, _).' }); }

    try {
        const existingUser = await User.findOne({ username: new RegExp(`^${username}$`, 'i') });
        if (existingUser) { return res.status(409).json({ message: 'Username already taken.' }); }

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        const newUser = new User({ username, passwordHash });
        await newUser.save();

        console.log(`SERVER LOG: User "${username}" registered.`);
        res.status(201).json({ message: 'Registration successful! Please login.' });
    } catch (error) {
        console.error("SERVER LOG: Registration error:", error);
        if (error.code === 11000) { return res.status(409).json({ message: 'Username already taken.' }); }
        res.status(500).json({ message: 'Server registration error.' });
    }
});

// Login Route
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    console.log(`SERVER LOG: Login attempt: "${username}"`);
    if (!username || !password) { return res.status(400).json({ message: 'Credentials required.' }); }

    try {
        const user = await User.findOne({ username: new RegExp(`^${username}$`, 'i') });
        if (!user) { return res.status(401).json({ message: 'Invalid credentials.' }); }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) { return res.status(401).json({ message: 'Invalid credentials.' }); }

        // Generate JWT
        const payload = { userId: user._id, username: user.username };
        jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' }, (err, token) => {
            if (err) { console.error("SERVER LOG: JWT signing error:", err); return res.status(500).json({ message: 'Token generation error.' }); }
            console.log(`SERVER LOG: User "${user.username}" logged in.`);
            res.json({ token, user: { id: user._id, username: user.username } });
        });
    } catch (error) { console.error("SERVER LOG: Login error:", error); res.status(500).json({ message: 'Server login error.' }); }
});

// --- Socket.IO Authentication Middleware ---
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    console.log(`SERVER LOG: Socket connect attempt ID: ${socket.id}. Checking token...`);
    if (!token) { console.log(`SERVER LOG: Conn rejected ${socket.id}. No token.`); return next(new Error('Authentication error: No token.')); }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) { console.log(`SERVER LOG: Conn rejected ${socket.id}. Invalid token: ${err.message}`); return next(new Error('Authentication error: Invalid token.')); }
        socket.userId = decoded.userId;
        socket.username = decoded.username;
        console.log(`SERVER LOG: Socket authenticated user "${socket.username}" (ID: ${socket.userId}), Socket ID: ${socket.id}`);
        next();
    });
});

// --- Socket.IO Connection Event ---
io.on('connection', (socket) => {
    console.log(`SERVER LOG: User "${socket.username}" (ID: ${socket.userId}) established connection. Socket ID: ${socket.id}.`);

    // Manage Online Users
    onlineUsers[socket.userId] = { username: socket.username, socketId: socket.id };
    console.log(`SERVER LOG: Broadcasting user list after connect: ${socket.username}`);
    io.emit('update_user_list', getOnlineUsernames());
    socket.broadcast.emit('user_connected', socket.username);

    // --- Socket Event Handlers ---
    socket.on('send_message', (messageData) => { /* ... same global message logic ... */ });
    socket.on('send_private_message', (data) => { /* ... same private message logic ... */ });
    socket.on('request_user_list', () => { /* ... same user list request logic ... */ });
    socket.on('disconnect', () => { /* ... same disconnect logic ... */ });

    // Add implementations back if they were accidentally removed
     socket.on('send_message', (messageData) => {
        const senderUsername = socket.username; 
        if (!messageData || typeof messageData.text !== 'string' || messageData.text.trim() === "") { return; }
        const messageText = messageData.text.trim();
        console.log(`SERVER LOG: Global message from ${senderUsername} (${socket.id}): ${messageText}`);
        const timestamp = new Date().toISOString();
        const fullMessage = { text: messageText, senderUsername, timestamp, socketId: socket.id };
        // TODO: Save global message to DB
        io.emit('receive_message', fullMessage);
    });

    socket.on('send_private_message', (data) => {
        const senderUsername = socket.username;
        const recipientUsername = data ? data.recipientUsername : null;
        const messageText = data ? data.text : null;
        console.log(`SERVER LOG: Received 'send_private_message' from ${senderUsername} to ${recipientUsername}`);

        if (!recipientUsername || !messageText || messageText.trim() === "") { socket.emit('private_message_failed', {recipientUsername: recipientUsername || '?', reason: 'Recipient/message missing.'}); return; }
        if (senderUsername.toLowerCase() === recipientUsername.toLowerCase()) { socket.emit('private_message_failed', { recipientUsername, reason: 'Cannot PM yourself.'}); return; }

        let recipientInfo = null; let recipientUserId = null;
        const recipientUsernameLower = recipientUsername.toLowerCase();
        for (const userId in onlineUsers) { if (onlineUsers[userId].username.toLowerCase() === recipientUsernameLower) { recipientInfo = onlineUsers[userId]; recipientUserId = userId; break; } }
        
        if (recipientInfo && io.sockets.sockets.get(recipientInfo.socketId)) {
            console.log(`SERVER LOG: Relaying PM from ${senderUsername} to ${recipientUsername} (socket ${recipientInfo.socketId})`);
            const timestamp = new Date().toISOString(); const messageContent = messageText.trim();
            // TODO: Save private message to DB
            io.to(recipientInfo.socketId).emit('receive_private_message', { type: 'received', senderUsername, text: messageContent, timestamp });
            socket.emit('receive_private_message', { type: 'sent', recipientUsername, text: messageContent, timestamp });
        } else {
             console.log(`SERVER LOG: PM failed from ${senderUsername}. Recipient ${recipientUsername} not found/offline.`);
            socket.emit('private_message_failed', { recipientUsername, reason: `User "${recipientUsername}" not found or is offline.` });
        }
    });

    socket.on('request_user_list', () => {
         console.log(`SERVER LOG: User list requested by ${socket.username} (${socket.id})`);
         socket.emit('update_user_list', getOnlineUsernames());
     });

    socket.on('disconnect', () => {
        const disconnectedUsername = socket.username; // Username from authenticated socket context
        console.log(`SERVER LOG: User disconnected. Socket ID: ${socket.id} (Username: ${disconnectedUsername || 'Already Cleaned Up?'})`);
        // Check using userId as it's more reliable if username wasn't set somehow (though middleware should prevent)
        if (socket.userId && onlineUsers[socket.userId]) {
            const actualUsername = onlineUsers[socket.userId].username; // Get username from map before deleting
            delete onlineUsers[socket.userId];
            console.log(`SERVER LOG: Broadcasting 'user_disconnected' for "${actualUsername}".`);
            io.emit('user_disconnected', actualUsername);
            console.log("SERVER LOG: Broadcasting updated user list after disconnect.");
            io.emit('update_user_list', getOnlineUsernames());
        } else { console.log(`SERVER LOG: Disconnected socket ${socket.id} had no associated user in online list.`); }
    });


}); // End io.on('connection')


// --- Start Server ---
server.listen(PORT, '0.0.0.0', () => {
    console.log(`SERVER LOG: Chat server listening on 0.0.0.0:${PORT}`);
});