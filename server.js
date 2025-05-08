// chat-server/server.js
require('dotenv').config(); // Load environment variables from .env file first
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models/User'); // Make sure models/User.js exists

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*", // TODO: Restrict this in production
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGODB_URI || !JWT_SECRET) {
    console.error("FATAL ERROR: MONGODB_URI or JWT_SECRET is missing in .env file or environment variables.");
    process.exit(1); // Exit if essential config is missing
}

// --- Database Connection ---
mongoose.connect(MONGODB_URI)
    .then(() => console.log('SERVER LOG: MongoDB Connected Successfully.'))
    .catch(err => {
        console.error('SERVER LOG: MongoDB connection error:', err);
        process.exit(1); // Exit if DB connection fails on startup
    });

// --- Middleware ---
app.use(express.json()); // To parse JSON request bodies for API routes

// --- User Tracking (In-memory map of online users) ---
const onlineUsers = {}; // Stores { userId: { username: "...", socketId: "..." } }

// Helper function to get current online usernames
function getOnlineUsernames() {
    // Extract unique usernames from the onlineUsers object
    const usernames = new Set();
    for (const userId in onlineUsers) {
        usernames.add(onlineUsers[userId].username);
    }
    return Array.from(usernames);
}


// --- API Routes ---
app.get('/', (req, res) => { // Root route for basic check
     res.send(`Chat server is alive! Listening on port ${PORT}. ${getOnlineUsernames().length} users online.`);
});

// Registration
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    console.log(`SERVER LOG: Registration attempt for username: "${username}"`);

    if (!username || !password || password.length < 6) {
         console.log(`SERVER LOG: Registration validation failed for "${username}" (missing fields or short password).`);
        return res.status(400).json({ message: 'Username and password (min 6 chars) required.' });
    }
     if (!/^[a-zA-Z0-9_]+$/.test(username) || username.length < 3 || username.length > 15) {
         console.log(`SERVER LOG: Registration validation failed for "${username}" (format/length).`);
         return res.status(400).json({ message: 'Username must be 3-15 chars (letters, numbers, underscore).' });
     }

    try {
        // Use collation for case-insensitive unique index if setup in MongoDB schema (or check manually)
        const existingUser = await User.findOne({ username: new RegExp(`^${username}$`, 'i') });
        if (existingUser) {
            console.log(`SERVER LOG: Registration failed for "${username}" (already exists).`);
            return res.status(409).json({ message: 'Username already taken.' });
        }

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        const newUser = new User({ username, passwordHash });
        await newUser.save();

        console.log(`SERVER LOG: User "${username}" registered successfully.`);
        res.status(201).json({ message: 'User registered successfully! Please login.' });

    } catch (error) {
        console.error("SERVER LOG: Registration error:", error);
         if (error.code === 11000) { // Mongo duplicate key error
             return res.status(409).json({ message: 'Username already taken.' });
         }
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
     console.log(`SERVER LOG: Login attempt for username: "${username}"`);

    if (!username || !password) { /* ... validation ... */ return res.status(400).json({ message: 'Credentials required.' }); }

    try {
        const user = await User.findOne({ username: new RegExp(`^${username}$`, 'i') });
        if (!user) { /* ... validation ... */ return res.status(401).json({ message: 'Invalid credentials.' }); }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) { /* ... validation ... */ return res.status(401).json({ message: 'Invalid credentials.' }); }

        // Generate JWT
        const payload = { userId: user._id, username: user.username };
        jwt.sign(
            payload, JWT_SECRET, { expiresIn: '1d' },
            (err, token) => {
                if (err) { /* ... error handling ... */ return res.status(500).json({ message: 'Token generation error.' }); }
                console.log(`SERVER LOG: User "${user.username}" logged in successfully.`);
                res.json({
                    token,
                    user: { id: user._id, username: user.username }
                });
            }
        );

    } catch (error) { /* ... error handling ... */ res.status(500).json({ message: 'Server login error.' }); }
});


// --- Socket.IO Middleware for Authentication ---
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    console.log(`SERVER LOG: Socket connection attempt. Socket ID: ${socket.id}. Checking token...`);
    if (!token) { /* ... error handling ... */ return next(new Error('Authentication error: No token.')); }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) { /* ... error handling ... */ return next(new Error('Authentication error: Invalid token.')); }

        // Check if user still exists in DB (optional, adds overhead but more secure)
        // User.findById(decoded.userId).then(user => { if (!user) { return next(new Error('Authentication error: User not found.')); } ... });

        socket.userId = decoded.userId;
        socket.username = decoded.username;
        console.log(`SERVER LOG: Socket authenticated for user "${socket.username}" (ID: ${socket.userId}), Socket ID: ${socket.id}`);
        next();
    });
});

// --- Socket.IO Connection Logic ---
io.on('connection', (socket) => {
    console.log(`SERVER LOG: User "${socket.username}" (ID: ${socket.userId}) connected via socket ${socket.id}.`);

    // Manage Online Users
    onlineUsers[socket.userId] = { username: socket.username, socketId: socket.id };
    console.log(`SERVER LOG: Broadcasting user list after connect: ${socket.username}`);
    io.emit('update_user_list', getOnlineUsernames());
    socket.broadcast.emit('user_connected', socket.username);

    // --- Message Handlers ---
    // Global Message
    socket.on('send_message', (messageData) => {
        const senderUsername = socket.username; // Authenticated username
        if (!messageData || typeof messageData.text !== 'string' || messageData.text.trim() === "") { return; }
        const messageText = messageData.text.trim();
        console.log(`SERVER LOG: Global message from ${senderUsername} (${socket.id}): ${messageText}`);
        const timestamp = new Date().toISOString();
        const fullMessage = { text: messageText, senderUsername, timestamp, socketId: socket.id };
        
        // TODO: Save global message to database here if needed
        
        io.emit('receive_message', fullMessage);
    });

    // Private Message
    socket.on('send_private_message', (data) => {
        const senderUsername = socket.username;
        const recipientUsername = data ? data.recipientUsername : null;
        const messageText = data ? data.text : null;
        console.log(`SERVER LOG: Received 'send_private_message' from ${senderUsername} to ${recipientUsername}`);

        // Validations (basic)
        if (!recipientUsername || !messageText || messageText.trim() === "") { /* ... */ return; }
        if (senderUsername.toLowerCase() === recipientUsername.toLowerCase()) { /* ... */ socket.emit('private_message_failed', { recipientUsername, reason: 'Cannot PM yourself.'}); return; }

        // Find Recipient Socket ID
        let recipientInfo = null;
        const recipientUsernameLower = recipientUsername.toLowerCase();
        let recipientUserId = null; // Need userId for saving to DB
        for (const userId in onlineUsers) {
            if (onlineUsers[userId].username.toLowerCase() === recipientUsernameLower) {
                recipientInfo = onlineUsers[userId];
                recipientUserId = userId; // Store the recipient's actual User ID
                break;
            }
        }
        
        if (recipientInfo && io.sockets.sockets.get(recipientInfo.socketId)) {
            console.log(`SERVER LOG: Relaying PM from ${senderUsername} to ${recipientUsername} (socket ${recipientInfo.socketId})`);
            const timestamp = new Date().toISOString();
            const messageContent = messageText.trim();

            // TODO: Save private message to database here, linking senderUserId, recipientUserId, text, timestamp

            io.to(recipientInfo.socketId).emit('receive_private_message', { type: 'received', senderUsername, text: messageContent, timestamp });
            socket.emit('receive_private_message', { type: 'sent', recipientUsername, text: messageContent, timestamp });
        } else {
            console.log(`SERVER LOG: PM failed from ${senderUsername}. Recipient ${recipientUsername} not found/offline.`);
            socket.emit('private_message_failed', { recipientUsername, reason: `User "${recipientUsername}" not found or is offline.` });
        }
    });

    // Request User List
     socket.on('request_user_list', () => {
         console.log(`SERVER LOG: User list requested by ${socket.username} (${socket.id})`);
         socket.emit('update_user_list', getOnlineUsernames());
     });

    // Disconnect
    socket.on('disconnect', () => {
        const disconnectedUsername = socket.username;
        console.log(`SERVER LOG: User disconnected. Socket ID: ${socket.id} (Username: ${disconnectedUsername || 'Auth Error?'})`);
        if (disconnectedUsername && onlineUsers[socket.userId]) { // Check if user was actually in the list
            delete onlineUsers[socket.userId];
            console.log(`SERVER LOG: Broadcasting 'user_disconnected' for "${disconnectedUsername}".`);
            io.emit('user_disconnected', disconnectedUsername);
            console.log("SERVER LOG: Broadcasting updated user list after disconnect.");
            io.emit('update_user_list', getOnlineUsernames());
        } else {
             console.log(`SERVER LOG: Disconnected socket ${socket.id} had no associated user in online list.`);
        }
    });
});

// --- Start Server ---
server.listen(PORT, '0.0.0.0', () => {
    console.log(`SERVER LOG: Chat server listening on 0.0.0.0:${PORT}`);
});