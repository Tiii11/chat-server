// chat-server/server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require("socket.io");
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const Message = require('./models/Message');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGODB_URI || !JWT_SECRET) {
    console.error("FATAL ERROR: MONGODB_URI or JWT_SECRET missing.");
    process.exit(1);
}

mongoose.connect(MONGODB_URI)
    .then(() => console.log('SERVER LOG: MongoDB Connected Successfully.'))
    .catch(err => {
        console.error('SERVER LOG: MongoDB connection error:', err);
        process.exit(1);
    });

const corsOptions = {
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));
app.use(express.json());

const onlineUsers = {};
function getOnlineUsernames() {
    const usernames = new Set();
    for (const userId in onlineUsers) {
        if (onlineUsers[userId]) { usernames.add(onlineUsers[userId].username); }
    }
    return Array.from(usernames);
}

app.get('/', (req, res) => {
     console.log(`SERVER LOG: Root path '/' hit. IP: ${req.ip}, Headers: ${JSON.stringify(req.headers)}`);
     res.status(200).send(`Chat server is alive! Port: ${PORT}. Users online: ${getOnlineUsernames().length}. Timestamp: ${new Date().toISOString()}`);
});

app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    console.log(`SERVER LOG: Registration attempt: "${username}"`);
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

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    console.log(`SERVER LOG: Login attempt: "${username}"`);
    if (!username || !password) { return res.status(400).json({ message: 'Credentials required.' }); }
    try {
        const user = await User.findOne({ username: new RegExp(`^${username}$`, 'i') });
        if (!user) { return res.status(401).json({ message: 'Invalid credentials.' }); }
        const isMatch = await user.comparePassword(password);
        if (!isMatch) { return res.status(401).json({ message: 'Invalid credentials.' }); }
        const payload = { userId: user._id, username: user.username };
        jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' }, (err, token) => {
            if (err) { console.error("SERVER LOG: JWT signing error:", err); return res.status(500).json({ message: 'Token generation error.' }); }
            console.log(`SERVER LOG: User "${user.username}" logged in.`);
            res.json({ token, user: { id: user._id, username: user.username } });
        });
    } catch (error) { console.error("SERVER LOG: Login error:", error); res.status(500).json({ message: 'Server login error.' }); }
});

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

io.on('connection', (socket) => {
    console.log(`SERVER LOG: User "${socket.username}" (ID: ${socket.userId}) established connection. Socket ID: ${socket.id}.`);
    onlineUsers[socket.userId] = { username: socket.username, socketId: socket.id };
    io.emit('update_user_list', getOnlineUsernames());
    socket.broadcast.emit('user_connected', socket.username);

    socket.on('send_message', async (messageData) => {
        const senderUsername = socket.username;
        if (!messageData || typeof messageData.text !== 'string' || messageData.text.trim() === "") { return; }
        const messageText = messageData.text.trim();
        console.log(`SERVER LOG: Global message from ${senderUsername} (${socket.id}): ${messageText}`);
        const timestamp = new Date();
        try {
            const newMessage = new Message({ sender: socket.userId, senderUsername, recipient: null, conversationId: 'global_chat', text: messageText, timestamp });
            await newMessage.save();
            console.log("SERVER LOG: Global message saved to DB.");
            io.emit('receive_message', { text: messageText, senderUsername, timestamp: timestamp.toISOString(), socketId: socket.id });
        } catch (error) { console.error("SERVER LOG: Error saving global message:", error); socket.emit('general_error', 'Could not send message.'); }
    });

    socket.on('send_private_message', async (data) => {
        const senderUsername = socket.username;
        const recipientUsername = data ? data.recipientUsername : null;
        const messageText = data ? data.text : null;
        console.log(`SERVER LOG: Received 'send_private_message' from ${senderUsername} to ${recipientUsername}`);
        if (!recipientUsername || !messageText || messageText.trim() === "") { socket.emit('private_message_failed', {recipientUsername: recipientUsername || '?', reason: 'Recipient/message missing.'}); return; }
        if (senderUsername.toLowerCase() === recipientUsername.toLowerCase()) { socket.emit('private_message_failed', { recipientUsername, reason: 'Cannot PM yourself.'}); return; }

        let recipientInfo = null; let recipientUserId = null;
        const recipientUsernameLower = recipientUsername.toLowerCase();
        try {
            const recipientUserDoc = await User.findOne({ username: new RegExp(`^${recipientUsername}$`, 'i') });
            if (!recipientUserDoc) { socket.emit('private_message_failed', { recipientUsername, reason: `User "${recipientUsername}" does not exist.` }); return; }
            recipientUserId = recipientUserDoc._id.toString();
            if (onlineUsers[recipientUserId]) { recipientInfo = onlineUsers[recipientUserId]; }
        } catch(dbError) { console.error("SERVER LOG: Error finding recipient for PM:", dbError); socket.emit('private_message_failed', { recipientUsername, reason: 'Server error finding recipient.' }); return; }

        const timestamp = new Date(); const messageContent = messageText.trim();
        const conversationId = Message.getPMConversationId(socket.userId, recipientUserId);
        try {
            const newPM = new Message({ sender: socket.userId, senderUsername, recipient: recipientUserId, conversationId, text: messageContent, timestamp });
            await newPM.save();
            console.log(`SERVER LOG: PM from ${senderUsername} to ${recipientUsername} saved to DB.`);
            if (recipientInfo && io.sockets.sockets.get(recipientInfo.socketId)) {
                io.to(recipientInfo.socketId).emit('receive_private_message', { type: 'received', senderUsername, text: messageContent, timestamp: timestamp.toISOString() });
            } else { console.log(`SERVER LOG: Recipient ${recipientUsername} offline for PM. Saved.`); }
            socket.emit('receive_private_message', { type: 'sent', recipientUsername, text: messageContent, timestamp: timestamp.toISOString() });
        } catch (error) { console.error("SERVER LOG: Error saving/sending PM:", error); socket.emit('private_message_failed', { recipientUsername, reason: 'Could not send/save PM.' }); }
    });

    socket.on('request_history', async ({ conversationId, recipientUsername }) => {
        console.log(`SERVER LOG: History requested for clientConvId: "${conversationId}", recipient: "${recipientUsername}" by ${socket.username}`);
        let dbConversationId;
        if (conversationId === 'global_chat' || conversationId === 'global') {
            dbConversationId = 'global_chat';
        } else if (recipientUsername) {
            try {
                const recipientUserDoc = await User.findOne({ username: new RegExp(`^${recipientUsername}$`, 'i') });
                if (!recipientUserDoc) { socket.emit('load_history', { conversationId: `pm_${recipientUsername}`, messages: [], error: "Recipient not found." }); return; }
                dbConversationId = Message.getPMConversationId(socket.userId, recipientUserDoc._id.toString());
            } catch (error) { console.error("SERVER LOG: Error finding recipient user for history:", error); socket.emit('load_history', { conversationId: `pm_${recipientUsername}`, messages: [], error: "Server error finding recipient." }); return; }
        } else {
            console.log("SERVER LOG: Invalid history request. ClientConvId:", conversationId, "RecipientUsername:", recipientUsername);
            socket.emit('load_history', { conversationId: conversationId, messages: [], error: "Invalid history request." }); return;
        }
        try {
            const messages = await Message.find({ conversationId: dbConversationId }).sort({ timestamp: 1 }).limit(50).lean();
            const formattedMessages = messages.map(msg => ({ ...msg, timestamp: msg.timestamp.toISOString() }));
            console.log(`SERVER LOG: Sending ${formattedMessages.length} messages for dbConvId: "${dbConversationId}" (client req: "${conversationId}")`);
            socket.emit('load_history', { conversationId: conversationId, messages: formattedMessages }); // Send back original client's conversationId
        } catch (error) { console.error("SERVER LOG: Error fetching history for ", dbConversationId, error); socket.emit('load_history', { conversationId: conversationId, messages: [], error: "Could not load history." }); }
    });

    socket.on('request_user_list', () => {
         console.log(`SERVER LOG: User list requested by ${socket.username} (${socket.id})`);
         socket.emit('update_user_list', getOnlineUsernames());
     });

    socket.on('disconnect', () => {
        const disconnectedUsername = socket.username;
        console.log(`SERVER LOG: User disconnected. Socket ID: ${socket.id} (Username: ${disconnectedUsername || 'Auth Error?'})`);
        if (socket.userId && onlineUsers[socket.userId]) {
            const actualUsername = onlineUsers[socket.userId].username;
            delete onlineUsers[socket.userId];
            console.log(`SERVER LOG: Broadcasting 'user_disconnected' for "${actualUsername}".`);
            io.emit('user_disconnected', actualUsername);
            console.log("SERVER LOG: Broadcasting updated user list after disconnect.");
            io.emit('update_user_list', getOnlineUsernames());
        } else { console.log(`SERVER LOG: Disconnected socket ${socket.id} had no associated user in online list.`); }
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`SERVER LOG: Chat server (HTTP & WebSocket) listening on 0.0.0.0:${PORT}`);
});