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
const Message = require('./models/Message'); // <--- NEW: Require Message model

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGODB_URI || !JWT_SECRET) { /* ... same essential config check ... */ process.exit(1); }

mongoose.connect(MONGODB_URI)
    .then(() => console.log('SERVER LOG: MongoDB Connected Successfully.'))
    .catch(err => { console.error('SERVER LOG: MongoDB connection error:', err); process.exit(1); });

const corsOptions = { origin: '*', methods: ['GET', 'POST', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] };
app.use(cors(corsOptions));
app.use(express.json());

const onlineUsers = {};
function getOnlineUsernames() { /* ... same ... */
    const usernames = new Set();
    for (const userId in onlineUsers) { if (onlineUsers[userId]) { usernames.add(onlineUsers[userId].username); } }
    return Array.from(usernames);
}

app.get('/', (req, res) => { /* ... same ... */ });
app.post('/api/auth/register', async (req, res) => { /* ... same registration logic ... */ });
app.post('/api/auth/login', async (req, res) => { /* ... same login logic ... */ });
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body; console.log(`SERVER LOG: Registration attempt: "${username}"`);
    if (!username || !password || password.length < 6) { return res.status(400).json({ message: 'Username & password (min 6 chars) required.' }); }
    if (!/^[a-zA-Z0-9_]+$/.test(username) || username.length < 3 || username.length > 15) { return res.status(400).json({ message: 'Username invalid (3-15 chars, A-Z, 0-9, _).' }); }
    try {
        const existingUser = await User.findOne({ username: new RegExp(`^${username}$`, 'i') });
        if (existingUser) { return res.status(409).json({ message: 'Username already taken.' }); }
        const salt = await bcrypt.genSalt(10); const passwordHash = await bcrypt.hash(password, salt);
        const newUser = new User({ username, passwordHash }); await newUser.save();
        console.log(`SERVER LOG: User "${username}" registered.`); res.status(201).json({ message: 'Registration successful! Please login.' });
    } catch (error) { console.error("SERVER LOG: Registration error:", error); if (error.code === 11000) { return res.status(409).json({ message: 'Username already taken.' }); } res.status(500).json({ message: 'Server registration error.' }); }
});
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body; console.log(`SERVER LOG: Login attempt: "${username}"`);
    if (!username || !password) { return res.status(400).json({ message: 'Credentials required.' }); }
    try {
        const user = await User.findOne({ username: new RegExp(`^${username}$`, 'i') });
        if (!user) { return res.status(401).json({ message: 'Invalid credentials.' }); }
        const isMatch = await user.comparePassword(password);
        if (!isMatch) { return res.status(401).json({ message: 'Invalid credentials.' }); }
        const payload = { userId: user._id, username: user.username };
        jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' }, (err, token) => {
            if (err) { console.error("SERVER LOG: JWT signing error:", err); return res.status(500).json({ message: 'Token generation error.' }); }
            console.log(`SERVER LOG: User "${user.username}" logged in.`); res.json({ token, user: { id: user._id, username: user.username } });
        });
    } catch (error) { console.error("SERVER LOG: Login error:", error); res.status(500).json({ message: 'Server login error.' }); }
});


io.use((socket, next) => { /* ... same JWT auth middleware ... */ });
io.use((socket, next) => {
    const token = socket.handshake.auth.token; console.log(`SERVER LOG: Socket connect attempt ID: ${socket.id}. Checking token...`);
    if (!token) { console.log(`SERVER LOG: Conn rejected ${socket.id}. No token.`); return next(new Error('Authentication error: No token.')); }
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) { console.log(`SERVER LOG: Conn rejected ${socket.id}. Invalid token: ${err.message}`); return next(new Error('Authentication error: Invalid token.')); }
        socket.userId = decoded.userId; socket.username = decoded.username;
        console.log(`SERVER LOG: Socket authenticated user "${socket.username}" (ID: ${socket.userId}), Socket ID: ${socket.id}`);
        next();
    });
});

io.on('connection', (socket) => {
    console.log(`SERVER LOG: User "${socket.username}" (ID: ${socket.userId}) established connection. Socket ID: ${socket.id}.`);
    onlineUsers[socket.userId] = { username: socket.username, socketId: socket.id };
    io.emit('update_user_list', getOnlineUsernames());
    socket.broadcast.emit('user_connected', socket.username);

    // --- Global Message Handling ---
    socket.on('send_message', async (messageData) => { // Made async
        const senderUsername = socket.username;
        if (!messageData || typeof messageData.text !== 'string' || messageData.text.trim() === "") { return; }
        const messageText = messageData.text.trim();
        console.log(`SERVER LOG: Global message from ${senderUsername} (${socket.id}): ${messageText}`);
        const timestamp = new Date(); // Use Date object directly

        // Save to DB
        try {
            const newMessage = new Message({
                sender: socket.userId,
                senderUsername: senderUsername,
                recipient: null, // Global message
                conversationId: 'global_chat',
                text: messageText,
                timestamp: timestamp
            });
            await newMessage.save();
            console.log("SERVER LOG: Global message saved to DB.");

            const fullMessage = { text: messageText, senderUsername, timestamp: timestamp.toISOString(), socketId: socket.id };
            io.emit('receive_message', fullMessage);
        } catch (error) {
            console.error("SERVER LOG: Error saving global message to DB:", error);
            socket.emit('general_error', 'Could not send message. Please try again.');
        }
    });

    // --- Private Message Handling ---
    socket.on('send_private_message', async (data) => { // Made async
        const senderUsername = socket.username;
        const recipientUsername = data ? data.recipientUsername : null;
        const messageText = data ? data.text : null;
        console.log(`SERVER LOG: Received 'send_private_message' from ${senderUsername} to ${recipientUsername}`);

        if (!recipientUsername || !messageText || messageText.trim() === "") { /* ... */ return; }
        if (senderUsername.toLowerCase() === recipientUsername.toLowerCase()) { /* ... */ socket.emit('private_message_failed', { recipientUsername, reason: 'Cannot PM yourself.'}); return; }

        let recipientInfo = null; let recipientUserId = null;
        const recipientUsernameLower = recipientUsername.toLowerCase();
        // Find recipient by username (case-insensitive) from DB to get their ID
        try {
            const recipientUserDoc = await User.findOne({ username: new RegExp(`^${recipientUsername}$`, 'i') });
            if (!recipientUserDoc) {
                console.log(`SERVER LOG: PM failed. Recipient user document "${recipientUsername}" not found in DB.`);
                socket.emit('private_message_failed', { recipientUsername, reason: `User "${recipientUsername}" does not exist.` });
                return;
            }
            recipientUserId = recipientUserDoc._id.toString(); // Get the ID of the recipient from DB

            // Check if recipient is online using onlineUsers map
            if (onlineUsers[recipientUserId]) {
                recipientInfo = onlineUsers[recipientUserId];
            }

        } catch(dbError) {
            console.error("SERVER LOG: Error finding recipient user for PM:", dbError);
            socket.emit('private_message_failed', { recipientUsername, reason: 'Server error finding recipient.' });
            return;
        }


        const timestamp = new Date(); // Use Date object directly
        const messageContent = messageText.trim();
        const conversationId = Message.getPMConversationId(socket.userId, recipientUserId); // Use static method

        // Save to DB
        try {
            const newPM = new Message({
                sender: socket.userId,
                senderUsername: senderUsername,
                recipient: recipientUserId,
                conversationId: conversationId,
                text: messageContent,
                timestamp: timestamp
            });
            await newPM.save();
            console.log(`SERVER LOG: PM from ${senderUsername} to ${recipientUsername} saved to DB.`);

            // If recipient is online, send real-time
            if (recipientInfo && io.sockets.sockets.get(recipientInfo.socketId)) {
                console.log(`SERVER LOG: Relaying PM to online recipient ${recipientUsername} (socket ${recipientInfo.socketId})`);
                io.to(recipientInfo.socketId).emit('receive_private_message', { type: 'received', senderUsername, text: messageContent, timestamp: timestamp.toISOString() });
            } else {
                console.log(`SERVER LOG: Recipient ${recipientUsername} is offline. PM saved, will be loaded from history.`);
                // Optionally, you could implement a notification system for offline messages here
            }
            // Send confirmation back to SENDER
            socket.emit('receive_private_message', { type: 'sent', recipientUsername, text: messageContent, timestamp: timestamp.toISOString() });

        } catch (error) {
            console.error("SERVER LOG: Error saving/sending PM:", error);
            socket.emit('private_message_failed', { recipientUsername, reason: 'Could not send/save PM.' });
        }
    });

    // --- Request Message History ---
    socket.on('request_history', async ({ conversationId, recipientUsername }) => { // recipientUsername for PMs
        console.log(`SERVER LOG: History requested for conversationId: "${conversationId}" by ${socket.username}`);
        try {
            let finalConversationId = conversationId;
            if (conversationId === 'global_chat') {
                // Handled by finalConversationId
            } else if (recipientUsername) { // For PMs, construct conversationId from recipient
                const recipientUserDoc = await User.findOne({ username: new RegExp(`^${recipientUsername}$`, 'i') });
                if (!recipientUserDoc) {
                    console.log("SERVER LOG: Cannot load history, recipient for PM not found in DB:", recipientUsername);
                    socket.emit('load_history', { conversationId: `pm_${recipientUsername}`, messages: [], error: "Recipient not found." });
                    return;
                }
                finalConversationId = Message.getPMConversationId(socket.userId, recipientUserDoc._id);
            } else {
                console.log("SERVER LOG: Invalid history request, recipientUsername needed for PM history.");
                socket.emit('load_history', { conversationId: 'unknown', messages: [], error: "Invalid request for PM history." });
                return;
            }


            const messages = await Message.find({ conversationId: finalConversationId })
                .sort({ timestamp: 1 }) // Load oldest first for client to prepend/display correctly
                .limit(50) // Get last 50 messages
                .populate('sender', 'username') // Optionally populate sender details (if needed beyond senderUsername)
                .lean(); // Use .lean() for plain JS objects, faster

            // Map messages to the format client expects (especially timestamp as ISO string)
            const formattedMessages = messages.map(msg => ({
                ...msg,
                timestamp: msg.timestamp.toISOString(),
                // senderUsername is already on the message model, but if you used populate:
                // senderUsername: msg.sender.username 
            }));

            console.log(`SERVER LOG: Sending ${formattedMessages.length} messages for conversationId: "${finalConversationId}"`);
            socket.emit('load_history', { conversationId: finalConversationId, messages: formattedMessages });
        } catch (error) {
            console.error("SERVER LOG: Error fetching message history:", error);
            socket.emit('load_history', { conversationId, messages: [], error: "Could not load history." });
        }
    });


    socket.on('request_user_list', () => { /* ... same ... */ });
    socket.on('disconnect', () => { /* ... same ... */ });
     socket.on('request_user_list', () => { console.log(`SERVER LOG: User list requested by ${socket.username} (${socket.id})`); socket.emit('update_user_list', getOnlineUsernames()); });
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
    console.log(`SERVER LOG: Chat server listening on 0.0.0.0:${PORT}`);
});