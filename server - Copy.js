// chat-server/server.js
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*", // Allow all origins - adjust for production if needed
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;

const users = {}; // Stores { socketId: "chosenUsername" }
const activeUsernames = new Set(); // To quickly check for unique active usernames (stores lowercase)

// Helper function to get current online usernames (with correct casing)
function getOnlineUsernames() {
    return Object.values(users).filter(username => username != null); // Filter out potential nulls just in case
}

// Optional: A simple route to check if the server is running via HTTP
app.get('/', (req, res) => {
    res.send(`Chat server is alive! Listening for WebSocket connections on port ${PORT}. ${getOnlineUsernames().length} users online.`);
});

io.on('connection', (socket) => {
    // Log for new connection
    console.log(`SERVER LOG: User connected to server. Socket ID: ${socket.id}. Awaiting username.`);

    // --- Username Handling ---
    socket.on('set_username', (desiredUsername) => {
        console.log(`SERVER LOG: 'set_username' event received. Desired: "${desiredUsername}", From Socket ID: ${socket.id}`);

        // Prevent setting username if already set for this socket
        if (users[socket.id]) {
             console.log(`SERVER LOG: User ${socket.id} (${users[socket.id]}) attempted to set username again.`);
             socket.emit('general_error', 'Username already set.');
             return;
        }

        const trimmedUsername = typeof desiredUsername === 'string' ? desiredUsername.trim() : '';

        // Validation
        if (!trimmedUsername || trimmedUsername.length < 3 || trimmedUsername.length > 15) {
            console.log(`SERVER LOG: Username "${trimmedUsername}" validation failed (length). Emitting 'username_error'.`);
            socket.emit('username_error', 'Username must be 3-15 characters.');
            return;
        }
        if (!/^[a-zA-Z0-9_]+$/.test(trimmedUsername)) {
            console.log(`SERVER LOG: Username "${trimmedUsername}" validation failed (characters). Emitting 'username_error'.`);
            socket.emit('username_error', 'Username can only contain letters, numbers, and underscores.');
            return;
        }
        if (activeUsernames.has(trimmedUsername.toLowerCase())) { // Case-insensitive uniqueness check
            console.log(`SERVER LOG: Username "${trimmedUsername}" is taken for ${socket.id}. Emitting 'username_error'.`);
            socket.emit('username_error', `Username "${trimmedUsername}" is already taken. Please choose another.`);
        } else {
            // Username is unique and valid
            users[socket.id] = trimmedUsername;
            activeUsernames.add(trimmedUsername.toLowerCase());

            console.log(`SERVER LOG: Username "${trimmedUsername}" accepted for ${socket.id}. Emitting 'username_accepted'.`);
            socket.emit('username_accepted', trimmedUsername);

            console.log(`SERVER LOG: Broadcasting 'user_connected' for "${trimmedUsername}" (from ${socket.id}).`);
            socket.broadcast.emit('user_connected', trimmedUsername);

            // Broadcast updated user list
            console.log("SERVER LOG: Broadcasting updated user list after successful username set.");
            io.emit('update_user_list', getOnlineUsernames());
        }
    });

    // --- Global Message Handling ---
    socket.on('send_message', (messageData) => {
        const senderUsername = users[socket.id];

        if (!senderUsername) {
            console.log(`SERVER LOG: Global message from unnamed user (socket ID: ${socket.id}): ${messageData ? messageData.text : 'undefined message'}`);
            socket.emit('general_error', 'Please set your username before sending messages.');
            return;
        }
        if (!messageData || typeof messageData.text !== 'string' || messageData.text.trim() === "") {
            console.log(`SERVER LOG: Empty global message attempt from ${senderUsername} (${socket.id})`);
            return;
        }

        const messageText = messageData.text.trim();
        console.log(`SERVER LOG: Global message from ${senderUsername} (${socket.id}): ${messageText}`);

        const timestamp = new Date().toISOString(); // Use ISO timestamp

        const fullMessage = {
            text: messageText,
            senderUsername: senderUsername,
            timestamp: timestamp, // Send full timestamp
            socketId: socket.id
        };
        io.emit('receive_message', fullMessage); // Broadcast global messages to ALL
    });

    // --- Private Message Handling ---
    socket.on('send_private_message', (data) => {
        const senderUsername = users[socket.id];
        const recipientUsername = data ? data.recipientUsername : null;
        const messageText = data ? data.text : null;

        console.log(`SERVER LOG: Received 'send_private_message' from ${senderUsername || socket.id} to ${recipientUsername}`);

        // Validations
        if (!senderUsername) { /* ... same validation ... */ socket.emit('general_error', 'Set username first.'); return; }
        if (!recipientUsername || typeof recipientUsername !== 'string') { /* ... same validation ... */ socket.emit('private_message_failed', { recipientUsername: recipientUsername || '?', reason: 'Recipient missing.' }); return; }
        if (!messageText || typeof messageText !== 'string' || messageText.trim() === "") { /* ... same validation ... */ socket.emit('private_message_failed', { recipientUsername: recipientUsername, reason: 'Message empty.' }); return; }
        if (senderUsername.toLowerCase() === recipientUsername.toLowerCase()) { /* ... same validation ... */ socket.emit('private_message_failed', { recipientUsername: recipientUsername, reason: 'Cannot PM yourself.' }); return; }

        // Find Recipient Socket ID
        let recipientSocketId = null;
        const recipientUsernameLower = recipientUsername.toLowerCase();
        for (const [id, username] of Object.entries(users)) {
            if (username.toLowerCase() === recipientUsernameLower) {
                recipientSocketId = id;
                break;
            }
        }

        if (recipientSocketId && io.sockets.sockets.get(recipientSocketId)) {
            // Recipient found and connected
            console.log(`SERVER LOG: Relaying PM from ${senderUsername} to ${recipientUsername} (socket ${recipientSocketId})`);
            const timestamp = new Date().toISOString(); // Use ISO timestamp

            // Send to RECIPIENT
            io.to(recipientSocketId).emit('receive_private_message', {
                type: 'received',
                senderUsername: senderUsername,
                text: messageText.trim(),
                timestamp: timestamp // Send full timestamp
            });

            // Send confirmation back to SENDER
            socket.emit('receive_private_message', {
                type: 'sent',
                recipientUsername: recipientUsername,
                text: messageText.trim(),
                timestamp: timestamp // Send full timestamp
            });
        } else {
            // Recipient not found or offline
            console.log(`SERVER LOG: PM failed from ${senderUsername}. Recipient ${recipientUsername} not found or offline.`);
            socket.emit('private_message_failed', {
                recipientUsername: recipientUsername,
                reason: `User "${recipientUsername}" not found or is offline.`
            });
        }
    });

     // --- Request User List --- (Client might request this after connect/reconnect)
     socket.on('request_user_list', () => {
         console.log(`SERVER LOG: User list requested by ${users[socket.id] || socket.id}`);
         // Send the list only back to the requester
         socket.emit('update_user_list', getOnlineUsernames());
     });


    // --- Disconnect Handling ---
    socket.on('disconnect', () => {
        const disconnectedUsername = users[socket.id];
        console.log(`SERVER LOG: User disconnected. Socket ID: ${socket.id} (Username: ${disconnectedUsername || 'Not yet named'})`);

        if (disconnectedUsername) {
            delete users[socket.id];
            activeUsernames.delete(disconnectedUsername.toLowerCase());
            console.log(`SERVER LOG: Broadcasting 'user_disconnected' for "${disconnectedUsername}".`);
            io.emit('user_disconnected', disconnectedUsername);

            // Broadcast updated user list
            console.log("SERVER LOG: Broadcasting updated user list after disconnect.");
            io.emit('update_user_list', getOnlineUsernames());
        }
    });
});

// --- Start Server ---
server.listen(PORT, '0.0.0.0', () => {
    console.log(`SERVER LOG: Chat server listening on 0.0.0.0:${PORT}`);
});