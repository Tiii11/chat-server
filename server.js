// chat-server/server.js
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;

const users = {}; // Stores { socketId: "chosenUsername" }
const activeUsernames = new Set(); // To quickly check for unique active usernames

// Optional: A simple route to check if the server is running via HTTP
app.get('/', (req, res) => {
    res.send(`Chat server is alive! Listening for WebSocket connections on port ${PORT}.`);
});

io.on('connection', (socket) => {
    // Enhanced log for new connection
    console.log(`SERVER LOG: User connected to server. Socket ID: ${socket.id}. Awaiting username.`);

    socket.on('set_username', (desiredUsername) => {
        // Enhanced log for event reception
        console.log(`SERVER LOG: 'set_username' event received. Desired: "${desiredUsername}", From Socket ID: ${socket.id}`);

        const trimmedUsername = typeof desiredUsername === 'string' ? desiredUsername.trim() : '';

        if (!trimmedUsername || trimmedUsername.length < 3 || trimmedUsername.length > 15) {
            console.log(`SERVER LOG: Username "${trimmedUsername}" validation failed (length/chars). Emitting 'username_error'.`);
            socket.emit('username_error', 'Username must be 3-15 alphanumeric characters.');
            return;
        }
        if (!/^[a-zA-Z0-9_]+$/.test(trimmedUsername)) {
            console.log(`SERVER LOG: Username "${trimmedUsername}" validation failed (characters). Emitting 'username_error'.`);
            socket.emit('username_error', 'Username can only contain letters, numbers, and underscores.');
            return;
        }

        if (activeUsernames.has(trimmedUsername.toLowerCase())) { // Case-insensitive check for uniqueness
            console.log(`SERVER LOG: Username "${trimmedUsername}" is taken for ${socket.id}. Emitting 'username_error'.`);
            socket.emit('username_error', `Username "${trimmedUsername}" is already taken. Please choose another.`);
        } else {
            // Username is unique and valid
            users[socket.id] = trimmedUsername;
            activeUsernames.add(trimmedUsername.toLowerCase()); // Store lowercase for uniqueness check

            console.log(`SERVER LOG: Username "${trimmedUsername}" accepted for ${socket.id}. Emitting 'username_accepted'.`);
            socket.emit('username_accepted', trimmedUsername); // Confirm to this client
            
            // Log before broadcasting
            console.log(`SERVER LOG: Broadcasting 'user_connected' for "${trimmedUsername}" (from ${socket.id}).`);
            socket.broadcast.emit('user_connected', trimmedUsername);
        }
    });

    socket.on('send_message', (messageData) => {
        const senderUsername = users[socket.id]; 

        if (!senderUsername) {
            console.log(`SERVER LOG: Message from unnamed user (socket ID: ${socket.id}): ${messageData ? messageData.text : 'undefined message'}`);
            socket.emit('general_error', 'Please set your username before sending messages.');
            return;
        }
        
        if (!messageData || typeof messageData.text !== 'string' || messageData.text.trim() === "") {
            console.log(`SERVER LOG: Empty message attempt from ${senderUsername} (${socket.id})`);
            return; 
        }

        console.log(`SERVER LOG: Message from ${senderUsername} (${socket.id}): ${messageData.text.trim()}`);

        const now = new Date();
        const timestamp = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;

        const fullMessage = {
            text: messageData.text.trim(), 
            senderUsername: senderUsername,
            timestamp: timestamp,
            socketId: socket.id 
        };
        io.emit('receive_message', fullMessage); 
    });

    socket.on('disconnect', () => {
        const disconnectedUsername = users[socket.id];
        // Enhanced log for disconnect
        console.log(`SERVER LOG: User disconnected. Socket ID: ${socket.id} (Username: ${disconnectedUsername || 'Not yet named'})`);

        if (disconnectedUsername) {
            delete users[socket.id];
            activeUsernames.delete(disconnectedUsername.toLowerCase()); 
            // Log before broadcasting
            console.log(`SERVER LOG: Broadcasting 'user_disconnected' for "${disconnectedUsername}".`);
            io.emit('user_disconnected', disconnectedUsername); 
        }
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`SERVER LOG: Chat server listening on 0.0.0.0:${PORT}`);
});