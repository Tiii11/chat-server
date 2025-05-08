// chat-server/server.js
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*", // Allow all origins for simplicity in development. For production, restrict this.
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000; // Server will run on port 3000

// Keep track of users (optional, for more advanced features like user lists)
const users = {}; // { socketId: username }

io.on('connection', (socket) => {
    console.log(`User connected: ${socket.id}`);
    // For simplicity, we'll use socket.id as the username for now
    // In a real app, you'd have a login/username assignment mechanism
    users[socket.id] = `User-${socket.id.slice(0, 5)}`;
    socket.emit('assign_username', users[socket.id]); // Tell client its assigned username

    // Broadcast to all other clients that a new user has connected
    socket.broadcast.emit('user_connected', users[socket.id]);

    socket.on('send_message', (messageData) => {
        // messageData should be { text: "Hello", senderUsername: "User-abcde" }
        console.log(`Message from ${messageData.senderUsername}: ${messageData.text}`);

        const now = new Date();
        const timestamp = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;

        const fullMessage = {
            ...messageData,
            timestamp: timestamp,
            id: socket.id // Identify the original sender socket
        };

        // Broadcast the message to all connected clients (including the sender)
        io.emit('receive_message', fullMessage);
    });

    socket.on('disconnect', () => {
        console.log(`User disconnected: ${socket.id}`);
        const disconnectedUser = users[socket.id];
        delete users[socket.id];
        // Broadcast to all other clients that a user has disconnected
        if (disconnectedUser) {
            io.emit('user_disconnected', disconnectedUser);
        }
    });
});

server.listen(PORT, () => {
    console.log(`Chat server listening on *:${PORT}`);
});