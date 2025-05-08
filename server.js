// chat-server/server.js
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

// Initialize Socket.IO server with CORS configuration
const io = new Server(server, {
    cors: {
        origin: "*", // Allows connections from any origin. Good for Electron apps & development.
                     // For a production web app, you might restrict this to your frontend's domain.
        methods: ["GET", "POST"]
    }
});

// Define the port. Render will set process.env.PORT.
// For local development, it will default to 3000.
const PORT = process.env.PORT || 3000;

// A simple object to keep track of users by their socket ID and assigned username
// In a real application, you might use a database or more robust session management.
const users = {}; // Example: { "socketId123": "User-abcde" }

// Optional: A simple route to check if the server is running via HTTP
app.get('/', (req, res) => {
    res.send(`Chat server is alive! Listening for WebSocket connections on port ${PORT}.`);
});

io.on('connection', (socket) => {
    console.log(`User connected: ${socket.id}`);

    // Assign a simple username based on socket ID
    // In a real app, you'd likely have a login flow or prompt for a username.
    const assignedUsername = `User-${socket.id.slice(0, 5)}`;
    users[socket.id] = assignedUsername;

    // Send the assigned username back to the connected client
    socket.emit('assign_username', assignedUsername);
    console.log(`Assigned username ${assignedUsername} to ${socket.id}`);

    // Broadcast to all *other* clients that a new user has connected
    socket.broadcast.emit('user_connected', assignedUsername);

    // Listen for 'send_message' events from clients
    socket.on('send_message', (messageData) => {
        // Expected messageData: { text: "Some message", senderUsername: "User-xxxxx" }
        // We trust the senderUsername from the client for now, but in production,
        // you might verify it or use the server-assigned username.
        const sender = users[socket.id] || messageData.senderUsername || "Anonymous"; // Fallback if needed

        console.log(`Message from ${sender} (${socket.id}): ${messageData.text}`);

        const now = new Date();
        const timestamp = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;

        const fullMessage = {
            text: messageData.text,
            senderUsername: sender,
            timestamp: timestamp,
            socketId: socket.id // Can be useful for client-side logic (e.g., styling own messages)
        };

        // Broadcast the message to ALL connected clients (including the sender)
        io.emit('receive_message', fullMessage);
    });

    // Handle client disconnections
    socket.on('disconnect', () => {
        const disconnectedUsername = users[socket.id];
        console.log(`User disconnected: ${socket.id} (${disconnectedUsername || 'Unknown User'})`);

        if (disconnectedUsername) {
            delete users[socket.id];
            // Broadcast to all other clients that this user has disconnected
            io.emit('user_disconnected', disconnectedUsername);
        }
    });
});

// Start the HTTP server
server.listen(PORT, '0.0.0.0', () => {
    // Listening on '0.0.0.0' is important for containerized environments like Render.
    // It means the server will accept connections on all available network interfaces.
    console.log(`Chat server listening on 0.0.0.0:${PORT}`);
    console.log(`Accessible publicly via your Render URL (e.g., https://chat-server-kbrx.onrender.com) if deployed.`);
    console.log(`For local testing, Electron app should connect to http://localhost:${PORT}`);
});