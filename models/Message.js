// chat-server/models/Message.js
const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    sender: {
        type: mongoose.Schema.Types.ObjectId, // Reference to the User who sent it
        ref: 'User', // Links to the 'User' model
        required: true
    },
    senderUsername: { // Denormalize username for easier display on client
        type: String,
        required: true
    },
    recipient: { // For private messages
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null // Null if it's a global message
    },
    conversationId: { // Helps group messages for PMs or global chat
        type: String,
        required: true,
        index: true // Good for querying efficiency
    },
    text: {
        type: String,
        required: true,
        trim: true
    },
    timestamp: {
        type: Date,
        default: Date.now, // Defaults to current time when created
        index: true
    }
}, { timestamps: true }); // Adds createdAt and updatedAt (can be redundant with 'timestamp' but useful)

// Helper function to generate conversation ID for PMs
// Ensures consistency: always smaller userId_larger userId
messageSchema.statics.getPMConversationId = function(userId1, userId2) {
    return [userId1.toString(), userId2.toString()].sort().join('_');
};

module.exports = mongoose.model('Message', messageSchema);