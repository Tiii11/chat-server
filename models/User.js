// chat-server/models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        unique: true,
        trim: true,
        lowercase: true,
        minlength: [3, 'Username must be at least 3 characters'],
        maxlength: [15, 'Username cannot exceed 15 characters'],
        match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores']
    },
    passwordHash: {
        type: String,
        required: [true, 'Password is required']
    },
    // --- NEW FIELDS FOR FRIEND SYSTEM ---
    friends: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User' // References another User document
    }],
    pendingFriendRequests_sent: [{ // Requests this user has sent out
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    pendingFriendRequests_received: [{ // Requests this user has received
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }]
    // --- END NEW FIELDS ---
    // Future fields:
    // email: { type: String, unique: true, sparse: true },
    // profilePictureUrl: { type: String, default: '/default-avatar.png' },
}, { timestamps: true });

// Method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.passwordHash);
};

module.exports = mongoose.model('User', userSchema);