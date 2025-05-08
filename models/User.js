// chat-server/models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        unique: true, // MongoDB will enforce uniqueness
        trim: true,
        lowercase: true, // Store username lowercase for case-insensitive lookup/uniqueness
        minlength: [3, 'Username must be at least 3 characters'],
        maxlength: [15, 'Username cannot exceed 15 characters'],
        match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores']
    },
    passwordHash: {
        type: String,
        required: [true, 'Password is required']
    },
    // Future fields:
    // email: { type: String, unique: true, sparse: true }, // sparse allows nulls but enforces uniqueness if present
    // profilePictureUrl: { type: String, default: '/default-avatar.png' },
    // friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
}, { timestamps: true });

// Method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
  // `this` refers to the user document
  return bcrypt.compare(candidatePassword, this.passwordHash);
};

// Optional: Middleware to hash password before saving (alternative to hashing in the route)
// userSchema.pre('save', async function(next) {
//   if (!this.isModified('passwordHash')) return next(); // Only hash if password field is modified
//   try {
//     const salt = await bcrypt.genSalt(10);
//     this.passwordHash = await bcrypt.hash(this.passwordHash, salt);
//     next();
//   } catch (error) {
//     next(error);
//   }
// });

module.exports = mongoose.model('User', userSchema);