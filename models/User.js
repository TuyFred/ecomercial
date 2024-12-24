const mongoose = require('mongoose');

// Define the user schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true }, // Enforces uniqueness at the database level
    password: { type: String, required: true },
    role: { type: String, required: true, enum: ['admin', 'customer'], default: 'customer' }, // Role with enum and default
}, { timestamps: true }); // Enable timestamps for createdAt and updatedAt

// Create a unique index for email to ensure email uniqueness at the database level

userSchema.index({ email: 1 }, { unique: true });

// Export the user model
module.exports = mongoose.model('User', userSchema);
