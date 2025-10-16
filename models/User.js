const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    select: false
  },
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  role: {
    type: String,
    enum: ['student', 'admin'],
    default: 'student'
  },
  contactNumber: String,
  sem: {  // Changed from Sem to sem (lowercase)
    type: String,
    enum: ["3", "4", "5", "6", "7"],
    default: "7" 
  },
  erpNumber: {  // Changed from ErpNumber to erpNumber (lowercase)
    type: String,
    unique: true
  },
  specialization: {
    type: String,
    enum: ['Cybersecurity', 'Artificial Intelligence', 'Others'],
    default: 'Cybersecurity'
  },
  collegeName: String,
  expertiseLevel: {
    type: String,
    enum: ['Beginner', 'Junior', 'Intermediate', 'Senior', 'Expert'],
    default: 'Beginner'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  lastLogin: Date,
  lastSeen: Date,
  loginHistory: [{
    timestamp: Date,
    ipAddress: String,
    userAgent: String,
    location: String,
    logoutTime: Date,
    sessionDuration: Number
  }],
  passwordResetToken: String,
  passwordResetExpires: Date
}, {
  timestamps: true
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.toJSON = function() {
  const user = this.toObject();
  delete user.password;
  delete user.passwordResetToken;
  delete user.passwordResetExpires;
  return user;
};

module.exports = mongoose.model('User', userSchema);