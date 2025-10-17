const mongoose = require('mongoose');

const ctfSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  category: {
    type: String,
    required: true,
    enum: ['Web Security', 'Cryptography', 'Forensics', 'Reverse Engineering', 'Pwn', 'Misc']
  },
  points: {
    type: Number,
    required: true,
    min: 0
  },
  difficulty: {
    type: String,
    enum: ['Easy', 'Medium', 'Hard', 'Expert'],
    default: 'Easy'
  },
  // Active hours configuration - IST TIMEZONE
  activeHours: {
    startTime: {
      type: String, // Format: "HH:MM" 24-hour IST format
      required: true
    },
    endTime: {
      type: String, // Format: "HH:MM" 24-hour IST format
      required: true
    },
    timezone: {
      type: String,
      default: 'Asia/Kolkata' // Force IST timezone
    }
  },
  // Schedule configuration - Dates stored in IST
  schedule: {
    startDate: {
      type: Date,
      required: true
    },
    endDate: {
      type: Date,
      required: true
    },
    recurrence: {
      type: String,
      enum: ['once', 'daily', 'weekly', 'monthly'],
      default: 'once'
    }
  },
  ctfLink: {
    type: String,
    default: ''
  },
  // CTF status and visibility
  isVisible: {
    type: Boolean,
    default: false
  },
  isPublished: {
    type: Boolean,
    default: false
  },
  status: {
    type: String,
    enum: ['upcoming', 'active', 'ended', 'inactive'],
    default: 'upcoming'
  },
  // Participants and submissions
  participants: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    joinedAt: {
      type: Date,
      default: Date.now
    },
    submittedAt: Date,
    isCorrect: {
      type: Boolean,
      default: false
    },
    pointsEarned: {
      type: Number,
      default: 0
    },
    attempts: {
      type: Number,
      default: 0
    },
    hasPendingSubmission: {
      type: Boolean,
      default: false
    }
  }],
  totalSubmissions: {
    type: Number,
    default: 0
  },
  correctSubmissions: {
    type: Number,
    default: 0
  },
  // Additional CTF configuration
  maxAttempts: {
    type: Number,
    default: 1
  },
  hints: [{
    text: String,
    cost: { type: Number, default: 0 }
  }],
  files: [{
    filename: String,
    url: String,
    size: Number
  }],
  rules: {
    requireScreenshot: {
      type: Boolean,
      default: false
    },
    allowMultipleSubmissions: {
      type: Boolean,
      default: false
    }
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin',
    required: true
  }
}, { 
  timestamps: true 
});

// ==========================
// IST TIME HELPER FUNCTIONS
// ==========================

// Get current IST time
ctfSchema.methods.getCurrentIST = function() {
  const now = new Date();
  const istOffset = 5.5 * 60 * 60 * 1000; // IST is UTC+5:30
  return new Date(now.getTime() + istOffset);
};

// Get current IST time string (HH:MM format)
ctfSchema.methods.getCurrentISTString = function() {
  const istTime = this.getCurrentIST();
  return `${istTime.getUTCHours().toString().padStart(2, '0')}:${istTime.getUTCMinutes().toString().padStart(2, '0')}`;
};
// Convert date to IST
const convertToIST = (date) => {
  if (!date) return null;
  return new Date(date.getTime() + (5.5 * 60 * 60 * 1000));
};

// ==========================
// CORE CTF STATUS METHODS
// ==========================

// Check if CTF is currently active based on IST time
ctfSchema.methods.isCurrentlyActive = function() {
  const currentIST = getCurrentIST();
  const currentISTString = getCurrentISTString();
  
  console.log('🔍 Backend Active Hours Check (IST):', {
    title: this.title,
    startTime: this.activeHours.startTime,
    endTime: this.activeHours.endTime,
    currentIST: currentISTString,
    scheduleStart: this.schedule.startDate,
    scheduleEnd: this.schedule.endDate
  });

  // First check if we're within the schedule dates
  const scheduleStartIST = convertToIST(this.schedule.startDate);
  const scheduleEndIST = convertToIST(this.schedule.endDate);
  
  if (currentIST < scheduleStartIST || currentIST > scheduleEndIST) {
    console.log('❌ Outside schedule dates');
    return false;
  }

  // Now check active hours
  const [startHours, startMinutes] = this.activeHours.startTime.split(':').map(Number);
  const [endHours, endMinutes] = this.activeHours.endTime.split(':').map(Number);

  // Use IST time for comparison
  const currentMinutes = currentIST.getUTCHours() * 60 + currentIST.getUTCMinutes();
  const startMinutesTotal = startHours * 60 + startMinutes;
  const endMinutesTotal = endHours * 60 + endMinutes;

  console.log('📊 IST Time Comparison:', {
    currentMinutes,
    startMinutesTotal,
    endMinutesTotal,
    currentISTTime: currentISTString
  });

  // Handle case where active hours cross midnight
  let isActive;
  if (endMinutesTotal < startMinutesTotal) {
    // Active hours cross midnight (e.g., 22:00 - 06:00)
    isActive = currentMinutes >= startMinutesTotal || currentMinutes <= endMinutesTotal;
  } else {
    // Normal case (e.g., 09:00 - 18:00)
    isActive = currentMinutes >= startMinutesTotal && currentMinutes <= endMinutesTotal;
  }

  console.log('✅ Backend Active Status (IST):', isActive);
  return isActive;
};

// Enhanced status calculation with proper IST handling
ctfSchema.methods.calculateStatus = function() {
  const currentIST = getCurrentIST();
  const currentISTString = getCurrentISTString();
  
  console.log('🔍 Enhanced CTF Status Calculation (IST):', {
    title: this.title,
    currentIST: currentISTString,
    startTime: this.activeHours.startTime,
    endTime: this.activeHours.endTime,
    scheduleStart: this.schedule.startDate,
    scheduleEnd: this.schedule.endDate,
    isVisible: this.isVisible,
    isPublished: this.isPublished
  });
  
  // Manual override checks first
  if (!this.isVisible || !this.isPublished) {
    return 'inactive';
  }
  
  // Convert schedule dates to IST for comparison
  const scheduleStartIST = convertToIST(this.schedule.startDate);
  const scheduleEndIST = convertToIST(this.schedule.endDate);
  
  // Schedule date checks (using IST)
  if (currentIST < scheduleStartIST) {
    return 'upcoming';
  }
  
  if (currentIST > scheduleEndIST) {
    return 'ended';
  }
  
  // Active hours check with IST
  const isActiveHours = this.isCurrentlyActive();
  
  return isActiveHours ? 'active' : 'inactive_hours';
};

// Check if user can submit to this CTF
ctfSchema.methods.canSubmit = function() {
  const currentIST = getCurrentISTString();
  
  console.log('🔍 canSubmit Check (IST):', {
    title: this.title,
    isVisible: this.isVisible,
    isPublished: this.isPublished,
    status: this.status,
    isCurrentlyActive: this.isCurrentlyActive(),
    currentIST: currentIST
  });

  // Check if CTF is visible, published, and active
  if (!this.isVisible || !this.isPublished) {
    console.log('❌ Cannot submit: CTF not visible or not published');
    return false;
  }

  // Use backend status as primary check
  if (this.status?.toLowerCase() !== 'active') {
    console.log('❌ Cannot submit: Backend status is', this.status);
    return false;
  }

  // Then check active hours using IST
  const isActive = this.isCurrentlyActive();
  console.log('✅ Backend canSubmit result:', isActive);
  return isActive;
};
// ==========================
// PARTICIPANT MANAGEMENT
// ==========================

// Add participant to CTF
ctfSchema.methods.addParticipant = function(userId) {
  const existingParticipant = this.participants.find(
    p => p.user.toString() === userId.toString()
  );
  
  if (!existingParticipant) {
    this.participants.push({
      user: userId,
      joinedAt: new Date(),
      attempts: 0,
      isCorrect: false,
      pointsEarned: 0,
      hasPendingSubmission: false
    });
    
    console.log('✅ Participant added to CTF:', {
      ctfId: this._id,
      ctfTitle: this.title,
      userId: userId,
      totalParticipants: this.participants.length,
      joinedAt: new Date().toISOString()
    });
  } else {
    console.log('ℹ️ User already participant:', {
      ctfId: this._id,
      userId: userId
    });
  }
  
  return this;
};

// Check if user has pending submission
ctfSchema.methods.hasPendingSubmission = function(userId) {
  return this.participants.some(p => 
    p.user.toString() === userId.toString() && 
    p.hasPendingSubmission
  );
};

// Update participant submission status
ctfSchema.methods.updateParticipantSubmissionStatus = function(userId, hasPending) {
  const participant = this.participants.find(p => 
    p.user.toString() === userId.toString()
  );
  
  if (participant) {
    participant.hasPendingSubmission = hasPending;
    console.log('📝 Updated participant submission status:', {
      ctfId: this._id,
      userId: userId,
      hasPendingSubmission: hasPending
    });
  }
  
  return this;
};

// ==========================
// SUBMISSION MANAGEMENT
// ==========================

// Submit flag with IST validation
ctfSchema.methods.submitFlag = function(userId, flag, screenshot = null) {
  const participant = this.participants.find(
    p => p.user.toString() === userId.toString()
  );
  
  if (!participant) {
    throw new Error('User is not a participant of this CTF');
  }
  
  const currentIST = this.getCurrentISTString();
  
  // Enhanced validation with IST logging
  console.log('🔍 submitFlag - Validation Check (IST):', {
    title: this.title,
    isVisible: this.isVisible,
    isPublished: this.isPublished,
    status: this.status,
    isCurrentlyActive: this.isCurrentlyActive(),
    canSubmit: this.canSubmit(),
    activeHours: this.activeHours,
    currentIST: currentIST,
    timezone: 'Asia/Kolkata'
  });

  // Direct validation instead of relying on canSubmit()
  if (!this.isVisible || !this.isPublished) {
    throw new Error('CTF is not available for submissions');
  }

  if (this.status?.toLowerCase() !== 'active') {
    throw new Error(`CTF is ${this.status}. Submissions are not allowed.`);
  }

  if (!this.isCurrentlyActive()) {
    throw new Error(`CTF is only active between ${this.activeHours.startTime} - ${this.activeHours.endTime} IST. Current time: ${currentIST} IST`);
  }

  if (participant.attempts >= this.maxAttempts && !this.rules.allowMultipleSubmissions) {
    throw new Error('Maximum attempts reached');
  }
  
  participant.attempts += 1;
  participant.submittedAt = new Date();
  
  // Compare with the actual flag
  const isCorrect = flag === this.flag;
  
  if (isCorrect) {
    participant.isCorrect = true;
    participant.pointsEarned = this.points;
    this.correctSubmissions += 1;
  }
  
  this.totalSubmissions += 1;
  
  console.log('✅ Flag submission result:', {
    ctfId: this._id,
    userId: userId,
    isCorrect: isCorrect,
    attempts: participant.attempts,
    currentIST: currentIST
  });
  
  return {
    isCorrect,
    points: isCorrect ? this.points : 0,
    attempts: participant.attempts,
    maxAttempts: this.maxAttempts
  };
};

// ==========================
// ADMIN MANAGEMENT METHODS
// ==========================

// Force status update (admin override)
ctfSchema.methods.forceStatusUpdate = function(status) {
  const currentIST = this.getCurrentISTString();
  
  console.log('🔄 Force status update (IST):', {
    from: this.status,
    to: status,
    title: this.title,
    currentIST: currentIST
  });
  
  this.status = status;
  
  // Adjust visibility based on forced status
  if (status === 'active' || status === 'upcoming') {
    this.isVisible = true;
    this.isPublished = true;
  } else if (status === 'ended' || status === 'inactive') {
    this.isVisible = false;
  }
  
  return this;
};

// Toggle activation with proper status calculation
ctfSchema.methods.toggleActivation = async function() {
  const currentIST = this.getCurrentISTString();
  
  this.isVisible = !this.isVisible;
  
  if (this.isVisible) {
    // When activating, recalculate status based on IST timing
    this.status = this.calculateStatus();
  } else {
    // When deactivating, set to inactive
    this.status = 'inactive';
  }
  
  console.log('🔧 Toggle activation (IST):', {
    title: this.title,
    isVisible: this.isVisible,
    newStatus: this.status,
    currentIST: currentIST
  });
  
  await this.save();
  return this;
};

// Update CTF status
ctfSchema.methods.updateStatus = async function() {
  const newStatus = this.calculateStatus();
  
  if (this.status !== newStatus) {
    console.log('🔄 Auto-updating CTF status:', {
      title: this.title,
      from: this.status,
      to: newStatus,
      currentIST: this.getCurrentISTString()
    });
    this.status = newStatus;
    await this.save();
  }
  
  return this;
};



// CTF lifecycle automation
ctfSchema.statics.manageCTFLifecycle = async function() {
  const now = new Date();
  const ctfs = await this.find({
    $or: [
      { 'schedule.startDate': { $lte: now } },
      { 'schedule.endDate': { $lte: now } },
      { status: { $in: ['active', 'upcoming'] } }
    ]
  });

  let updated = 0;
  let ended = 0;

  for (const ctf of ctfs) {
    const oldStatus = ctf.status;
    const newStatus = ctf.calculateStatus();

    if (oldStatus !== newStatus) {
      ctf.status = newStatus;
      
      // Log status changes
      if (newStatus === 'ended') {
        console.log('🏁 CTF ended:', {
          title: ctf.title,
          endedAt: new Date().toISOString(),
          IST: getCurrentISTString()
        });
        ended++;
      }
      
      await ctf.save();
      updated++;
    }
  }

  return { updated, ended };
};
// ==========================
// ANALYTICS METHODS
// ==========================

// Enhanced analytics method
ctfSchema.methods.getAnalytics = function() {
  const participants = this.participants || [];
  const correctSubmissions = participants.filter(p => p.isCorrect).length;
  const totalSubmissions = this.totalSubmissions || 0;
  
  return {
    basic: {
      title: this.title,
      category: this.category,
      difficulty: this.difficulty,
      points: this.points,
      status: this.status,
      totalParticipants: participants.length,
      correctSubmissions,
      totalSubmissions,
      successRate: totalSubmissions > 0 ? 
        Math.round((correctSubmissions / totalSubmissions) * 100) : 0,
      averageAttempts: participants.length > 0 ? 
        (participants.reduce((sum, p) => sum + (p.attempts || 0), 0) / participants.length).toFixed(1) : 0
    },
    participants: participants.map(p => ({
      user: p.user,
      joinedAt: p.joinedAt,
      submittedAt: p.submittedAt,
      isCorrect: p.isCorrect,
      pointsEarned: p.pointsEarned,
      attempts: p.attempts
    })),
    timing: {
      activeHours: this.activeHours,
      schedule: {
        startDate: this.schedule.startDate,
        endDate: this.schedule.endDate,
        startDateIST: this.schedule.startDate.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
        endDateIST: this.schedule.endDate.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })
      },
      currentStatus: this.isCurrentlyActive() ? 'Active' : 'Inactive',
      currentIST: this.getCurrentISTString(),
      timezone: 'Asia/Kolkata'
    },
    performance: {
      completionRate: participants.length > 0 ? 
        Math.round((correctSubmissions / participants.length) * 100) : 0,
      averageTimeToSolve: this.calculateAverageSolveTime?.() || 'N/A'
    }
  };
};

// Calculate average solve time
ctfSchema.methods.calculateAverageSolveTime = function() {
  const correctParticipants = this.participants.filter(p => p.isCorrect && p.joinedAt && p.submittedAt);
  
  if (correctParticipants.length === 0) return 'N/A';
  
  const totalTime = correctParticipants.reduce((sum, p) => {
    const solveTime = new Date(p.submittedAt) - new Date(p.joinedAt);
    return sum + solveTime;
  }, 0);
  
  const averageMs = totalTime / correctParticipants.length;
  const minutes = Math.floor(averageMs / (1000 * 60));
  const hours = Math.floor(minutes / 60);
  
  if (hours > 0) {
    return `${hours}h ${minutes % 60}m`;
  }
  return `${minutes}m`;
};

// ==========================
// STATIC METHODS
// ==========================

// Static method to update all CTF statuses using IST
ctfSchema.statics.updateAllStatuses = async function() {
  const ctfs = await this.find();
  let updated = 0;
  
  for (const ctf of ctfs) {
    const newStatus = ctf.calculateStatus();
    if (ctf.status !== newStatus) {
      ctf.status = newStatus;
      await ctf.save();
      updated++;
    }
  }
  
  console.log('🔄 Batch status update completed:', {
    totalCTFs: ctfs.length,
    updated: updated,
    currentIST: new Date(new Date().getTime() + 5.5 * 60 * 60 * 1000).toISOString()
  });
  
  return { updated };
};

// ==========================
// MIDDLEWARE
// ==========================

// Pre-save middleware to auto-calculate status with IST
ctfSchema.pre('save', function(next) {
  const currentIST = this.getCurrentISTString();
  
  console.log('💾 Pre-save middleware triggered (IST):', {
    title: this.title,
    currentIST: currentIST
  });
  
  // Always calculate status, but respect manual inactive setting
  const newStatus = this.calculateStatus();
  
  // Only update status if it's different and CTF is visible
  if (this.status !== newStatus) {
    console.log('🔄 Status changed:', {
      from: this.status,
      to: newStatus,
      isVisible: this.isVisible,
      currentIST: currentIST
    });
    this.status = newStatus;
  } else {
    console.log('✅ Status unchanged:', this.status);
  }
  
  next();
});

// ==========================
// INDEXES
// ==========================

ctfSchema.index({ 'schedule.startDate': 1, 'schedule.endDate': 1 });
ctfSchema.index({ status: 1 });
ctfSchema.index({ isVisible: 1, isPublished: 1 });
ctfSchema.index({ category: 1 });
ctfSchema.index({ difficulty: 1 });
ctfSchema.index({ 'participants.user': 1 });

module.exports = mongoose.model('CTF', ctfSchema);