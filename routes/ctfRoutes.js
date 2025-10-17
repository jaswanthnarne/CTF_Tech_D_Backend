const express = require('express');
const mongoose = require('mongoose');
const CTF = require('../models/CTF');
const Submission = require('../models/Submission');
const { requireAuth } = require('./authRoutes');
const { requireAdmin } = require('./adminRoutes');
const { uploadToCloudinary, deleteFromCloudinary } = require('../utils/cloudinary');
const multer = require('multer');

const { body, validationResult } = require('express-validator');

const router = express.Router();

// ==========================
// IST TIME HELPER FUNCTIONS
// ==========================

const getCurrentIST = () => {
  const now = new Date();
  const istOffset = 5.5 * 60 * 60 * 1000; // IST is UTC+5:30
  return new Date(now.getTime() + istOffset);
};

const getCurrentISTString = () => {
  const istTime = getCurrentIST();
  return `${istTime.getUTCHours().toString().padStart(2, '0')}:${istTime.getUTCMinutes().toString().padStart(2, '0')}`;
};

// ==========================
// MULTER CONFIGURATION
// ==========================

const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 4 * 1024 * 1024, // 4MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// ==========================
// PUBLIC ROUTES
// ==========================

// Health check with IST
router.get('/health', (req, res) => {
  const currentIST = getCurrentIST();
  res.json({ 
    message: 'CTF service is running', 
    timestamp: currentIST.toISOString(),
    timezone: 'IST (Asia/Kolkata)'
  });
});

// Get all CTFs with filtering
router.get('/ctfs', async (req, res) => {
  try {
    const { page = 1, limit = 10, status = 'all', category = 'all', search = '' } = req.query;
    
    let filter = { isVisible: true };
    
    if (status !== 'all') {
      filter.status = status;
    }
    
    if (category !== 'all') {
      filter.category = category;
    }

    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    const ctfs = await CTF.find(filter)
      .populate('createdBy', 'fullName email')
      .select('-flag -participants')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await CTF.countDocuments(filter);

    // Get unique categories for filter
    const categories = await CTF.distinct('category', { isVisible: true });

    // Add current IST time to response
    const currentIST = getCurrentISTString();

    res.json({
      ctfs,
      categories,
      currentIST,
      timezone: 'IST',
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get CTFs error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single CTF with IST info
router.get('/ctfs/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid CTF ID format' });
    }

    const ctf = await CTF.findById(id)
      .populate('createdBy', 'fullName email')
      .select('-flag');

    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    if (!ctf.isVisible) {
      return res.status(403).json({ error: 'CTF is not visible' });
    }

    // Calculate current status with IST
    const currentStatus = ctf.calculateStatus();
    const isCurrentlyActive = ctf.isCurrentlyActive();
    const currentIST = getCurrentISTString();
    
    res.json({ 
      ctf: {
        ...ctf.toObject(),
        currentStatus,
        isCurrentlyActive,
        canSubmit: ctf.canSubmit()
      },
      timeInfo: {
        currentIST,
        timezone: 'IST (Asia/Kolkata)'
      }
    });
  } catch (error) {
    console.error('Get CTF error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get global leaderboard
router.get('/leaderboard/global', async (req, res) => {
  try {
    const { limit = 100 } = req.query;

    const leaderboard = await Submission.aggregate([
      {
        $match: {
          isCorrect: true
        }
      },
      {
        $group: {
          _id: '$user',
          totalPoints: { $sum: '$points' },
          solveCount: { $sum: 1 },
          lastSolve: { $max: '$submittedAt' }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          'user.password': 0,
          'user.loginHistory': 0,
          'user.passwordResetToken': 0,
          'user.passwordResetExpires': 0
        }
      },
      {
        $sort: {
          totalPoints: -1,
          lastSolve: 1
        }
      },
      {
        $limit: parseInt(limit)
      }
    ]);

    res.json({ 
      leaderboard,
      timezone: 'IST',
      currentIST: getCurrentISTString()
    });
  } catch (error) {
    console.error('Get global leaderboard error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================
// PROTECTED ROUTES (Require Auth)
// ==========================

// Join CTF with IST validation
router.post('/ctfs/:id/join', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid CTF ID format' });
    }

    const ctf = await CTF.findById(id);
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    // Get current IST time for logging and validation
    const currentIST = getCurrentISTString();

    console.log('🔍 Join CTF Validation (IST):', {
      title: ctf.title,
      isVisible: ctf.isVisible,
      isPublished: ctf.isPublished,
      status: ctf.status,
      isCurrentlyActive: ctf.isCurrentlyActive(),
      currentIST: currentIST,
      activeHours: ctf.activeHours,
      timezone: ctf.activeHours.timezone
    });

    // Enhanced validation for joining
    if (!ctf.isVisible || !ctf.isPublished) {
      return res.status(403).json({ 
        error: 'CTF is not available for joining',
        details: {
          isVisible: ctf.isVisible,
          isPublished: ctf.isPublished,
          currentIST: currentIST
        }
      });
    }

    // Check if CTF is currently active using IST
    const isActive = ctf.isCurrentlyActive();
    if (!isActive) {
      return res.status(403).json({ 
        error: `CTF is only active between ${ctf.activeHours.startTime} - ${ctf.activeHours.endTime} IST. Current time: ${currentIST} IST`,
        details: {
          activeHours: ctf.activeHours,
          currentIST: currentIST,
          backendStatus: ctf.status,
          isCurrentlyActive: ctf.isCurrentlyActive(),
          timezone: 'IST (Asia/Kolkata)'
        }
      });
    }

    // Check if already joined
    const alreadyJoined = ctf.participants.some(
      participant => participant.user.toString() === userId.toString()
    );

    if (alreadyJoined) {
      return res.status(400).json({ 
        error: 'Already joined this CTF',
        details: {
          ctfId: ctf._id,
          ctfTitle: ctf.title
        }
      });
    }

    // Add participant to CTF
    ctf.addParticipant(userId);
    await ctf.save();

    console.log('✅ CTF Joined Successfully (IST):', {
      ctfId: ctf._id,
      ctfTitle: ctf.title,
      userId: userId,
      joinedAt: new Date().toISOString(),
      currentIST: currentIST,
      activeHours: ctf.activeHours
    });

    res.json({ 
      message: 'Successfully joined CTF', 
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        status: ctf.status,
        isCurrentlyActive: isActive,
        activeHours: ctf.activeHours,
        timezone: 'IST (Asia/Kolkata)',
        joinedAt: new Date()
      },
      timeInfo: {
        currentIST: currentIST,
        serverTime: new Date().toISOString(),
        timezone: 'IST'
      }
    });
  } catch (error) {
    console.error('❌ Join CTF error:', error);
    
    // Get current IST time for error logging
    const currentIST = getCurrentISTString();
    
    console.error('❌ Join CTF Error Details (IST):', {
      error: error.message,
      currentIST: currentIST,
      timestamp: new Date().toISOString()
    });

    if (error.name === 'CastError') {
      return res.status(400).json({ error: 'Invalid CTF ID format' });
    }
    
    res.status(500).json({ 
      error: 'Server error while joining CTF',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Submit flag for CTF with IST validation
router.post('/ctfs/:id/submit', requireAuth, [
  body('flag').notEmpty().withMessage('Flag is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { id } = req.params;
    const { flag, screenshot } = req.body;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid CTF ID format' });
    }

    const ctf = await CTF.findById(id);
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    // Get current IST for logging
    const currentIST = getCurrentISTString();

    console.log('🔍 Submit Flag Validation (IST):', {
      title: ctf.title,
      isVisible: ctf.isVisible,
      isPublished: ctf.isPublished,
      status: ctf.status,
      isCurrentlyActive: ctf.isCurrentlyActive(),
      currentIST: currentIST,
      timezone: 'IST'
    });

    if (!ctf.isVisible) {
      return res.status(403).json({ 
        error: 'CTF is not available',
        details: { currentIST }
      });
    }

    // Check if user has joined the CTF
    const hasJoined = ctf.participants.some(
      p => p.user.toString() === userId.toString()
    );

    if (!hasJoined) {
      return res.status(400).json({ error: 'You must join the CTF before submitting' });
    }

    try {
      // Submit flag using CTF method (includes IST validation)
      const result = ctf.submitFlag(userId, flag, screenshot);
      
      // Create submission record
      const submission = new Submission({
        user: userId,
        ctf: id,
        flag,
        isCorrect: result.isCorrect,
        points: result.points,
        screenshot: screenshot || null,
        ipAddress: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
        userAgent: req.headers['user-agent'],
        attemptNumber: result.attempts
      });

      await submission.save();
      await ctf.save();

      if (result.isCorrect) {
        return res.json({ 
          message: 'Correct flag! CTF solved.', 
          points: result.points,
          solved: true,
          submissionId: submission._id,
          attempts: result.attempts,
          currentIST: currentIST
        });
      } else {
        return res.status(400).json({ 
          error: 'Incorrect flag', 
          solved: false,
          attempts: result.attempts,
          maxAttempts: result.maxAttempts,
          currentIST: currentIST
        });
      }
    } catch (submitError) {
      return res.status(400).json({ 
        error: submitError.message,
        currentIST: getCurrentISTString()
      });
    }
  } catch (error) {
    console.error('Submit flag error:', error);
    res.status(500).json({ 
      error: 'Server error',
      currentIST: getCurrentISTString()
    });
  }
});

// Get user's CTF progress with IST info
router.get('/ctfs/:id/progress', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid CTF ID format' });
    }

    const ctf = await CTF.findById(id)
      .select('title description category points difficulty status activeHours schedule participants rules');

    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    // Find user's participation
    const participation = ctf.participants.find(
      p => p.user.toString() === userId.toString()
    );

    // Get user's submissions for this CTF
    const submissions = await Submission.find({
      user: userId,
      ctf: id
    }).sort({ submittedAt: -1 });

    const progress = {
      hasJoined: !!participation,
      isSolved: participation ? participation.isCorrect : false,
      pointsEarned: participation ? participation.pointsEarned : 0,
      attempts: participation ? participation.attempts : 0,
      maxAttempts: ctf.maxAttempts,
      submittedAt: participation ? participation.submittedAt : null,
      submissions: submissions,
      canSubmit: ctf.canSubmit() && (!participation?.isCorrect || ctf.rules.allowMultipleSubmissions)
    };

    res.json({
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        description: ctf.description,
        category: ctf.category,
        points: ctf.points,
        difficulty: ctf.difficulty,
        status: ctf.status,
        activeHours: ctf.activeHours,
        schedule: ctf.schedule,
        isCurrentlyActive: ctf.isCurrentlyActive(),
        rules: ctf.rules
      },
      progress,
      timeInfo: {
        currentIST: getCurrentISTString(),
        timezone: 'IST'
      }
    });
  } catch (error) {
    console.error('Get CTF progress error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user's submission history
router.get('/my-submissions', requireAuth, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;

    const submissions = await Submission.find({ user: req.user._id })
      .populate('ctf', 'title category points')
      .sort({ submittedAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .select('-ipAddress -userAgent');

    const total = await Submission.countDocuments({ user: req.user._id });

    res.json({
      submissions,
      currentIST: getCurrentISTString(),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get submissions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check if user has joined CTF
router.get('/ctfs/:id/joined', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid CTF ID format' });
    }

    const ctf = await CTF.findById(id);
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    const hasJoined = ctf.participants.some(
      participant => participant.user.toString() === userId.toString()
    );

    res.json({ 
      joined: hasJoined,
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        status: ctf.status,
        isCurrentlyActive: ctf.isCurrentlyActive()
      },
      currentIST: getCurrentISTString()
    });
  } catch (error) {
    console.error('Check CTF join status error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get CTF leaderboard
router.get('/ctfs/:id/leaderboard', async (req, res) => {
  try {
    const { id } = req.params;
    const { limit = 50 } = req.query;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid CTF ID format' });
    }

    const leaderboard = await Submission.aggregate([
      {
        $match: {
          ctf: new mongoose.Types.ObjectId(id),
          isCorrect: true
        }
      },
      {
        $group: {
          _id: '$user',
          points: { $max: '$points' },
          submittedAt: { $min: '$submittedAt' }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          'user.password': 0,
          'user.loginHistory': 0,
          'user.passwordResetToken': 0,
          'user.passwordResetExpires': 0
        }
      },
      {
        $sort: {
          points: -1,
          submittedAt: 1
        }
      },
      {
        $limit: parseInt(limit)
      }
    ]);

    res.json({ 
      leaderboard,
      currentIST: getCurrentISTString()
    });
  } catch (error) {
    console.error('Get CTF leaderboard error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================
// SCREENSHOT SUBMISSION ROUTES
// ==========================

// Get user's submission for a specific CTF
router.get('/ctfs/:id/my-submission', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;

    console.log('🔍 Fetching submission for CTF:', id, 'User:', userId);

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid CTF ID format' });
    }

    const submission = await Submission.findOne({
      user: userId,
      ctf: id
    })
    .populate('ctf', 'title category points activeHours schedule')
    .populate('reviewedBy', 'fullName email')
    .sort({ submittedAt: -1 });

    if (!submission) {
      return res.status(404).json({ 
        error: 'No submission found for this CTF',
        submission: null 
      });
    }

    console.log('✅ Submission found:', submission._id);
    res.json({ 
      message: 'Submission found',
      submission,
      currentIST: getCurrentISTString()
    });
  } catch (error) {
    console.error('Get user submission error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Submit flag with screenshot (IST validated)
router.post('/ctfs/:id/submit-with-screenshot', requireAuth, upload.single('screenshot'), [
  body('flag').notEmpty().withMessage('Flag is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { id } = req.params;
    const { flag } = req.body;
    const userId = req.user._id;

    const currentIST = getCurrentISTString();

    console.log('📥 Received submission request (IST):', {
      ctfId: id,
      userId: userId,
      hasFile: !!req.file,
      flag: flag,
      currentIST: currentIST
    });

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid CTF ID format' });
    }

    // Check if screenshot is provided
    if (!req.file) {
      return res.status(400).json({ error: 'Screenshot is required' });
    }

    const ctf = await CTF.findById(id);
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    // Enhanced validation with IST logging
    console.log('🔍 Backend Submission Validation (IST):', {
      isVisible: ctf.isVisible,
      isPublished: ctf.isPublished,
      backendStatus: ctf.status,
      canSubmit: ctf.canSubmit(),
      isCurrentlyActive: ctf.isCurrentlyActive(),
      activeHours: ctf.activeHours,
      currentIST: currentIST,
      timezone: 'IST'
    });

    // If CTF is not visible or not published, cannot submit
    if (!ctf.isVisible || !ctf.isPublished) {
      return res.status(400).json({ 
        error: 'CTF is not available for submissions',
        details: {
          isVisible: ctf.isVisible,
          isPublished: ctf.isPublished,
          currentIST: currentIST
        }
      });
    }

    // If backend status is not active, cannot submit
    if (ctf.status?.toLowerCase() !== 'active') {
      return res.status(400).json({ 
        error: `CTF is ${ctf.status}. Submissions are not allowed.`,
        details: {
          backendStatus: ctf.status,
          requiredStatus: 'active',
          currentIST: currentIST
        }
      });
    }

    // If backend status is active, check if within active hours using CTF method (IST)
    if (!ctf.isCurrentlyActive()) {
      return res.status(400).json({ 
        error: `CTF is only active between ${ctf.activeHours.startTime} - ${ctf.activeHours.endTime} IST. Current time: ${currentIST} IST`,
        details: {
          activeHours: ctf.activeHours,
          currentIST: currentIST,
          timezone: 'IST (Asia/Kolkata)'
        }
      });
    }

    // Check if user has joined the CTF
    const hasJoined = ctf.participants.some(
      p => p.user.toString() === userId.toString()
    );

    if (!hasJoined) {
      return res.status(400).json({ error: 'You must join the CTF before submitting' });
    }

    // Check if user already has a pending submission
    const existingPendingSubmission = await Submission.findOne({
      user: userId,
      ctf: id,
      submissionStatus: 'pending'
    });

    if (existingPendingSubmission) {
      return res.status(400).json({ 
        error: 'You already have a pending submission for this CTF. Please wait for admin review or edit your existing submission.' 
      });
    }

    try {
      // Upload screenshot to Cloudinary
      const uploadResult = await uploadToCloudinary(req.file.buffer, `ctf-${id}`);

      // Submit flag using CTF method (includes IST validation)
      const result = ctf.submitFlag(userId, flag);
      
      // Create submission record with screenshot
      const submission = new Submission({
        user: userId,
        ctf: id,
        flag,
        isCorrect: result.isCorrect,
        points: result.points,
        screenshot: {
          public_id: uploadResult.public_id,
          url: uploadResult.secure_url,
          filename: req.file.originalname,
          size: req.file.size
        },
        submissionStatus: 'pending', // Always starts as pending for screenshot submissions
        ipAddress: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
        userAgent: req.headers['user-agent'],
        attemptNumber: result.attempts
      });

      await submission.save();
      
      // Update CTF participant to mark as having pending submission
      ctf.updateParticipantSubmissionStatus(userId, true);
      await ctf.save();

      console.log('✅ Submission created successfully (IST):', {
        submissionId: submission._id,
        currentIST: currentIST
      });

      res.json({ 
        message: 'Submission received! Your screenshot is pending admin review.', 
        submissionId: submission._id,
        submissionStatus: 'pending',
        attempts: result.attempts,
        currentIST: currentIST
      });
    } catch (submitError) {
      console.error('Submit flag error:', submitError);
      return res.status(400).json({ 
        error: submitError.message,
        currentIST: currentIST
      });
    }
  } catch (error) {
    console.error('Submit with screenshot error:', error);
    res.status(500).json({ 
      error: 'Server error',
      currentIST: getCurrentISTString()
    });
  }
});

// Edit submission (replace screenshot) with IST validation
router.put('/submissions/:submissionId/screenshot', requireAuth, upload.single('screenshot'), async (req, res) => {
  try {
    const { submissionId } = req.params;
    const userId = req.user._id;

    const currentIST = getCurrentISTString();

    if (!mongoose.Types.ObjectId.isValid(submissionId)) {
      return res.status(400).json({ error: 'Invalid submission ID format' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'New screenshot is required' });
    }

    const submission = await Submission.findById(submissionId)
      .populate('ctf');
    
    if (!submission) {
      return res.status(404).json({ error: 'Submission not found' });
    }

    // Check if user owns the submission
    if (submission.user.toString() !== userId.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Check if submission is still pending
    if (submission.submissionStatus !== 'pending') {
      return res.status(400).json({ 
        error: 'Cannot edit submission that has already been reviewed' 
      });
    }

    // Check if CTF is still active using IST
    if (!submission.ctf.canSubmit()) {
      return res.status(400).json({ 
        error: `Cannot edit submission outside CTF active hours. Current time: ${currentIST} IST`,
        details: {
          activeHours: submission.ctf.activeHours,
          currentIST: currentIST
        }
      });
    }

    // Delete old screenshot from Cloudinary
    if (submission.screenshot && submission.screenshot.public_id) {
      try {
        await deleteFromCloudinary(submission.screenshot.public_id);
      } catch (deleteError) {
        console.error('Error deleting old screenshot:', deleteError);
        // Continue with upload even if delete fails
      }
    }

    // Upload new screenshot to Cloudinary
    const uploadResult = await uploadToCloudinary(
      req.file.buffer, 
      `ctf-${submission.ctf._id}`
    );

    // Update submission with new screenshot
    submission.screenshot = {
      public_id: uploadResult.public_id,
      url: uploadResult.secure_url,
      filename: req.file.originalname,
      size: req.file.size,
      uploadedAt: new Date()
    };

    submission.submittedAt = new Date(); // Update submission time
    await submission.save();

    res.json({ 
      message: 'Screenshot updated successfully!',
      submission: {
        _id: submission._id,
        submissionStatus: submission.submissionStatus,
        screenshot: submission.screenshot
      },
      currentIST: currentIST
    });
  } catch (error) {
    console.error('Edit submission screenshot error:', error);
    res.status(500).json({ 
      error: 'Server error',
      currentIST: getCurrentISTString()
    });
  }
});

module.exports = router;