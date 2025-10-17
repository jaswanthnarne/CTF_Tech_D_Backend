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
// PUBLIC ROUTES
// ==========================

// Health check
router.get('/health', (req, res) => {
  res.json({ 
    message: 'CTF service is running', 
    timestamp: new Date().toISOString() 
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

    res.json({
      ctfs,
      categories,
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

// Get single CTF
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

    // Calculate current status
    const currentStatus = ctf.calculateStatus();
    const isCurrentlyActive = ctf.isCurrentlyActive();
    
    res.json({ 
      ctf: {
        ...ctf.toObject(),
        currentStatus,
        isCurrentlyActive,
        canSubmit: ctf.canSubmit()
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

    res.json({ leaderboard });
  } catch (error) {
    console.error('Get global leaderboard error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================
// PROTECTED ROUTES (Require Auth)
// ==========================

// Join CTF - Fix validation
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

    console.log('🔍 Join CTF Validation:', {
      title: ctf.title,
      isVisible: ctf.isVisible,
      isPublished: ctf.isPublished,
      status: ctf.status,
      isCurrentlyActive: ctf.isCurrentlyActive(),
      currentTime: new Date().toLocaleTimeString(),
      activeHours: ctf.activeHours
    });

    // Enhanced validation for joining
    if (!ctf.isVisible || !ctf.isPublished) {
      return res.status(403).json({ 
        error: 'CTF is not available for joining',
        details: {
          isVisible: ctf.isVisible,
          isPublished: ctf.isPublished
        }
      });
    }

    // Check if CTF is currently active using the same method as status calculation
    const isActive = ctf.isCurrentlyActive();
    if (!isActive) {
      return res.status(403).json({ 
        error: `CTF is only active between ${ctf.activeHours.startTime} - ${ctf.activeHours.endTime}. Current time: ${new Date().toLocaleTimeString()}`,
        details: {
          activeHours: ctf.activeHours,
          currentTime: new Date().toLocaleTimeString(),
          backendStatus: ctf.status
        }
      });
    }

    // Check if already joined
    const alreadyJoined = ctf.participants.some(
      participant => participant.user.toString() === userId.toString()
    );

    if (alreadyJoined) {
      return res.status(400).json({ error: 'Already joined this CTF' });
    }

    // Add participant
    ctf.addParticipant(userId);
    await ctf.save();

    res.json({ 
      message: 'Successfully joined CTF', 
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        status: ctf.status,
        isCurrentlyActive: isActive
      }
    });
  } catch (error) {
    console.error('Join CTF error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Submit flag for CTF
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

    if (!ctf.isVisible) {
      return res.status(403).json({ error: 'CTF is not available' });
    }

    // Check if user has joined the CTF
    const hasJoined = ctf.participants.some(
      p => p.user.toString() === userId.toString()
    );

    if (!hasJoined) {
      return res.status(400).json({ error: 'You must join the CTF before submitting' });
    }

    try {
      // Submit flag using CTF method
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
          attempts: result.attempts
        });
      } else {
        return res.status(400).json({ 
          error: 'Incorrect flag', 
          solved: false,
          attempts: result.attempts,
          maxAttempts: result.maxAttempts
        });
      }
    } catch (submitError) {
      return res.status(400).json({ 
        error: submitError.message 
      });
    }
  } catch (error) {
    console.error('Submit flag error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user's CTF progress
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
      progress
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
      }
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

    res.json({ leaderboard });
  } catch (error) {
    console.error('Get CTF leaderboard error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
// Configure multer for memory storage
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
    .sort({ submittedAt: -1 }); // Get the latest submission

    if (!submission) {
      return res.status(404).json({ 
        error: 'No submission found for this CTF',
        submission: null 
      });
    }

    console.log('✅ Submission found:', submission._id);
    res.json({ 
      message: 'Submission found',
      submission 
    });
  } catch (error) {
    console.error('Get user submission error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Submit flag with screenshot
// In ctfRoutes.js - Update the submit-with-screenshot route validation
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

    console.log('📥 Received submission request:', {
      ctfId: id,
      userId: userId,
      hasFile: !!req.file,
      flag: flag,
      currentTime: new Date().toLocaleString()
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

    // Enhanced validation with detailed logging
    console.log('🔍 Backend Submission Validation:', {
      isVisible: ctf.isVisible,
      isPublished: ctf.isPublished,
      backendStatus: ctf.status,
      canSubmit: ctf.canSubmit(),
      isCurrentlyActive: ctf.isCurrentlyActive(),
      activeHours: ctf.activeHours,
      currentTime: new Date().toLocaleTimeString()
    });

    // If CTF is not visible or not published, cannot submit
    if (!ctf.isVisible || !ctf.isPublished) {
      return res.status(400).json({ 
        error: 'CTF is not available for submissions',
        details: {
          isVisible: ctf.isVisible,
          isPublished: ctf.isPublished
        }
      });
    }

    // If backend status is not active, cannot submit
    if (ctf.status?.toLowerCase() !== 'active') {
      return res.status(400).json({ 
        error: `CTF is ${ctf.status}. Submissions are not allowed.`,
        details: {
          backendStatus: ctf.status,
          requiredStatus: 'active'
        }
      });
    }

    // If backend status is active, check if within active hours using CTF method
    if (!ctf.isCurrentlyActive()) {
      return res.status(400).json({ 
        error: `CTF is only active between ${ctf.activeHours.startTime} - ${ctf.activeHours.endTime}. Current time: ${new Date().toLocaleTimeString()}`,
        details: {
          activeHours: ctf.activeHours,
          currentTime: new Date().toLocaleTimeString()
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

      // Submit flag using CTF method
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

      console.log('✅ Submission created successfully:', submission._id);
      res.json({ 
        message: 'Submission received! Your screenshot is pending admin review.', 
        submissionId: submission._id,
        submissionStatus: 'pending',
        attempts: result.attempts
      });
    } catch (submitError) {
      console.error('Submit flag error:', submitError);
      return res.status(400).json({ 
        error: submitError.message 
      });
    }
  } catch (error) {
    console.error('Submit with screenshot error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Edit submission (replace screenshot)
router.put('/submissions/:submissionId/screenshot', requireAuth, upload.single('screenshot'), async (req, res) => {
  try {
    const { submissionId } = req.params;
    const userId = req.user._id;

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

    // Check if CTF is still active
    if (!submission.ctf.canSubmit()) {
      return res.status(400).json({ 
        error: 'Cannot edit submission outside CTF active hours' 
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
      }
    });
  } catch (error) {
    console.error('Edit submission screenshot error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
module.exports = router;