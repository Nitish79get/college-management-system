require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');

// 1. DATABASE MODELS (Now includes AuditLog)
const { User, Complaint, AuditLog } = require('./models');

const app = express();

// 2. MIDDLEWARE
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(cors());
app.use('/uploads', express.static('uploads'));

// --- SECURITY MIDDLEWARE (NEW) ---
// This checks if the user has a valid token before letting them access routes
const verifyToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    try {
        // Remove "Bearer " if it exists
        const cleanToken = token.startsWith('Bearer ') ? token.slice(7, token.length) : token;
        const verified = jwt.verify(cleanToken, process.env.JWT_SECRET);
        req.user = verified; // Contains { id, role, department }
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid token.' });
    }
};

// 3. EMAIL TRANSPORTER
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// 4. MONGODB CONNECTION
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('MongoDB connection error:', err));


// ==========================================
// AUTHENTICATION ROUTES
// ==========================================

// SIGNUP (Supports 'super_admin' role creation if needed)
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { role, name, email, password, enrollmentNumber, department } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUserData = { role, name, email: email.toLowerCase(), password: hashedPassword };
        if (role === 'student') newUserData.enrollmentNumber = enrollmentNumber;
        if (role === 'admin') newUserData.department = department;

        const newUser = new User(newUserData);
        await newUser.save();
        
        res.status(201).json({ message: 'User created successfully', user: { _id: newUser._id, name: newUser.name, email: newUser.email, role: newUser.role } });
    } catch (error) {
        res.status(500).json({ error: 'Error creating user. Email might already exist.' });
    }
});

// LOGIN (Upgraded: Token now stores role and department for RBAC)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, role } = req.body;
        const user = await User.findOne({ email: email.toLowerCase(), role });
        if (!user) return res.status(404).json({ error: 'User not found' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

        // Include role and department in the token payload for security checks later
        const token = jwt.sign(
            { id: user._id, role: user.role, department: user.department }, 
            process.env.JWT_SECRET, 
            { expiresIn: '8h' }
        );
        res.json({ token, user: { _id: user._id, name: user.name, email: user.email, role: user.role, enrollmentNumber: user.enrollmentNumber, department: user.department } });
    } catch (error) {
        res.status(500).json({ error: 'Server error during login' });
    }
});

// FORGOT PASSWORD
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
        if (!user) return res.status(404).json({ error: "No account found with this email." });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.resetOTP = otp;
        user.resetOTPExpires = Date.now() + 600000; 
        await user.save();

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: "Your Password Reset OTP",
            text: `Your OTP is: ${otp}. It expires in 10 minutes.`
        });
        res.json({ message: "OTP sent! Check your Gmail." });
    } catch (error) {
        res.status(500).json({ error: "Failed to send email." });
    }
});

// RESET PASSWORD
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        const user = await User.findOne({ 
            email: { $regex: new RegExp(`^${email}$`, 'i') },
            resetOTP: otp,
            resetOTPExpires: { $gt: Date.now() }
        });

        if (!user) return res.status(400).json({ error: "Invalid or expired OTP." });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        user.resetOTP = undefined;
        user.resetOTPExpires = undefined;
        await user.save();

        res.json({ message: "Success! Password changed." });
    } catch (error) {
        res.status(500).json({ error: "Could not reset password." });
    }
});


// ==========================================
// COMPLAINT ROUTES (The Enterprise Upgrade)
// ==========================================

// Multer Configuration (Upgraded to allow multiple files up to 5)
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });


// 1. SUBMIT COMPLAINT (Student)
app.post('/api/complaints', verifyToken, upload.array('evidenceFiles', 5), async (req, res) => {
    try {
        const { department, category, subCategory, title, description, urgency, isAnonymous } = req.body;
        
        // Privacy Feature: Anonymity handling
        const anonFlag = isAnonymous === 'true';
        const studentName = anonFlag ? 'Anonymous Student' : req.body.studentName;
        const enrollmentNumber = anonFlag ? 'HIDDEN' : req.body.enrollmentNumber;

        // Extract file paths if uploaded
        const files = req.files ? req.files.map(f => `/uploads/${f.filename}`) : [];

        // Auto-Assignment Feature: Find an admin in this department
        const targetAdmin = await User.findOne({ role: 'admin', department: department });

        const newComplaint = new Complaint({
            studentId: req.user.id,
            studentName,
            enrollmentNumber,
            isAnonymous: anonFlag,
            department,
            category,
            subCategory,
            title,
            description,
            urgency: urgency || 'Medium',
            evidenceFiles: files,
            assignedTo: targetAdmin ? targetAdmin._id : null,
            status: 'Open'
        });

        // Initialize history
        newComplaint.history.push({
            action: 'Complaint Filed',
            performedBy: req.user.id
        });

        await newComplaint.save();
        res.status(201).json({ message: 'Complaint submitted!', complaintId: newComplaint._id });
    } catch (error) {
        console.error("Submission Error:", error);
        res.status(500).json({ error: 'Error submitting complaint' });
    }
});


// 2. GET STUDENT COMPLAINTS
app.get('/api/complaints/student', verifyToken, async (req, res) => {
    try {
        const complaints = await Complaint.find({ studentId: req.user.id })
            .sort({ createdAt: -1 })
            .populate('assignedTo', 'name'); // Gets the name of the admin handling it
        res.json(complaints);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching complaints' });
    }
});


// 3. ADMIN: GET COMPLAINTS (Role-Based Access Control)
// 3. ADMIN: GET COMPLAINTS (Role-Based Access Control)
app.get('/api/complaints', verifyToken, async (req, res) => {
    try {
        if (req.user.role === 'student') return res.status(403).json({ error: 'Access denied.' });

        let filter = {};
        
        // Smart Logic: If department is "All", the filter stays empty so they see everything!
        if (req.user.role === 'admin' && req.user.department !== 'All') {
            filter.department = req.user.department;
        }

        const complaints = await Complaint.find(filter)
            .sort({ createdAt: -1 })
            .populate('assignedTo', 'name')
            .populate('history.performedBy', 'name');
            
        res.json(complaints);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching all complaints' });
    }
});


// 4. ADMIN: UPDATE STATUS & LIFECYCLE
app.patch('/api/complaints/:id/status', verifyToken, async (req, res) => {
    try {
        if (req.user.role === 'student') return res.status(403).json({ error: 'Admins only.' });

        const { status, internalNote, adminReply } = req.body;
        const complaint = await Complaint.findById(req.params.id).populate('studentId');

        if (!complaint) return res.status(404).json({ error: 'Complaint not found.' });

        // Update core status
        if (status) {
            complaint.status = status;
            complaint.history.push({ action: `Status updated to ${status}`, performedBy: req.user.id });
        }

        // Add internal remarks (hidden from student)
        if (internalNote) {
            complaint.internalNotes.push({ note: internalNote, addedBy: req.user.id });
            complaint.history.push({ action: 'Internal note added', performedBy: req.user.id });
        }

        // Add official admin reply (visible to student)
        if (adminReply) {
            complaint.adminReply = adminReply;
            complaint.history.push({ action: 'Official reply sent to student', performedBy: req.user.id });
        }

        await complaint.save();

        // Security: Log this action in the Audit Log
        await AuditLog.create({
            adminId: req.user.id,
            action: `Modified complaint #${complaint._id}`,
            targetId: complaint._id
        });
        // --- NEW FEATURE: LIVE EMAIL NOTIFICATION ---
        // Send an email to the student if the status or reply changed
        if (complaint.studentId && complaint.studentId.email) {
            try {
                await transporter.sendMail({
                    from: process.env.EMAIL_USER,
                    to: complaint.studentId.email,
                    subject: `Portal Update: Complaint #${complaint._id.toString().slice(-6)}`,
                    html: `
                        <h3>Update on your Grievance</h3>
                        <p>Hello <b>${complaint.studentName}</b>,</p>
                        <p>There has been an update to your complaint: <i>"${complaint.title}"</i></p>
                        <p><b>New Status:</b> <span style="color: #764ba2;">${complaint.status}</span></p>
                        ${adminReply ? `<p><b>Official Admin Reply:</b> ${adminReply}</p>` : ''}
                        <p>Please log in to the Student Portal to view full details or leave feedback.</p>
                    `
                });
            } catch (emailErr) {
                console.error("Failed to send status email", emailErr);
            }
        }
        // --------------------------------------------
        res.json({ message: "Update successful", complaint });
    } catch (error) {
        res.status(500).json({ error: 'Error updating complaint' });
    }
});

// 5. STUDENT: SUBMIT FEEDBACK RATING
app.post('/api/complaints/:id/feedback', verifyToken, async (req, res) => {
    try {
        const { rating, comment } = req.body;
        const complaint = await Complaint.findById(req.params.id);

        if (complaint.studentId.toString() !== req.user.id) {
            return res.status(403).json({ error: 'You can only review your own complaints.' });
        }
        if (complaint.status !== 'Resolved' && complaint.status !== 'Closed') {
            return res.status(400).json({ error: 'Complaint must be resolved before rating.' });
        }

        complaint.feedback = { rating, comment };
        await complaint.save();

        res.json({ message: "Feedback submitted successfully." });
    } catch (error) {
        res.status(500).json({ error: 'Error submitting feedback.' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
module.exports = app;