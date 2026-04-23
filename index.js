// models/index.js
const mongoose = require('mongoose');

// ==========================================
// 1. USER SCHEMA (Now with RBAC)
// ==========================================
const UserSchema = new mongoose.Schema({
    // Added 'super_admin' for Role-Based Access Control (RBAC)
    role: { type: String, enum: ['student', 'admin', 'super_admin'], required: true },
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }, 
    
    // Student specifics
    enrollmentNumber: { type: String, sparse: true },
    
    // Admin specifics (Super Admins won't need a specific department)
    department: { type: String, sparse: true },

    // Password Reset Fields
    resetOTP: { type: String },
    resetOTPExpires: { type: Date }
}, { timestamps: true });


// ==========================================
// 2. COMPLAINT SCHEMA (The Enterprise Upgrade)
// ==========================================
const ComplaintSchema = new mongoose.Schema({
    // --- Core Info ---
    studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    studentName: { type: String, required: true },
    enrollmentNumber: { type: String, required: true },
    
    // Privacy Feature: If true, Admin UI will hide the student's name and ID
    isAnonymous: { type: Boolean, default: false }, 

    // --- Categorization & Routing ---
    department: { type: String, required: true }, // e.g., "Hostel", "IT"
    category: { type: String, required: true },    // e.g., "Infrastructure", "Harassment"
    subCategory: { type: String, required: true },
    
    // Auto/Manual Assignment: Which admin is handling this right now?
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },

    // --- The Issue ---
    title: { type: String, required: true },
    description: { type: String, required: true },
    
    // Upgraded Evidence Viewer: Changed to an array to allow multiple uploads later
    evidenceFiles: [{ type: String }], 
    
    // Urgency Heatmap (Low, Medium, High, Critical)
    urgency: { type: String, enum: ['Low', 'Medium', 'High', 'Critical'], default: 'Medium' },

    // --- Lifecycle & Status Tracker ---
    status: { 
        type: String, 
        enum: ['Open', 'Under Review', 'Resolved', 'Closed'], 
        default: 'Open' 
    },
    
    // Action History: The "Paper Trail" (Who changed what and when)
    history: [{
        action: String, // e.g., "Status changed to Under Review"
        performedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        timestamp: { type: Date, default: Date.now }
    }],

    // --- Communication & Feedback ---
    // Internal Remarks (Hidden from student)
    internalNotes: [{
        note: String,
        addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        timestamp: { type: Date, default: Date.now }
    }],
    
    // Direct Response (The official reply sent to the student)
    adminReply: { type: String, default: '' },
    
    // Post-Resolution Feedback
    feedback: {
        rating: { type: Number, min: 1, max: 5 }, // 1 to 5 stars
        comment: { type: String }
    }

}, { timestamps: true });


// ==========================================
// 3. AUDIT LOG SCHEMA (New Security Feature)
// ==========================================
// Tracks every major action an admin takes to prevent tampering
const AuditLogSchema = new mongoose.Schema({
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    action: { type: String, required: true }, // e.g., "Logged In", "Deleted Complaint #123"
    targetId: { type: mongoose.Schema.Types.ObjectId }, // ID of the affected complaint/user
    ipAddress: { type: String }
}, { timestamps: true });


const User = mongoose.model('User', UserSchema);
const Complaint = mongoose.model('Complaint', ComplaintSchema);
const AuditLog = mongoose.model('AuditLog', AuditLogSchema);

module.exports = { User, Complaint, AuditLog };