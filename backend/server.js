// =================================================================
// --- 1. IMPORTS & INITIAL SETUP ---
// =================================================================
// We begin by importing all the necessary libraries (packages) that our server needs to function.
const express = require('express');        // The core framework for building our web server and APIs.
const cors = require('cors');              // A middleware to enable Cross-Origin Resource Sharing, which is crucial for allowing our frontend pages to communicate with this backend.
const bcrypt = require('bcryptjs');        // A library for securely "hashing" passwords. We never store plain text passwords.
const mongoose = require('mongoose');      // An Object Data Modeling (ODM) library that makes interacting with our MongoDB database simple and structured.
const nodemailer = require('nodemailer');  // A module for sending emails from Node.js, which we use for sending OTPs.
const jwt = require('jsonwebtoken');       // A library to implement JSON Web Tokens (JWT) for secure user authentication after they log in.

// --- Key Configuration Variables ---
// In a real production app, this secret key should be stored securely in an environment variable, not written directly in the code.
const JWT_SECRET = 'your-super-secret-key-that-is-long-and-random-and-changed-for-production';
const PORT = 3000; // The port on which our server will listen for incoming requests.
const MONGO_URI = 'mongodb://localhost:27017/sipeDB'; // The connection string for our local MongoDB database.

// --- Initialize the Express App ---
const app = express();


// =================================================================
// --- 2. MIDDLEWARE & DATABASE CONNECTION ---
// =================================================================
// Middleware are functions that run for every incoming request. They are essential for preparing the request before it reaches our specific endpoints.
app.use(cors()); // Enables CORS for all routes, allowing any frontend to make requests.
app.use(express.json({ limit: '10mb' })); // This parses incoming request bodies into JSON format and increases the payload size limit to handle large data like base64-encoded images.

// --- Connect to MongoDB ---
// Mongoose attempts to establish a persistent connection to the MongoDB database running in your Docker container.
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ Successfully connected to MongoDB!'))
    .catch(err => console.error('❌ Database connection error:', err));


// =================================================================
// --- 3. DATABASE SCHEMAS & MODELS ---
// =================================================================
// Schemas define the structure, data types, and rules for the documents we will store in our database collections.
// Models are the tools we use in our code to create, read, update, and delete these documents.

const studentSchema = new mongoose.Schema({ name: String, email: { type: String, unique: true, required: true }, institution: String, exam: String, password: { type: String, required: true } });
const Student = mongoose.model('Student', studentSchema);

const institutionSchema = new mongoose.Schema({ name: String, type: String, state: String, city: String, email: { type: String, unique: true, required: true }, contactPerson: String, website: String, password: { type: String, required: true }, status: { type: String, default: 'Pending Review' } });
const Institution = mongoose.model('Institution', institutionSchema);

const sessionSchema = new mongoose.Schema({ title: String, description: String, audience: String, date: Date, mentorName: String, mentorPicture: String, institutionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Institution' } });
const Session = mongoose.model('Session', sessionSchema);

const inquirySchema = new mongoose.Schema({ userType: String, name: String, email: String, institutionName: String, expertise: String, message: String });
const Inquiry = mongoose.model('Inquiry', inquirySchema);

const alumniSchema = new mongoose.Schema({ name: { type: String, required: true }, email: { type: String, required: true, unique: true }, company: { type: String, required: true }, linkedin: { type: String }, picture: { type: String }, institutionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Institution', required: true } });
const Alumni = mongoose.model('Alumni', alumniSchema);

const eventSchema = new mongoose.Schema({ title: { type: String, required: true }, date: { type: Date, required: true }, time: { type: String, required: true }, description: { type: String, required: true }, institutionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Institution', required: true } });
const Event = mongoose.model('Event', eventSchema);

const hubSubmissionSchema = new mongoose.Schema({ helpType: { type: String, required: true }, prototypeFile: { type: String }, financialSupport: { type: Number }, description: { type: String, required: true }, studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Student', required: true } });
const HubSubmission = mongoose.model('HubSubmission', hubSubmissionSchema);


// =================================================================
// --- 4. HELPER FUNCTIONS (OTP & AUTH MIDDLEWARE) ---
// =================================================================
const otpStore = {}; // A simple in-memory object to store OTPs. For production, a more robust solution like Redis is recommended.
let transporter; // This variable will hold our Nodemailer email transport configuration.

// Creates a temporary, fake email account using Ethereal for safe testing.
nodemailer.createTestAccount((err, account) => {
    if (err) {
        console.error('❌ Failed to create a testing account. ' + err.message);
        return process.exit(1);
    }
    console.log('✅ Ethereal test account created successfully!');
    transporter = nodemailer.createTransport({
        host: account.smtp.host, port: account.smtp.port, secure: account.smtp.secure,
        auth: { user: account.user, pass: account.pass },
    });
});

// Reusable function to generate and send an OTP via email.
const sendOtpEmail = async (email) => {
    if (!transporter) throw new Error('Email service is not ready. Please try again in a moment.');
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = { otp, expiry: Date.now() + 10 * 60 * 1000 }; // 10 minute expiry
    console.log(`Generated OTP for ${email}: ${otp}`);
    
    let info = await transporter.sendMail({
        from: '"SIPE Support" <support@sipe.com>',
        to: email,
        subject: 'Your SIPE Verification Code',
        html: `<p>Your verification code is <b>${otp}</b>. It is valid for 10 minutes.</p>`,
    });
    // This URL lets you preview the sent email in your browser.
    console.log('📧 Preview URL: %s', nodemailer.getTestMessageUrl(info));
};

// An authentication middleware that acts as a gatekeeper for protected institution routes.
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Unauthorized: No token provided.' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET); // Verify the token's authenticity.
        req.institution = decoded; // Attach the decoded payload (id, name) to the request object.
        next(); // If the token is valid, proceed to the actual route handler.
    } catch (error) {
        res.status(401).json({ message: 'Unauthorized: Invalid token.' });
    }
};

// A similar authentication middleware specifically for protecting student routes.
const studentAuthMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Unauthorized: No token provided.' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.student = decoded; // Attach student info to the request object.
        next();
    } catch (error) {
        res.status(401).json({ message: 'Unauthorized: Invalid token.' });
    }
};


// =================================================================
// --- 5. API ENDPOINTS (ROUTES) ---
// =================================================================

// --- Public / General Endpoints ---
// These endpoints can be accessed by anyone without a token.

// Endpoint for the contact form.
app.post('/api/contact', async (req, res) => {
    try {
        const { userType, name, email, institutionName, expertise, message } = req.body;
        if (!userType || !name || !email || !message) {
            return res.status(400).json({ message: 'Please fill out all required fields.' });
        }
        const newInquiry = new Inquiry({ userType, name, email, institutionName, expertise, message });
        await newInquiry.save();
        console.log(`New inquiry received from a ${userType}: ${name}`);
        res.status(201).json({ message: 'Your inquiry has been submitted successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Server error. Please try again later.' });
    }
});

// Endpoint for the student signup page to get a list of all registered institution names.
app.get('/api/institutions', async (req, res) => {
    try {
        // RECTIFIED: Removed the status filter to show all registered institutions for now.
        const institutions = await Institution.find({}, 'name'); 
        res.status(200).json(institutions);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch institutions.' });
    }
});

// Endpoint for the student dashboard to get all alumni for a specific institution.
app.get('/api/alumni/:institutionName', async (req, res) => {
    try {
        const institution = await Institution.findOne({ name: req.params.institutionName });
        if (!institution) return res.status(404).json([]);
        const alumni = await Alumni.find({ institutionId: institution._id });
        res.json(alumni);
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

// Endpoint for the student dashboard to get all events for a specific institution.
app.get('/api/events/:institutionName', async (req, res) => {
    try {
        const institution = await Institution.findOne({ name: req.params.institutionName });
        if (!institution) return res.status(404).json([]);
        const events = await Event.find({ institutionId: institution._id });
        res.json(events);
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});


// --- Student Authentication Endpoints ---
app.post('/api/students/send-otp', async (req, res) => {
    try {
        await sendOtpEmail(req.body.email);
        res.status(200).json({ message: 'OTP sent successfully. Please check your email.' });
    } catch (error) {
        res.status(500).json({ message: error.message || 'Failed to send OTP.' });
    }
});
app.post('/api/students/signup', async (req, res) => {
    try {
        const { name, email, institution, exam, password, otp } = req.body;
        const storedOtpData = otpStore[email];
        if (!storedOtpData || Date.now() > storedOtpData.expiry || storedOtpData.otp !== otp) {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }
        if (await Student.findOne({ email })) return res.status(400).json({ message: 'User with this email already exists.' });
        
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newStudent = new Student({ name, email, institution, exam, password: hashedPassword });
        await newStudent.save();
        delete otpStore[email];
        res.status(201).json({ message: 'User created successfully!', userId: newStudent._id });
    } catch (error) {
        res.status(500).json({ message: 'Server error during signup.' });
    }
});
app.post('/api/students/login', async (req, res) => {
    const { email, password } = req.body;
    const student = await Student.findOne({ email });
    if (!student || !(await bcrypt.compare(password, student.password))) {
        return res.status(400).json({ message: 'Invalid credentials.' });
    }
    const token = jwt.sign({ id: student._id, name: student.name, institution: student.institution }, JWT_SECRET, { expiresIn: '24h' });
    res.status(200).json({ message: 'Login successful!', token });
});

// --- Institution Authentication Endpoints ---
app.post('/api/institutions/send-otp', async (req, res) => {
    try {
        await sendOtpEmail(req.body.email);
        res.status(200).json({ message: 'OTP sent successfully to the institution email.' });
    } catch (error) {
        res.status(500).json({ message: error.message || 'Failed to send OTP.' });
    }
});
app.post('/api/institutions/signup', async (req, res) => {
    try {
        const { name, type, state, city, email, contactPerson, website, password, otp } = req.body;
        const storedOtpData = otpStore[email];
        if (!storedOtpData || Date.now() > storedOtpData.expiry || storedOtpData.otp !== otp) {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }
        if (await Institution.findOne({ email })) {
            return res.status(400).json({ message: 'Institution with this email already registered.' });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newInstitution = new Institution({ name, type, state, city, email, contactPerson, website, password: hashedPassword });
        await newInstitution.save();
        delete otpStore[email];
        res.status(201).json({ message: 'Registration submitted successfully! We will review your application.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error during institution signup.' });
    }
});
app.post('/api/institutions/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const institution = await Institution.findOne({ email });
        if (!institution || !(await bcrypt.compare(password, institution.password))) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        const token = jwt.sign({ id: institution._id, name: institution.name }, JWT_SECRET, { expiresIn: '24h' });
        res.status(200).json({ message: 'Login successful!', token: token });
    } catch (error) {
        res.status(500).json({ message: 'Server error during institution login.' });
    }
});

// --- Protected Institution Dashboard Endpoints ---
// These routes can only be accessed by a logged-in institution with a valid token.
app.get('/api/institutions/profile', authMiddleware, async (req, res) => {
    try {
        const institution = await Institution.findById(req.institution.id).select('-password');
        if (!institution) return res.status(404).json({ message: 'Institution not found.' });
        res.status(200).json(institution);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching profile.' });
    }
});
app.get('/api/institutions/student-count', authMiddleware, async (req, res) => {
    try {
        const count = await Student.countDocuments({ institution: req.institution.name });
        res.status(200).json({ count: count });
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching student count.' });
    }
});
app.get('/api/institutions/session-count', authMiddleware, async (req, res) => {
    try {
        const count = await Session.countDocuments({ institutionId: req.institution.id });
        res.status(200).json({ count: count });
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching session count.' });
    }
});
app.post('/api/institutions/sessions', authMiddleware, async (req, res) => {
    try {
        const { title, description, audience, date, mentorName, mentorPicture } = req.body;
        const newSession = new Session({
            title, description, audience, date, mentorName, mentorPicture,
            institutionId: req.institution.id
        });
        await newSession.save();
        res.status(201).json({ message: 'Session created successfully!', session: newSession });
    } catch (error) {
        res.status(500).json({ message: 'Server error creating session.' });
    }
});
app.post('/api/institutions/events', authMiddleware, async (req, res) => {
    const { title, date, time, description } = req.body;
    const newEvent = new Event({ title, date, time, description, institutionId: req.institution.id });
    await newEvent.save();
    res.status(201).json({ message: 'Event created successfully!', event: newEvent });
});
app.get('/api/institutions/event-count', authMiddleware, async (req, res) => {
    const count = await Event.countDocuments({ institutionId: req.institution.id });
    res.json({ count });
});
app.post('/api/institutions/alumni', authMiddleware, async (req, res) => {
    const { name, email, company, linkedin, picture } = req.body;
    const newAlumni = new Alumni({ name, email, company, linkedin, picture, institutionId: req.institution.id });
    await newAlumni.save();
    res.status(201).json({ message: 'Alumnus registered successfully!', alumni: newAlumni });
});
app.get('/api/institutions/alumni-count', authMiddleware, async (req, res) => {
    const count = await Alumni.countDocuments({ institutionId: req.institution.id });
    res.json({ count });
});

// --- Protected Student Dashboard Endpoints ---
// These routes can only be accessed by a logged-in student with a valid token.
app.get('/api/students/profile', studentAuthMiddleware, async (req, res) => {
    const student = await Student.findById(req.student.id).select('-password');
    res.json(student);
});
app.post('/api/students/hub-submission', studentAuthMiddleware, async (req, res) => {
    const { helpType, financialSupport, description } = req.body;
    const newSubmission = new HubSubmission({ helpType, financialSupport, description, studentId: req.student.id });
    await newSubmission.save();
    res.status(201).json({ message: 'Your submission was received!' });
});

// =================================================================
// --- 6. START THE SERVER ---
// =================================================================
app.listen(PORT, () => {
    console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
