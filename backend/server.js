// =================================================================
// --- 1. IMPORTS & INITIAL SETUP ---
// =================================================================
// We begin by importing all the necessary libraries (packages) that our server needs to function.

const express = require('express');        // The core framework for building our web server and APIs.
const cors = require('cors');              // A middleware to enable Cross-Origin Resource Sharing, which is crucial for allowing our frontend pages to communicate with this backend.
const bcrypt = require('bcryptjs');        // A library for securely "hashing" passwords. We never store plain text passwords, only their irreversible hashes.
const mongoose = require('mongoose');      // An Object Data Modeling (ODM) library that makes interacting with our MongoDB database simple and structured.
const nodemailer = require('nodemailer');  // A module for sending emails from Node.js, which we use for sending OTPs.
const jwt = require('jsonwebtoken');       // A library to implement JSON Web Tokens (JWT) for secure user authentication after they log in.

// --- Key Configuration Variables ---
// These are central settings for our application.

// This is a secret key used to sign our JWTs. In a real production environment, this MUST be stored securely as an environment variable, not written directly in the code.
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-that-is-long-and-random';

// The port on which our server will listen for incoming requests. We use the PORT environment variable provided by Render, or default to 3000 for local development.
const PORT = process.env.PORT || 3000;

// --- Initialize the Express App ---
// This creates an instance of our web server.
const app = express();


// =================================================================
// --- 2. MIDDLEWARE & DATABASE CONNECTION ---
// =================================================================
// Middleware are functions that run for every incoming request. They are essential for preparing the request before it reaches our specific endpoints.

app.use(cors()); // Enables CORS for all routes, allowing any frontend to make requests to this server.
app.use(express.json({ limit: '10mb' })); // This parses incoming request bodies into JSON format. We set a 10mb limit to handle potentially large data like base64-encoded images for profile pictures.

// --- Connect to MongoDB ---
// This is one of the most critical parts of the server setup.

// We get the database connection string from an environment variable named MONGO_URI. This is what Render will provide.
// If it's not found (like when we're running it on our own Mac), it will fall back to the local development database address.
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/sipeDB';

// We log the URI we are attempting to connect to. This is very helpful for debugging deployment issues.
console.log(`Attempting to connect to MongoDB...`);

// Mongoose attempts to establish a persistent connection to the database.
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ Successfully connected to MongoDB!')) // This message confirms our database is connected and ready.
    .catch(err => console.error('❌ Database connection error:', err)); // If this message appears, there's a problem with the database connection.


// =================================================================
// --- 3. DATABASE SCHEMAS & MODELS ---
// =================================================================
// Schemas define the structure, data types, and rules for the documents we will store in our database collections.
// Models are the tools we use in our code to create, read, update, and delete these documents.

// Defines the structure for a student user.
const studentSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, unique: true, required: true }, // 'unique: true' ensures no two students can have the same email.
    institution: { type: String, required: true },
    exam: { type: String, required: true },
    password: { type: String, required: true }
});
const Student = mongoose.model('Student', studentSchema);

// Defines the structure for a partner institution.
const institutionSchema = new mongoose.Schema({
    name: { type: String, required: true },
    type: { type: String, required: true },
    state: { type: String, required: true },
    city: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    contactPerson: { type: String, required: true },
    website: { type: String },
    password: { type: String, required: true },
    status: { type: String, default: 'Pending Review' } // All new institutions start with this status.
});
const Institution = mongoose.model('Institution', institutionSchema);

// Defines the structure for a session created by an institution.
const sessionSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    category: { type: String, required: true }, // e.g., 'Exam Prep', 'Startup'
    examType: { type: String }, // Only if category is 'Exam Prep'
    mentorName: { type: String, required: true },
    mentorPicture: { type: String }, // Base64 encoded image
    institutionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Institution', required: true } // This links the session to the institution that created it.
});
const Session = mongoose.model('Session', sessionSchema);

// Defines the structure for an inquiry from the contact form.
const inquirySchema = new mongoose.Schema({
    userType: { type: String, required: true },
    name: { type: String, required: true },
    email: { type: String, required: true },
    institutionName: { type: String },
    expertise: { type: String },
    message: { type: String, required: true }
});
const Inquiry = mongoose.model('Inquiry', inquirySchema);

// Defines the structure for an alumnus registered by an institution.
const alumniSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    company: { type: String, required: true },
    linkedin: { type: String },
    picture: { type: String }, // Base64 encoded image
    institutionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Institution', required: true } // Links the alumnus to their institution.
});
const Alumni = mongoose.model('Alumni', alumniSchema);

// Defines the structure for an event created by an institution.
const eventSchema = new mongoose.Schema({
    title: { type: String, required: true },
    date: { type: Date, required: true },
    time: { type: String, required: true },
    description: { type: String, required: true },
    institutionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Institution', required: true } // Links the event to its institution.
});
const Event = mongoose.model('Event', eventSchema);

// Defines the structure for a submission from the Student Dashboard's Innovation Hub.
const hubSubmissionSchema = new mongoose.Schema({
    helpType: { type: String, required: true },
    prototypeFile: { type: String }, // We would store a URL to an uploaded file here.
    financialSupport: { type: Number },
    description: { type: String, required: true },
    studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Student', required: true } // Links the submission to the student.
});
const HubSubmission = mongoose.model('HubSubmission', hubSubmissionSchema);


// =================================================================
// --- 4. HELPER FUNCTIONS (OTP & AUTH MIDDLEWARE) ---
// =================================================================
const otpStore = {}; // A simple in-memory object to store OTPs. For a real production app, a more robust solution like Redis is recommended.
let transporter; // This variable will hold our Nodemailer email transport configuration.

// Creates a temporary, fake email account using Ethereal for safe testing. This runs when the server starts.
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

// A reusable function to generate and send an OTP via email.
const sendOtpEmail = async (email) => {
    if (!transporter) {
        // This handles the case where an email is requested before the test account is ready.
        throw new Error('Email service is not ready. Please try again in a moment.');
    }
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = { otp, expiry: Date.now() + 10 * 60 * 1000 }; // OTP is valid for 10 minutes.
    console.log(`Generated OTP for ${email}: ${otp}`);
    
    let info = await transporter.sendMail({
        from: '"SIPE Support" <support@sipe.com>',
        to: email,
        subject: 'Your SIPE Verification Code',
        html: `<p>Your verification code is <b>${otp}</b>. It is valid for 10 minutes.</p>`,
    });

    // This URL lets you preview the sent email in your browser. It will be logged in the terminal.
    console.log('📧 Preview URL: %s', nodemailer.getTestMessageUrl(info));
};

// An authentication middleware that acts as a gatekeeper for protected institution routes.
const authMiddleware = (req, res, next) => {
    // 1. Check for the Authorization header.
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Unauthorized: No token provided.' });
    }
    // 2. Extract the token from the header.
    const token = authHeader.split(' ')[1];
    try {
        // 3. Verify the token's authenticity using our secret key.
        const decoded = jwt.verify(token, JWT_SECRET);
        // 4. If valid, attach the decoded payload (id, name) to the request object for later use.
        req.institution = decoded;
        // 5. Proceed to the actual route handler.
        next();
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
        req.student = decoded; // Attach student info (id, name, institution) to the request object.
        next();
    } catch (error) {
        res.status(401).json({ message: 'Unauthorized: Invalid token.' });
    }
};


// =================================================================
// --- 5. API ENDPOINTS (ROUTES) ---
// =================================================================

// --- Public / General Endpoints ---
// These endpoints can be accessed by anyone without needing a token.

// Endpoint for the contact form.
app.post('/api/contact', async (req, res) => {
    try {
        const { userType, name, email, institutionName, expertise, message } = req.body;
        // Basic validation
        if (!userType || !name || !email || !message) {
            return res.status(400).json({ message: 'Please fill out all required fields.' });
        }
        const newInquiry = new Inquiry({ userType, name, email, institutionName, expertise, message });
        await newInquiry.save(); // Save the inquiry to the database.
        console.log(`New inquiry received from a ${userType}: ${name}`);
        res.status(201).json({ message: 'Your inquiry has been submitted successfully!' });
    } catch (error) {
        console.error("Contact form error:", error);
        res.status(500).json({ message: 'Server error. Please try again later.' });
    }
});

// Endpoint for the student signup page to get a list of all registered institution names.
app.get('/api/institutions', async (req, res) => {
    try {
        // Find all institutions but only return their 'name' field.
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

// Step 1 of signup: Send an OTP.
app.post('/api/students/send-otp', async (req, res) => {
    try {
        await sendOtpEmail(req.body.email);
        res.status(200).json({ message: 'OTP sent successfully. Please check your email.' });
    } catch (error) {
        res.status(500).json({ message: error.message || 'Failed to send OTP.' });
    }
});

// Step 2 of signup: Verify OTP and create the user.
app.post('/api/students/signup', async (req, res) => {
    try {
        const { name, email, institution, exam, password, otp } = req.body;
        
        // Check if OTP is valid
        const storedOtpData = otpStore[email];
        if (!storedOtpData || Date.now() > storedOtpData.expiry || storedOtpData.otp !== otp) {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }
        
        // Check if user already exists
        if (await Student.findOne({ email })) {
            return res.status(400).json({ message: 'User with this email already exists.' });
        }
        
        // Hash the password and create the new student
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newStudent = new Student({ name, email, institution, exam, password: hashedPassword });
        await newStudent.save();
        
        delete otpStore[email]; // Clean up the used OTP.
        res.status(201).json({ message: 'User created successfully! Please log in.', userId: newStudent._id });
    } catch (error) {
        console.error("Student signup error:", error);
        res.status(500).json({ message: 'Server error during signup.' });
    }
});

// Student login endpoint.
app.post('/api/students/login', async (req, res) => {
    const { email, password } = req.body;
    const student = await Student.findOne({ email });
    
    // Check if student exists and if the password is correct.
    if (!student || !(await bcrypt.compare(password, student.password))) {
        return res.status(400).json({ message: 'Invalid credentials.' });
    }
    
    // If credentials are valid, create a JWT.
    const token = jwt.sign({ id: student._id, name: student.name, institution: student.institution }, JWT_SECRET, { expiresIn: '24h' });
    res.status(200).json({ message: 'Login successful!', token });
});

// --- Institution Authentication Endpoints ---

// Step 1 of signup: Send an OTP.
app.post('/api/institutions/send-otp', async (req, res) => {
    try {
        await sendOtpEmail(req.body.email);
        res.status(200).json({ message: 'OTP sent successfully to the institution email.' });
    } catch (error) {
        res.status(500).json({ message: error.message || 'Failed to send OTP.' });
    }
});

// Step 2 of signup: Verify OTP and create the institution.
app.post('/api/institutions/signup', async (req, res) => {
    try {
        const { name, type, state, city, email, contactPerson, website, password, otp } = req.body;

        // Check if OTP is valid
        const storedOtpData = otpStore[email];
        if (!storedOtpData || Date.now() > storedOtpData.expiry || storedOtpData.otp !== otp) {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }
        
        // Check if institution already exists
        if (await Institution.findOne({ email })) {
            return res.status(400).json({ message: 'Institution with this email already registered.' });
        }
        
        // Hash the password and create the new institution
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newInstitution = new Institution({ name, type, state, city, email, contactPerson, website, password: hashedPassword });
        await newInstitution.save();

        delete otpStore[email]; // Clean up the used OTP.
        res.status(201).json({ message: 'Registration submitted successfully! We will review your application.' });
    } catch (error) {
        console.error("Institution signup error:", error);
        res.status(500).json({ message: 'Server error during institution signup.' });
    }
});

// Institution login endpoint.
app.post('/api/institutions/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const institution = await Institution.findOne({ email });

        // Check if institution exists and password is correct.
        if (!institution || !(await bcrypt.compare(password, institution.password))) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        // Create a JWT for the institution.
        const token = jwt.sign({ id: institution._id, name: institution.name }, JWT_SECRET, { expiresIn: '24h' });
        res.status(200).json({ message: 'Login successful!', token: token });
    } catch (error) {
        res.status(500).json({ message: 'Server error during institution login.' });
    }
});

// --- Protected Institution Dashboard Endpoints ---
// These routes can ONLY be accessed by a logged-in institution with a valid token. The 'authMiddleware' gatekeeper runs first.

app.get('/api/institutions/profile', authMiddleware, async (req, res) => {
    try {
        // The 'req.institution.id' comes from the decoded token in the middleware.
        const institution = await Institution.findById(req.institution.id).select('-password'); // '-password' excludes the password hash from the result.
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
        const { title, description, category, examType, mentorName, mentorPicture } = req.body;
        const newSession = new Session({
            title, description, category, examType, mentorName, mentorPicture,
            institutionId: req.institution.id
        });
        await newSession.save();
        res.status(201).json({ message: 'Session created successfully!', session: newSession });
    } catch (error) {
        console.error("Session creation error:", error);
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
// These routes can ONLY be accessed by a logged-in student. The 'studentAuthMiddleware' is the gatekeeper.

app.get('/api/students/profile', studentAuthMiddleware, async (req, res) => {
    // The 'req.student.id' comes from the decoded token in the middleware.
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
// This command starts our web server, making it listen for incoming requests on the specified port.
app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
});
