const { User, Individual, Business, Admin } = require('../models/userModel');
const jwt = require('jsonwebtoken');
const { hashPassword, comparePassword } = require('../utils/hashing');
const Joi = require('joi');
const { ObjectId } = require('mongoose').Types;
const { sendEmail } = require('../middlewares/sendMail'); // i am  keeping this if i may need it elsewhere
const bcrypt = require('bcrypt');
const crypto = require('crypto');  
const {
    validateForgotPassword,
    validateVerifyResetCode,
    validateResetPassword
} = require('../middlewares/validator');
const path = require('path');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { protect } = require('../middlewares/authMiddleware');
const { OAuth2Client } = require('google-auth-library');

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);


// const admin = require('firebase-admin');

// const serviceAccount = {
//   type: process.env.FIREBASE_TYPE,
//   project_id: process.env.FIREBASE_PROJECT_ID,
//   private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
//   private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'), 
//   client_email: process.env.FIREBASE_CLIENT_EMAIL,
//   client_id: process.env.FIREBASE_CLIENT_ID,
//   auth_uri: process.env.FIREBASE_AUTH_URI,
//   token_uri: process.env.FIREBASE_TOKEN_URI,
//   auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
//   client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
//   universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN
// };
// admin.initializeApp({
//     credential: admin.credential.cert(serviceAccount),
//     storageBucket: process.env.FIREBASE_STORAGE_BUCKET_URL // Make sure you have this in your .env file (e.g., gs://your-project-id.appspot.com)
// });

// Configure Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configure multer for memory storage
// const storage = multer.memoryStorage();
// const upload = multer({ storage: storage });

// Function to generate JWT token
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    });
};

// Controller for user registration (Individual and Business)
const pendingRegistrations = new Map();
const generateVerificationCode = () => {
    // Generate a random 6-digit number
    return Math.floor(100000 + Math.random() * 900000).toString();
};

const hashVerificationCode = async (code) => {
    const saltRounds = 10;
    return await bcrypt.hash(code, saltRounds);
};
// Controller for user registration (Individual and Business) - REVISED
exports.register = async (req, res) => {
    try {
        const { role, password, ...userData } = req.body;

        let existingUser;
        if (role === 'individual' || role === 'admin') {
            existingUser = await User.findOne({ role, email: userData.email });
        } else if (role === 'business') {
            existingUser = await User.findOne({ role, business_email: userData.business_email });
        }

        if (existingUser) {
            return res.status(409).json({ message: 'Account with this email is already registered. Please log in.' });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create the new user
        const newUser = new User({
            ...userData,
            password: hashedPassword,
            role,
        });

        await newUser.save();

        // Generate JWT token
        const token = generateToken(newUser._id);

        res.status(201).json({ message: 'Registration successful.', token: token });

    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Failed to register user.' });
    }
};

// Controller for user login (Individual, Business, and Admin) - REVISED
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        let user;

        const individualUser = await Individual.findOne({ email }).select('+password');
        const businessUser = await Business.findOne({ business_email: email }).select('+password');
        const adminUser = await Admin.findOne({ email }).select('+password');

        if (individualUser) {
            user = individualUser;
        } else if (businessUser) {
            user = businessUser;
        } else if (adminUser) {
            user = adminUser;
        }

        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        const isPasswordMatch = await comparePassword(password, user.password);

        if (!isPasswordMatch) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        const token = generateToken(user._id);

        res.status(200).json({ message: 'Login successful!', token, user: { _id: user._id, role: user.role, email: user.email || user.business_email } });

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Failed to login.' });
    }
};

// Controller for Google Authentication
exports.googleAuth = async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({ message: 'Google ID token is required.' });
        }

        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        const googleEmail = payload.email;
        const googleName = payload.name;
        const googlePicture = payload.picture;

        if (!googleEmail) {
            return res.status(400).json({ message: 'Could not retrieve email from Google token.' });
        }

        let user;
        user = await Individual.findOne({ email: googleEmail });
        if (!user) {
            user = await Business.findOne({ business_email: googleEmail });
        }
        if (!user) {
            user = await Admin.findOne({ email: googleEmail });
        }

        if (user) {
            // User already exists, generate and return JWT
            const jwtToken = generateToken(user._id);
            return res.status(200).json({ message: 'Login successful via Google.', token: jwtToken, user: { _id: user._id, role: user.role, email: user.email || user.business_email, profile_picture: user.profile_picture || googlePicture, first_name: user.first_name || googleName } });
        } else {
            // Create a new user
            const newUser = new User({
                email: googleEmail,
                first_name: googleName ? googleName.split(' ')[0] : null,
                last_name: googleName ? googleName.split(' ')[1] : null,
                profile_picture: googlePicture,
                role: 'individual', // Default role for Google signup, adjust as needed
                password: crypto.randomBytes(20).toString('hex'), // Generate a random password
            });

            await newUser.save();
            const jwtToken = generateToken(newUser._id);
            return res.status(201).json({ message: 'Registration successful via Google.', token: jwtToken, user: { _id: newUser._id, role: newUser.role, email: newUser.email, profile_picture: newUser.profile_picture } });
        }

    } catch (error) {
        console.error('Error during Google authentication:', error);
        res.status(401).json({ message: 'Google authentication failed.' });
    }
};

// Controller for user logout
exports.logout = async (req, res) => {
    try {
        res.status(200).json({ message: 'Logout successful!' });
    } catch (error) {
        console.error('Error during logout:', error);
        res.status(500).json({ message: 'Failed to logout.' });
    }
};

// Controller for user profile 
exports.getMe = async (req, res) => {
    try {
        // req.user is set by the 'protect' middleware
        if (!req.user) {
            return res.status(401).json({ message: 'Not authorized' });
        }

        let userDetails;
        if (req.user.role === 'individual') {
            userDetails = await Individual.findById(req.user.id);
        } else if (req.user.role === 'business') {
            userDetails = await Business.findById(req.user.id);
        } else if (req.user.role === 'admin') {
            userDetails = await Admin.findById(req.user.id);
        }

        if (!userDetails) {
            return res.status(404).json({ message: 'User details not found' });
        }

        // Send back the user details, including the role
        res.status(200).json(userDetails);

    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ message: 'Failed to fetch user profile' });
    }
};

exports.forgotPassword = async (req, res) => {
    try {
        const { error } = validateForgotPassword(req.body);
        if (error) return res.status(400).json({ message: error.details[0].message });

        const { email } = req.body;
        let user = null;

        user = await Individual.findOne({ email });
        if (!user) {
            user = await Business.findOne({ business_email: email });
        }
        if (!user) {
            user = await Admin.findOne({ email });
        }

        if (!user) {
            return res.status(404).json({ message: 'User with this email not found.' });
        }

        const verificationCode = generateVerificationCode();
        const hashedVerificationCode = await hashPassword(verificationCode);
        const passwordResetCodeExpires = Date.now() + 15 * 60 * 1000; // 15 minutes expiry

        const updateData = {
            passwordResetCode: hashedVerificationCode,
            passwordResetCodeExpires: passwordResetCodeExpires,
        };

        if (user instanceof Individual) {
            await Individual.updateOne({ _id: user._id }, updateData);
        } else if (user instanceof Business) {
            await Business.updateOne({ _id: user._id }, updateData);
        } else if (user instanceof Admin) {
            await Admin.updateOne({ _id: user._id }, updateData);
        }

        const subject = 'Password Reset Verification Code';
        const html = `<p>You have requested to reset your password. Please use the following verification code:</p>
                                    <h2>${verificationCode}</h2>
                                    <p>This code will expire in 15 minutes.</p>
                                    <p>If you did not request this, please ignore this email.</p>`;

        await sendEmail(user.email || user.business_email, subject, html);

        res.status(200).json({ message: 'Password reset verification code sent to your email address.' });

    } catch (error) {
        console.error('Error during forgot password request:', error);
        res.status(500).json({ message: 'Something went wrong, please try again later.' });
    }
};

exports.verifyResetCode = async (req, res) => {
    try {
        const { error } = validateVerifyResetCode(req.body);
        if (error) return res.status(400).json({ message: error.details[0].message });

        const { email, code } = req.body;
        let user = null;

        user = await Individual.findOne({ email }).select('+passwordResetCode +passwordResetCodeExpires');
        if (!user) {
            user = await Business.findOne({ business_email: email }).select('+passwordResetCode +passwordResetCodeExpires');
        }
        if (!user) {
            user = await Admin.findOne({ email }).select('+passwordResetCode +passwordResetCodeExpires');
        }

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        if (!user.passwordResetCode || !user.passwordResetCodeExpires || user.passwordResetCodeExpires < Date.now()) {
            return res.status(400).json({ message: 'Verification code is invalid or has expired.' });
        }

        const isMatch = await comparePassword(code, user.passwordResetCode);
        if (!isMatch) {
            return res.status(400).json({ message: 'Verification code is incorrect.' });
        }

        const tempToken = crypto.randomBytes(20).toString('hex');
        const tempTokenExpires = Date.now() + 30 * 60 * 1000; // 30 minutes expiry for the temp token

        const updateData = {
            passwordResetTempToken: tempToken,
            passwordResetTempTokenExpires: tempTokenExpires,
            passwordResetCode: undefined, // Clear the hashed verification code
            passwordResetCodeExpires: undefined,
        };

        if (user instanceof Individual) {
            await Individual.updateOne({ _id: user._id }, updateData);
        } else if (user instanceof Business) {
            await Business.updateOne({ _id: user._id }, updateData);
        } else if (user instanceof Admin) {
            await Admin.updateOne({ _id: user._id }, updateData);
        }

        res.status(200).json({ message: 'Verification code is valid.', tempToken: tempToken });

    } catch (error) {
        console.error('Error during verify reset code:', error);
        res.status(500).json({ message: 'Something went wrong, please try again later.' });
    }
};

exports.resetPassword = async (req, res) => {
    try {
        const { error } = validateResetPassword(req.body);
        if (error) return res.status(400).json({ message: error.details[0].message });

        const { tempToken, newPassword } = req.body;
        let user = null;

        user = await Individual.findOne({ passwordResetTempToken: tempToken, passwordResetTempTokenExpires: { $gt: Date.now() } });
        if (!user) {
            user = await Business.findOne({ passwordResetTempToken: tempToken, passwordResetTempTokenExpires: { $gt: Date.now() } });
        }
        if (!user) {
            user = await Admin.findOne({ passwordResetTempToken: tempToken, passwordResetTempTokenExpires: { $gt: Date.now() } });
        }

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired temporary token for password reset.' });
        }

        const hashedPassword = await hashPassword(newPassword);

        const updateData = {
            password: hashedPassword,
            passwordResetTempToken: undefined,
            passwordResetTempTokenExpires: undefined,
        };

        if (user instanceof Individual) {
            await Individual.updateOne({ _id: user._id }, updateData);
        } else if (user instanceof Business) {
            await Business.updateOne({ _id: user._id }, updateData);
        } else if (user instanceof Admin) {
            await Admin.updateOne({ _id: user._id }, updateData);
        }

        res.status(200).json({ message: 'Password reset successfully.' });

    } catch (error) {
        console.error('Error during reset password:', error);
        res.status(500).json({ message: 'Something went wrong, please try again later.' });
    }
};

// Main delete account function
exports.deleteAccount = async (req, res) => {
    try {
        const userId = req.user.id;
        const userRole = req.user.role;

        let deletionResult;

        if (userRole === 'individual') {
            deletionResult = await Individual.findByIdAndDelete(userId);
        } else if (userRole === 'business') {
            deletionResult = await Business.findByIdAndDelete(userId);
        } else if (userRole === 'admin') {
            deletionResult = await Admin.findByIdAndDelete(userId);
        }

        if (!deletionResult) {
            return res.status(404).json({ message: 'Account not found.' });
        }

        res.status(200).json({ message: 'Account deleted successfully.' });

    } catch (error) {
        console.error('Error deleting account:', error);
        res.status(500).json({ message: 'Failed to delete account.' });
    }
};

//Test -delete i will remove this later for the production purpose
exports.testDeleteAccountByEmail = async (req, res) => {
    try {
        const { email, role } = req.body;

        if (!email || !role) {
            return res.status(400).json({ message: 'Please provide email and role.' });
        }

        let deletionResult;

        if (role === 'individual') {
            deletionResult = await Individual.findOneAndDelete({ email });
        } else if (role === 'business') {
            deletionResult = await Business.findOneAndDelete({ business_email: email });
        } else if (role === 'admin') {
            deletionResult = await Admin.findOneAndDelete({ email });
        } else {
            return res.status(400).json({ message: 'Invalid role provided.' });
        }

        if (!deletionResult) {
            return res.status(404).json({ message: 'Account with provided email not found.' });
        }

        res.status(200).json({ message: 'Account deleted successfully (TEST FUNCTION).' });

    } catch (error) {
        console.error('Error deleting account by email (TEST FUNCTION):', error);
        res.status(500).json({ message: 'Failed to delete account.' });
    }
};

//Upload Profile picture

exports.uploadProfilePicture = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No profile picture file uploaded.' });
        }

        const userId = req.user.id;
        const userRole = req.user.role;

        console.log('User Role:', userRole); // Add this line

        let Model;
        let folderPrefix;

        if (userRole === 'individual') {
            Model = Individual;
            folderPrefix = 'individual';
        } else if (userRole === 'business') {
            Model = Business;
            folderPrefix = 'business';
        } else {
            return res.status(400).json({ message: 'Invalid user role for profile picture upload.' });
        }

        const fileBuffer = req.file.buffer;
        const base64Image = fileBuffer.toString('base64');

        try {
            const result = await cloudinary.uploader.upload(`data:${req.file.mimetype};base64,${base64Image}`, {
                folder: 'profile-pictures',
                public_id: `${folderPrefix}-${userId}-${Date.now()}`,
            });

            const profilePictureUrl = result.secure_url;

            const updatedUser = await Model.findByIdAndUpdate(
                userId,
                { profile_picture: profilePictureUrl },
                { new: true }
            );

            if (!updatedUser) {
                return res.status(404).json({ message: `${userRole.charAt(0).toUpperCase() + userRole.slice(1)} user not found.` });
            }

            return res.status(200).json({ message: 'Profile picture uploaded successfully.', user: updatedUser });

        } catch (cloudinaryError) {
            console.error('Error uploading to Cloudinary:', cloudinaryError);
            return res.status(500).json({ message: 'Failed to upload profile picture to Cloudinary.' });
        }

    } catch (error) {
        console.error('Error in uploadProfilePicture function:', error);
        return res.status(500).json({ message: 'Failed to upload profile picture.' });
    }
};
