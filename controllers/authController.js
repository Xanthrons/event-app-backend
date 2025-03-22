const { User, Individual, Business, Admin } = require('../models/userModel');
const jwt = require('jsonwebtoken');
const { hashPassword, comparePassword } = require('../utils/hashing');
const Joi = require('joi');
const { ObjectId } = require('mongoose').Types;
const { sendEmail } = require('../middlewares/sendMail');
const bcrypt = require('bcrypt');

// Function to generate JWT token
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    });
};

// Controller for user registration (Individual and Business)
exports.register = async (req, res) => {
    // console.log(req.body);
    try {
        const { role, password, ...userData } = req.body;

        let existingUser;
        if (role === 'individual' || role === 'admin') {
            existingUser = await User.findOne({ role, email: userData.email });
        } else if (role === 'business') {
            existingUser = await User.findOne({ role, business_email: userData.business_email });
        }

        if (existingUser) {
            return res.status(409).json({ message: 'Email already exists!' });
        }

        const hashedPassword = await hashPassword(password);

        let newUser;
        if (role === 'individual') {
            newUser = await Individual.create({ ...userData, password: hashedPassword });
        } else if (role === 'business') {
            newUser = await Business.create({ ...userData, password: hashedPassword });
        } else if (role === 'admin') {
            newUser = await Admin.create({ ...userData, password: hashedPassword });
        }

        const token = generateToken(newUser._id);

        res.status(201).json({ message: 'Registration successful!', token, user: { _id: newUser._id, role: newUser.role, email: newUser.email || newUser.business_email } });

    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Failed to register user.' });
    }
};

// Controller for user login (Individual, Business, and Admin)
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

        if (!user.verified) {
            return res.status(403).json({ message: 'Email not verified. Please verify your email address.' });
        }

        const token = generateToken(user._id);

        res.status(200).json({ message: 'Login successful!', token, user: { _id: user._id, role: user.role, email: user.email || user.business_email, verified: user.verified } });

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Failed to login.' });
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

const generateVerificationCode = () => {
    // Generate a random 6-digit number
    return Math.floor(100000 + Math.random() * 900000).toString();
};

const hashVerificationCode = async (code) => {
    const saltRounds = 10;
    return await bcrypt.hash(code, saltRounds);
};

exports.sendVerificationCode = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        if (user.verified) {
            return res.status(400).json({ message: 'User is already verified.' });
        }

        const verificationCode = generateVerificationCode();
        const hashedVerificationCode = await hashVerificationCode(verificationCode);
        const verificationCodeExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes

        user.verificationCode = hashedVerificationCode;
        user.verificationCodeValidation = verificationCodeExpiry;
        await user.save({ validateBeforeSave: false }); // Prevent other validations

        const subject = 'Email Verification Code';
        const html = `<p>Your verification code is: <strong>${verificationCode}</strong></p>
                    <p>This code will expire in 10 minutes.</p>`;

        await sendEmail(email, subject, html);

        res.status(200).json({ message: 'Verification code sent to your email.' });

    } catch (error) {
        console.error('Error sending verification code:', error);
        res.status(500).json({ message: 'Failed to send verification code.' });
    }
};

exports.validateVerificationCode = async (req, res) => {
    try {
        const { email, code } = req.body;

        const user = await User.findOne({ email }).select('+verificationCode +verificationCodeValidation');
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        if (user.verified) {
            return res.status(400).json({ message: 'User is already verified.' });
        }

        if (!user.verificationCode || !user.verificationCodeValidation || user.verificationCodeValidation < Date.now()) {
            return res.status(400).json({ message: 'Verification code is invalid or has expired.' });
        }

        const isMatch = await bcrypt.compare(code, user.verificationCode);
        if (!isMatch) {
            return res.status(400).json({ message: 'Verification code is incorrect.' });
        }

        user.verified = true;
        user.verificationCode = undefined;
        user.verificationCodeValidation = undefined;
        await user.save();

        res.status(200).json({ message: 'Email verified successfully!' });

    } catch (error) {
        console.error('Error validating verification code:', error);
        res.status(500).json({ message: 'Failed to validate verification code.' });
    }
};