const { User, Individual, Business, Admin } = require('../models/userModel');
const jwt = require('jsonwebtoken');

exports.protect = async (req, res, next) => {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            // Get token from header
            token = req.headers.authorization.split(' ')[1];

            // Verify token
            const decoded = jwt.verify(token, process.env.JWT_SECRET); // Replace with your actual secret

            // Get user from token
            let user = await Individual.findById(decoded.id).select('-password');
            if (!user) {
                user = await Business.findById(decoded.id).select('-password');
            }
            if (!user) {
                user = await Admin.findById(decoded.id).select('-password');
            }

            if (!user) {
                return res.status(401).json({ message: 'Not authorized' });
            }

            req.user = user;
            next();
        } catch (error) {
            console.error('Error during authentication:', error);
            res.status(401).json({ message: 'Not authorized, token failed' });
        }
    }

    if (!token) {
        res.status(401).json({ message: 'Not authorized, no token' });
    }
};