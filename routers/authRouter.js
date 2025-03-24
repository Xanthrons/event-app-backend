const express = require('express');
const authController = require('../controllers/authController');
const validator = require('../middlewares/validator');
const { protect } = require('../middlewares/authMiddleware');
const multer = require('multer');

const router = express.Router();

const storageProfile = multer.memoryStorage();
const uploadProfilePictureMiddleware = multer({ storage: storageProfile });

router.post('/register', validator.validateRegistration, authController.register);
router.post('/login', authController.login);
router.post('/logout', authController.logout);
router.post('/forgot-password', authController.forgotPassword);
router.post('/verify-reset-code', authController.verifyResetCode);
router.post('/reset-password', authController.resetPassword);
router.get('/me', protect, authController.getMe);
router.delete('/me', protect, authController.deleteAccount);
router.delete('/test-delete', authController.testDeleteAccountByEmail); // Modified DELETE route for testing purposes
router.post('/upload-profile-picture', protect, uploadProfilePictureMiddleware.single('profilePicture'), authController.uploadProfilePicture);
router.post('/google-auth', authController.googleAuth);



module.exports = router;