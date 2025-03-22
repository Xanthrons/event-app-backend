const express = require('express');
const authController = require('../controllers/authController');
console.log("authController", authController);
const validator = require('../middlewares/validator');
const { protect } = require('../middlewares/authMiddleware');

const router = express.Router();

router.post('/register', validator.validateRegistration, authController.register);
router.post('/login', authController.login);
router.post('/logout', authController.logout);
router.post('/send-verification-code', authController.sendVerificationCode);
router.post('/verify-code', authController.validateVerificationCode); 
router.post('/forgot-password', authController.forgotPassword);
router.post('/verify-reset-code', authController.verifyResetCode);
router.post('/reset-password', authController.resetPassword);
router.post('/individual/additional-info', protect, authController.updateIndividualInfo);
router.post('/business/additional-info', protect, authController.updateBusinessInfo);
router.get('/me', protect, authController.getMe);

module.exports = router;