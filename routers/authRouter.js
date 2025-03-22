const express = require('express');
const authController = require('../controllers/authController');
const validator = require('../middlewares/validator');

const router = express.Router();

router.post('/register', validator.validateRegistration, authController.register);
router.post('/login', authController.login);
router.post('/logout', authController.logout);
router.post('/send-verification-code', authController.sendVerificationCode);
router.post('/verify-code', authController.validateVerificationCode); 

module.exports = router;