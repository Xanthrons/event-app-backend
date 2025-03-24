const express = require('express');
const router = express.Router();
const eventController = require('../controllers/eventController');
const { protect } = require('../middlewares/authMiddleware');
const isAdmin = require('../middlewares/isAdminMiddleware');
const upload = require('../middlewares/uploadMiddleware'); 

router.post(
    '/create-event',
    protect,
    isAdmin,
    upload.fields([{ name: 'eventPictures', maxCount: 10 }]), // Example: Allow up to 10 event pictures
    eventController.createEvent
);

module.exports = router;