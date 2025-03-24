const Event = require('../models/eventModel');
const cloudinary = require('cloudinary').v2;

exports.createEvent = async (req, res) => {
    try {
        const {
            eventName,
            eventCategory,
            eventType,
            location,
            map,
            startDate,
            endDate,
            eventOrganizer,
            purpose,
            targetAudience,
            agenda,
            speakers,
            regularSeats,
            regularSeatsPrice,
            vipSeats,
            vipSeatsPrice,
            premiumSeats,
            premiumSeatsPrice,
        } = req.body;

        // Calculate total number of seats
        const totalNumberOfSeats =
            parseInt(regularSeats || 0) +
            parseInt(vipSeats || 0) +
            parseInt(premiumSeats || 0);

        const eventPictures =[]; // Initialize eventPictures array
        if (req.files && Array.isArray(req.files.eventPictures)) {
            for (const file of req.files.eventPictures) {
                const result = await cloudinary.uploader.upload(file.path, {
                    folder: 'event-pictures',
                });
                eventPictures.push({
                    public_id: result.public_id,
                    url: result.secure_url,
                });
            }
        } else if (req.files && req.files.eventPictures) {
            const file = req.files.eventPictures;
            const result = await cloudinary.uploader.upload(file.path, {
                folder: 'event-pictures',
            });
            eventPictures.push({
                public_id: result.public_id,
                url: result.secure_url,
            });
        }

        const event = await Event.create({
            eventName,
            eventCategory,
            eventType,
            location,
            map,
            startDate,
            endDate,
            eventOrganizer,
            purpose,
            targetAudience,
            agenda,
            speakers: speakers ? JSON.parse(speakers):[], // Corrected syntax for speakers parsing
            regularSeats: parseInt(regularSeats || 0),
            regularSeatsPrice: parseFloat(regularSeatsPrice || 0),
            vipSeats: parseInt(vipSeats || 0),
            vipSeatsPrice: parseFloat(vipSeatsPrice || 0),
            premiumSeats: parseInt(premiumSeats || 0),
            premiumSeatsPrice: parseFloat(premiumSeatsPrice || 0),
            totalNumberOfSeats,
            eventPictures,
        });

        res.status(201).json({
            success: true,
            message: 'Event created successfully',
            event,
        });
    } catch (error) {
        console.error('Error creating event:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create event',
            error: error.message,
        });
    }
};