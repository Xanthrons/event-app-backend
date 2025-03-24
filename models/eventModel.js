const mongoose = require('mongoose');

const eventSchema = new mongoose.Schema({
    eventName: {
        type: String,
        required: [true, 'Please enter the event name'],
        trim: true,
        maxLength: [100, 'Event name cannot exceed 100 characters'],
    },
    eventCategory: {
        type: String,
        enum: ['Conference', 'Meeting', 'Exhibition', 'Education', 'Seminar', 'Webinar'],
        required: [true, 'Please select the event category'],
    },
    eventType: {
        type: String,
        enum: ['In person', 'Web', 'Hybrid'],
        required: [true, 'Please select the event type'],
    },
    location: {
        type: String,
        required: [true, 'Please enter the event location'],
        trim: true,
    },
    map: {
        type: String, // You might want to store coordinates or an embed URL
        trim: true,
        default: null,
    },
    startDate: {
        type: Date,
        required: [true, 'Please enter the event start date'],
    },
    endDate: {
        type: Date,
        required: [true, 'Please enter the event end date'],
    },
    eventOrganizer: {
        type: String,
        required: [true, 'Please enter the event organizer'],
        trim: true,
    },
    purpose: {
        type: String,
        trim: true,
        default: null,
    },
    targetAudience: {
        type: String,
        trim: true,
        default: null,
    },
    agenda: {
        type: String,
        trim: true,
        default: null,
    },
    speakers: [{
        name: {
            type: String,
            trim: true,
        },
        link: {
            type: String,
            trim: true,
        },
    }],
    regularSeats: {
        type: Number,
        default: 0,
        min: 0,
    },
    regularSeatsPrice: {
        type: Number,
        default: 0,
        min: 0,
    },
    vipSeats: {
        type: Number,
        default: 0,
        min: 0,
    },
    vipSeatsPrice: {
        type: Number,
        default: 0,
        min: 0,
    },
    premiumSeats: {
        type: Number,
        default: 0,
        min: 0,
    },
    premiumSeatsPrice: {
        type: Number,
        default: 0,
        min: 0,
    },
    totalNumberOfSeats: {
        type: Number,
        default: 0,
        min: 0,
    },
    eventPictures: [{
        public_id: {
            type: String,
            required: true,
        },
        url: {
            type: String,
            required: true,
        },
    }],
    createdAt: {
        type: Date,
        default: Date.now,
    },
});

module.exports = mongoose.model('Event', eventSchema);