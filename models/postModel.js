const mongoose = require('mongoose');
const { Schema } = mongoose;

const postSchema = new Schema({
    title: {
        type: String,
        required: [true, 'Event title is required!'],
        trim: true
    },
    description: {
        type: String,
        trim: true
    },
    location: {
        type: String,
        required: [true, 'Event location is required!'],
        trim: true
    },
    date: {
        type: Date,
        required: [true, 'Event date is required!']
    },
    time: {
        type: String,
        trim: true
    },
    category: {
        type: String,
        trim: true
    },
    organizer: {
        type: Schema.Types.ObjectId,
        ref: 'User', // Reference to the User model
        required: [true, 'Organizer (Admin) is required!']
        // I will enforce in the controller that only users with 'admin' role can create events
    },
    attendees: [{
        type: Schema.Types.ObjectId,
        ref: 'User' // Reference to the User model (can be individual or business)
    }],
    created_at: {
        type: Date,
        default: Date.now
    },
    updated_at: {
        type: Date,
        default: Date.now
    }
}, { timestamps: true }); 

const Post = mongoose.model('Post', postSchema);

module.exports = Post;