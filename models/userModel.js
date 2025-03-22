const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    role: {
        type: String,
        enum: ['individual', 'business', 'admin'],
        required: true
    },
    password: {
        type: String,
        required: [true, 'Password is required!'],
        minlength: 6,
        select:false
    },
    verified: { 
        type: Boolean,
        default: false
    },
    verificationCode:{
        type:String,
        select:false
    },
    verificationCodeValidation: { // Stores the expiration timestamp for the code
        type: Date,
        select: false
    },
    forgotPasswordCode:{
        type: Number,
        select:false
    },
    forgotPasswordCodeValidation:{
        type: Number,
        select:false
    },
    country: {
        type: String,
        trim: true
    },
    city: {
        type: String,
        trim: true
    },
    phone_number: {
        country_code: {
            type: String,
            trim: true
        },
        number: {
            type: String,
            trim: true
        }
    },
    created_at: {
        type: Date,
        default: Date.now
    },
    updated_at: {
        type: Date,
        default: Date.now
    }
}, { discriminatorKey: 'role' }); // The discriminator key will be 'role'

const User = mongoose.model('User', userSchema);

// Individual User Model
const Individual = User.discriminator('individual', new mongoose.Schema({
    first_name: {
        type: String,
        required: [true, 'First name is required!'],
        trim: true
    },
    last_name: {
        type: String,
        required: [true, 'Last name is required!'],
        trim: true
    },
    gender: {
        type: String,
        enum: ['male', 'female', 'other'],
        trim: true
    },
    email: { // Defined in the Individual schema
        type: String,
        required: [true, 'Email is required!'],
        unique: [true,'Email already exists!'],
        trim: true,
        lowercase: true,
        match: [/.+\@.+\..+/, 'Please enter a valid email address']
    },
    organization_name: {
        type: String,
        trim: true,
        required:[true, 'Organization name is required!']
    }
}));

// Business User Model
const Business = User.discriminator('business', new mongoose.Schema({
    business_name: {
        type: String,
        required: [true, 'Business name is required!'],
        trim: true
    },
    business_type: {
        type: String,
        trim: true,
        required:[true, 'Business type is required!']
    },
    business_website: {
        type: String,
        trim: true
    },
    business_email: { // Defined in the Business schema
        type: String,
        required: [true, 'Business email is required!'],
        unique: [true, 'Business email already exists!'],
        trim: true,
        lowercase: true,
        match: [/.+\@.+\..+/, 'Please enter a valid business email address']
    }
}));

// Admin User Model
const Admin = User.discriminator('admin', new mongoose.Schema({
    email: { // Defined in the Admin schema
        type: String,
        required: [true, 'Email is required!'],
        unique: [true,'Email already exists!'],
        trim: true,
        lowercase: true,
        match: [/.+\@.+\..+/, 'Please enter a valid email address']
    }
    // Admins might have specific permissions or IDs I could add here later
}));

module.exports = { User, Individual, Business, Admin };