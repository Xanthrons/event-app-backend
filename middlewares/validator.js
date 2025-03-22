const Joi = require('joi');

const personalEmailDomains = [
    'gmail.com',
    'yahoo.com',
    'hotmail.com',
    'aol.com',
    'msn.com',
    'outlook.com',
    'icloud.com',
    'mail.com',
    'gmx.com',
    'ymail.com',
    // Add more common personal email domains as needed
];

const passwordSchema = Joi.string()
    .min(8) // Increase minimum length to 8 (or more)
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$'))
    .required()
    .messages({
        'string.min': 'Password must be at least 8 characters long',
        'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)',
        'any.required': 'Password is required'
    });

exports.validateRegistration = (req, res, next) => {
    const { role } = req.body;
    let schema;

    if (role === 'individual') {
        schema = Joi.object({
            role: Joi.string().valid('individual').required(),
            first_name: Joi.string().required(),
            last_name: Joi.string().required(),
            gender: Joi.string().valid('male', 'female', 'other').optional().allow(null, ''),
            phone_number: Joi.object({
                country_code: Joi.string().optional().allow(null, ''),
                number: Joi.string().required()
            }).required(),
            email: Joi.string().email().required(),
            organization_name: Joi.string().optional().allow(null, ''),
            country: Joi.string().optional().allow(null, ''),
            city: Joi.string().optional().allow(null, ''),
            password: passwordSchema // Use the stronger password schema
        });
    } else if (role === 'business') {
        schema = Joi.object({
            role: Joi.string().valid('business').required(),
            business_name: Joi.string().required(),
            business_type: Joi.string().required(),
            phone_number: Joi.object({
                country_code: Joi.string().optional().allow(null, ''),
                number: Joi.string().required()
            }).required(),
            business_email: Joi.string().email().required().custom((value, helpers) => {
                const domain = value.split('@')[1];
                if (personalEmailDomains.includes(domain)) {
                    return helpers.message('Business email should not be a personal email address.');
                }
                return value;
            }),
            business_website: Joi.string().optional().allow(null, ''),
            country: Joi.string().optional().allow(null, ''),
            city: Joi.string().optional().allow(null, ''),
            password: passwordSchema // Use the stronger password schema
        });
    } else if (role === 'admin') {
        schema = Joi.object({
            role: Joi.string().valid('admin').required(),
            email: Joi.string().email().required(),
            password: passwordSchema // Use the stronger password schema
            // Add other admin specific fields if needed
        });
    } else {
        return res.status(400).json({ message: 'Invalid user role for registration.' });
    }

    const { error } = schema.validate(req.body);
    if (error) {
        return res.status(400).json({ message: error.details[0].message });
    }
    next();
};

// New validation functions for Forgot Password
exports.validateForgotPassword = (body) => {
    const schema = Joi.object({
        email: Joi.string().email().required().label('Email')
    });
    return schema.validate(body);
};

exports.validateVerifyResetCode = (body) => {
    const schema = Joi.object({
        email: Joi.string().email().required().label('Email'),
        code: Joi.string().length(6).pattern(/^[0-9]+$/).required().label('Verification Code')
    });
    return schema.validate(body);
};
exports.validateResetPassword = (body) => {
    const schema = Joi.object({
        tempToken: Joi.string().required().label('Temporary Token'),
        newPassword: passwordSchema // Use the same strong password schema
    });
    return schema.validate(body);
};