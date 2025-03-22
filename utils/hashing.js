const bcrypt = require('bcrypt');

exports.hashPassword = async (password) => {
    try {
        const salt = await bcrypt.genSalt(10);
        return await bcrypt.hash(password, salt);
    } catch (error) {
        console.error('Error hashing password:', error);
        throw error;
    }
};

exports.comparePassword = async (candidatePassword, hashedPassword) => {
    try {
        return await bcrypt.compare(candidatePassword, hashedPassword);
    } catch (error) {
        console.error('Error comparing passwords:', error);
        return false;
    }
};