const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.NODE_CODE_SENDING_EMAIL,
        pass: process.env.NODE_CODE_SENDING_PASSWORD 
    }
});

const sendEmail = async (to, subject, html) => {
    try {
        const mailOptions = {
            from: process.env.NODE_CODE_SENDING_EMAIL, 
            to: to,
            subject: subject,
            html: html
        };

        await transporter.sendMail(mailOptions);
        console.log(`Email sent to ${to}`);
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
};

module.exports = { sendEmail };