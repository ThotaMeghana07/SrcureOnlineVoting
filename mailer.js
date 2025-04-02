const nodemailer = require('nodemailer')

exports.sendVerMail = (req, res, next) => {

    let { email, otp } = req.body
    console.log(email, otp)
    let transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: process.env.MAIL_ID,
            pass: process.env.MAIL_PSWD
        }
    })
    let mailOptions = {
        from: process.env.MAIL_ID,
        to: email,
        subject: 'Verify Your Mail from SecureVote',
        html: `Use this as OTP : ${otp}`
    }
    transporter.sendMail(mailOptions)
        .then(info => console.log(info.response))
        .catch(err => next(err))

    res.send(`Check ${email} for OTP`)
}