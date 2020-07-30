const ErrorResponse = require('../utils/errorResponse');
const asyncHandler = require('../middleware/async');
// const Bootcamp = require('../models/Bootcamp');
const sendEmail = require('../utils/sendEmail');
const User = require('../models/User');

// @desc - Register User
// @route - POST /api/v1/auth/register
// @access - public
exports.register = asyncHandler(async (req, res, next) => {
  const { name, email, password, role } = req.body;

  // Create user
  const user = await User.create({
    name,
    email,
    password,
    role
  });

  sendTokenResponse(user, 200, res);
});

// @desc - Login User
// @route - POST /api/v1/auth/login
// @access - public
exports.login = asyncHandler(async (req, res, next) => {
  const { email, password } = req.body;

  // Validate email and password
  if (!email || !password) {
    return next(new ErrorResponse('Please provide and email and password', 400));
  }

  // Check for user
  const user = await User.findOne({ email }).select('+password');

  if (!user) {
    return next(new ErrorResponse('Invalid credentials', 401));
  }

  // Check if password matches 
  const isMatch = await user.matchPassword(password);

  if (!isMatch) {
    return next(new ErrorResponse('Invalid credentials', 401));
  }

  sendTokenResponse(user, 200, res);
});

// @desc - Get current logged in user
// @route - POST /api/v1/auth/me
// @access - private
exports.getMe = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user.id);

  res.status(200).json({
    success: true,
    data: user
  })
});

// @desc - Forgot password
// @route - POST /api/v1/auth/forgotpassword
// @access -Public
exports.forgotPassword = asyncHandler(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return next(new ErrorResponse('There is no user with that email', 404));
  }

  // Get reset token
  const resetToken = user.getResetPasswordToken();

  await user.save({ validateBeforeSave: false });

  // Create reset url
  const resetUrl = `${req.protocol}://${req.get('host')}/api/v1/resetpassword/${resetToken}`;

  const message = `You are receiving this email because you (or someone else) has requested the reset of a password. Please make a PUT request to /n/n ${resetUrl}`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'Password reset token',
      message
    });

    res.status(200).json({ success: true, data: 'Email sent' });
  } catch (err) {
    console.error(err);

    user.getResetPasswordToken = undefined;
    user.getResetPasswordExpire = undefined;

    await user.save({ validateBeforeSave: false });

    return next(new ErrorResponse('Email could not be sent', 500));
  }

  // console.log(resetToken);

  // This was causing error 'cannot send headers after they are sent to client

  // res.status(200).json({
  //   success: true,
  //   data: user
  // })
});

// Get token from model, also create cookie and send response
const sendTokenResponse = (user, statusCode, res) => {
  // Create token
  const token = user.getSignedJwtToken();

  const options = {
    // Calculate the 30 days in config file for the expiration

    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000
    ),
    httpOnly: true
  };

  if (process.env.NODE_ENV === 'production') {
    options.secure = true;
  }


  res
    .status(statusCode)
    .cookie('token', token, options)
    .json({
      success: true,
      token
    });
};