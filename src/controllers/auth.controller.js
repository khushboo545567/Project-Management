import asyncHandler from "../utils/asyncHandler.js";
import {
  emailVerificationContent,
  forgetPasswordMailgenContent,
  sendMail,
} from "../utils/mail.js";
import { User } from "../models/user.models.js";
import { ApiError } from "../utils/apiError.js";
import { ApiResponse } from "../utils/apiRsponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (err) {
    throw new ApiError(
      500,
      "something went wrong while generate the refresh token",
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  const { email, userName, fullName, password, role } = req.body;

  if ((!email || !userName, !password, !fullName)) {
    throw new ApiError(400, "all fields are required", []);
  }

  const existedUser = await User.findOne({ email });

  if (existedUser) {
    throw new ApiError(409, "User with this email is already existed", []);
  }

  // it returns the user
  const user = await User.create({
    email,
    password,
    userName,
    fullName,
    isEmailVerified: false,
  });

  // to verify the email generate the temp token
  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  // now prepare to send the email for user verifacation
  await sendMail({
    email: user?.email,
    subject: "please verify your email",
    mailgenContent: emailVerificationContent(
      user.userName,
      `${req.protocol}://${req.get("Host")}/api/v1/users/verify-email/${unHashedToken}`,
    ),
  });

  const createUser = await User.findById(user._id).select(
    "-emailVerificationExpiry -emailVerificationToken -password -refreshToken",
  );

  if (!createUser) {
    throw new ApiError(500, "something went wrong while registering a user");
  }

  return res
    .status(201)
    .json(
      new ApiResponse(
        200,
        { user: createUser },
        "user successfully registered and an email has been send to your email",
      ),
    );
});

const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new ApiError(400, "email or password is required");
  }

  const user = await User.findOne({ email });

  if (!user) {
    throw new ApiError(400, "User do not exist please register first");
  }

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(400, "invalid crediancitals");
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
    user._id,
  );

  const loggedInuser = await User.findById(user._id).select(
    "-emailVerificationExpiry -emailVerificationToken -password -refreshToken",
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        { user: loggedInuser, accessToken, refreshToken },
        "user logged in successfully",
      ),
    );
});

const logout = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: "",
      },
    },
    {
      new: true,
    },
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "user loggedout successfully"));
});

const currentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "user data successfully fetched"));
});

const verifyEmail = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;

  if (!verificationToken) {
    throw new ApiError(400, "email verification token is missing");
  }

  let hashedToken = crypto
    .createHash("sha256")
    .update(verificationToken)
    .digest("hex");

  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpiry: { $gt: Date.now() },
  });

  if (!user) {
    throw new ApiError(400, "Token is invalid or expired");
  }

  user.emailVerificationToken = undefined;
  user.emailVerificationExpiry = undefined;

  user.isEmailVerified = true;
  await user.save({ validateBeforeSave: false });

  return res.status(200).json(new ApiResponse(200, {}, "email is verified"));
});

const resendEmail = asyncHandler(async (req, res) => {
  // dout is here how do i acces the user if no middleware are there
  const user = await User.findById(req.user?._id);
  if (!user) {
    throw new ApiError(404, "user does not exist");
  }
  if (user.isEmailVerified) {
    throw new ApiError(409, "user is already verified");
  }
  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  // now prepare to send the email for user verifacation
  await sendMail({
    email: user?.email,
    subject: "please verify your email",
    mailgenContent: emailVerificationContent(
      user.userName,
      `${req.protocol}://${req.get("Host")}/api/v1/users/verify-email/${unHashedToken}`,
    ),
  });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "mail has been send to you email ID"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incommingToken = req.cookies.refreshToken || req.body.refreshToken;

  if (!incommingToken) {
    throw new ApiError(401, "unauthorized access");
  }

  try {
    const decodedToken = jwt.verify(
      incommingToken,
      process.env.REFRESH_TOKEN_SECRET,
    );
    const user = await User.findById(decodedToken._id);
    if (!user) {
      throw new ApiError(401, "invalid refresh token");
    }
    if (incommingToken !== user?.refreshToken) {
      throw new ApiError(401, "Token has been expired");
    }

    const options = {
      httpOnly: true,
      secure: true,
    };

    const { accessToken, refreshToken: newRefreshToken } =
      await generateAccessAndRefreshToken(user._id);

    user.refreshToken = newRefreshToken;
    await user.save();

    return res
      .status(200)
      .cookies("accessToken", accessToken, options)
      .cookies("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "accessToken is refreshed",
        ),
      );
  } catch (error) {
    throw new ApiError(401, "Invalid refresh token");
  }
});

const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    throw new ApiError(404, "user does not exist");
  }

  // generate token
  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.forgetPasswordToken = hashedToken;
  user.expireForgetPassowrdToken = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  // sned the email with token to rest password
  await sendMail({
    email: user?.email,
    subject: "Reset you password",
    mailgenContent: forgetPasswordMailgenContent(
      user.userName,
      `${req.protocol}://${req.get("Host")}/api/v1/users/rest-password/${unHashedToken}`,
    ),
  });

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        {},
        "pasword reset mail has been sent to your e-mail",
      ),
    );
});

const resetForgotPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { newPassword } = req.body;

  let hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  const user = await User.findOne({
    forgetPasswordToken: hashedToken,
    expireForgetPassowrdToken: { $gt: Date.now() },
  });

  if (!user) {
    throw new ApiError(489, "Token is invalid and expired");
  }

  user.forgetPasswordToken = undefined;
  user.expireForgetPassowrdToken = undefined;
  // now take the pass and update the db
  user.password = newPassword;
  user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "password reset successfully"));
});

const changePassword = asyncHandler(async (req, res) => {
  const { oldpassword, newPassword } = req.body;
  const user = await User.findById(req.user?._id);
  const isOldPasswordCorrect = user.isPasswordCorrect(oldpassword);
  if (!isOldPasswordCorrect) {
    throw new ApiError(400, "invalid old password");
  }

  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiError(200, {}, "password changed successfully"));
});

export {
  registerUser,
  loginUser,
  logout,
  currentUser,
  verifyEmail,
  resendEmail,
  refreshAccessToken,
  forgotPassword,
  resetForgotPassword,
  changePassword,
};
