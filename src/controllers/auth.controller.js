import asyncHandler from "../utils/asyncHandler.js";
import { emailVerificationContent, sendMail } from "../utils/mail.js";
import { User } from "../models/user.models.js";
import { ApiError } from "../utils/apiError.js";
import { ApiResponse } from "../utils/apiRsponse.js";

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
console.log("hii from the auth controller");
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

  console.log(user);
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

export { registerUser };
