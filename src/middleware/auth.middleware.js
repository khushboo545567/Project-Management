import { User } from "../models/user.models";
import { ApiError } from "../utils/apiError";
import asyncHandler from "../utils/asyncHandler";

const verifyJWT = asyncHandler(async (req, res, next) => {
  const token =
    req.cookies?.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    throw new ApiError(400, "unauthorized token ");
  }

  try {
  } catch (error) {}
});

export { verifyJWT };
