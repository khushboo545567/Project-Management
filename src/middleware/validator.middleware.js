import { validationResult } from "express-validator";
import { ApiError } from "../utils/apiError.js";

export const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) {
    return next();
  }
  const extrectedError = [];
  errors.array().map((err) => extrectedError.push({ [err.path]: err.msg }));
  throw new ApiError(422, "Resivied data is not valid");
};
