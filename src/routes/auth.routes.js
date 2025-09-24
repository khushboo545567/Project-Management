import { Router } from "express";
import {
  changePassword,
  currentUser,
  forgotPassword,
  loginUser,
  logout,
  refreshAccessToken,
  registerUser,
  resendEmail,
  resetForgotPassword,
  verifyEmail,
} from "../controllers/auth.controller.js";
import { validate } from "../middleware/validator.middleware.js";
import {
  userRegisterValidator,
  userLoginValidator,
  resetForgetPasswordValidator,
  changePasswordValidator,
} from "../validators/index.js";
import { verifyJWT } from "../middleware/auth.middleware.js";

const router = Router();

// unsecured routes (do not need the authenticaiton)

router.route("/register").post(userRegisterValidator(), validate, registerUser);
router.route("/login").post(userLoginValidator(), validate, loginUser);
router.route("/verify-email/:verificationToken").get(verifyEmail);
router.route("/refresh-token").post(refreshAccessToken);
router
  .route("/forget-password")
  .post(resetForgetPasswordValidator(), validate, forgotPassword);
router
  .route("/reset-password/:resetToken")
  .post(resetForgetPasswordValidator(), validate, resetForgotPassword);

// require authentication secure routes

router.route("/logout").post(verifyJWT, logout);
router.route("/current-user").post(verifyJWT, currentUser);
router
  .route("/change-password")
  .post(verifyJWT, changePasswordValidator(), validate, changePassword);

router.route("/resend-email-verification").post(verifyJWT, resendEmail);

export default router;
