import { body } from "express-validator";

const userRegisterValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),
    body("userName")
      .trim()
      .notEmpty()
      .withMessage("user name is required")
      .isLength({ min: 3 })
      .withMessage("user name must be atleast 3 characters"),
    body("password")
      .trim()
      .notEmpty()
      .withMessage("password is required")
      .isLength({ min: 8 })
      .withMessage("the password should be at least length 8"),
  ];
};

const userLoginValidator = () => {
  return [
    body("email").isEmail().withMessage("Email is required"),
    body("password").notEmpty().withMessage("password is required"),
  ];
};

const changePasswordValidator = () => {
  return [
    body("oldPassword").notEmpty().withMessage("old passoword is required"),
    body("newPassword").notEmpty().withMessage("new password is required"),
  ];
};

const forgotPasswordValidotor = () => {
  return [
    body("email")
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),
  ];
};

const resetForgetPasswordValidator = () => {
  return [body("newPassword").notEmpty().withMessage("password is required")];
};

export {
  userRegisterValidator,
  userLoginValidator,
  changePasswordValidator,
  forgotPasswordValidotor,
  resetForgetPasswordValidator,
};
