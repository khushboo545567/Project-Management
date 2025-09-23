import { Router } from "express";
import { registerUser } from "../controllers/auth.controller.js";

const test = function () {
  console.log("testing form auth route");
  return;
};

const router = Router();
router.route("/register").post(registerUser);
export default router;
