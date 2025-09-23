import { Router } from "express";
import { helthCheck } from "../controllers/healthcheck.controller.js";

const router = Router();
router.route("/").get(helthCheck);
export default router;
