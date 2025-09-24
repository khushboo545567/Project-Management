import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser());
// cors configuration

app.use(
  cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

// IMPORTS ROUTES
import helthCheckRouter from "./routes/helthcheck.route.js";
import authRouter from "./routes/auth.routes.js";
import { contextsKey } from "express-validator/src/base.js";
app.use("/api/v1/helthcheck", helthCheckRouter);
app.use("/api/v1/auth", authRouter);

export default app;
