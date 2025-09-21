import app from "./app.js";
import dotenv from "dotenv";
import connectDB from "./db/index.js";
dotenv.config({
  path: "./.env",
});

const port = process.env.PORT || 300;
connectDB()
  .then(() => {
    app.listen(port, () => {
      console.log("the server is listening on the port ");
    });
  })
  .catch((error) => {
    ("mongo errorr", error);
  });
